package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestHistoricalPreflightRejectsStaleSelectorAndNeverAllowsRestore(t *testing.T) {
	store, core, _, handler := checkedApplyHarness(t)
	defer store.Close()
	preview := checkedPreviewTest(t, handler)
	if result := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", preview.Receipt); result.Code != http.StatusOK {
		t.Fatal("seed apply failed")
	}
	initial := recoveryAuditHTTP(t, handler)
	if len(initial.Generations) != 1 || initial.RestoreSupported ||
		initial.Generations[0].RestoreReady ||
		initial.Generations[0].PreflightStatus != recoveryPreflightConsistentOnly {
		t.Fatalf("initial preflight incorrect: %+v", initial)
	}
	initialCoreEvents := len(core.events)
	// Intent is an independently persisted state; even a legacy write that
	// points outside this generation must not be treated as the old default.
	if _, err := store.SetCurrentSelectionIntent(context.Background(),
		[]byte(`{"kind":"specific_node","profile_id":"p1","node_id":"missing"}`)); err != nil {
		t.Fatal(err)
	}
	stale := recoveryAuditHTTP(t, handler)
	if stale.Generations[0].PreflightStatus != recoveryPreflightSelectorMismatch ||
		stale.Generations[0].RestoreReady || stale.RestoreSupported ||
		len(core.events) != initialCoreEvents {
		t.Fatalf("stale selection was authorized: %+v", stale)
	}
}

func TestRecoveryAuditIntentAndRefsChangeDetection(t *testing.T) {
	a := storage.SelectionIntent{Revision: 3, TargetJSON: json.RawMessage(`{"kind":"specific_node"}`)}
	b := a
	if !sameRecoveryAuditIntent(a, true, b, true) {
		t.Fatal("same intent rejected")
	}
	b.Revision++
	if sameRecoveryAuditIntent(a, true, b, true) || sameRecoveryAuditIntent(a, true, a, false) {
		t.Fatal("intent CAS change ignored")
	}
	refs := []storage.ConfirmedGenerationRef{{GenerationID: 1, TargetConfigRevision: 2, PayloadRetained: true}}
	if !sameRecoveryAuditRefs(refs, false, refs, false) || sameRecoveryAuditRefs(refs, false, refs, true) {
		t.Fatal("retention truncation change ignored")
	}
	next := append([]storage.ConfirmedGenerationRef(nil), refs...)
	next[0].PayloadRetained = false
	if sameRecoveryAuditRefs(refs, false, next, false) {
		t.Fatal("payload pruning change ignored")
	}
	before := storage.Snapshot{Revision: 2, RoutingMode: storage.RoutingModeRule}
	after := before
	after.PrivateDirect = true
	if sameRecoveryAuditSnapshot(before, after) {
		t.Fatal("routing policy change ignored")
	}
}
