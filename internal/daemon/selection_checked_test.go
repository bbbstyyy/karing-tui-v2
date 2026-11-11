package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func appliedSelectionFixture(t *testing.T) (*storage.Store, []byte, *fakeSelectionDaemonCore, http.Handler) {
	t.Helper()
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	document := currentSelectionTestDeclaration()
	decl, err := store.CommitDeclaration(ctx, 0, document, "test:checked-selection")
	if err != nil {
		t.Fatal(err)
	}
	// A verified generation must bind the actual native config bytes.
	configSum := sha256.Sum256([]byte("{}"))
	manifest, err := json.Marshal(compiler.NativeManifest{
		SchemaID:            compiler.NativeSchemaID,
		ConfigSHA256:        hex.EncodeToString(configSum[:]),
		DeclarationRevision: decl.Revision,
		DeclarationSHA256:   decl.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := store.PrepareApplyWithMetadata(ctx, 0, []byte("{}"), manifest, []byte("[]"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginVerification(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitApplied(ctx, attempt.ID, true); err != nil {
		t.Fatal(err)
	}
	a := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	tag, err := declaration.CurrentSelectionRuntimeTag(document, a)
	if err != nil {
		t.Fatal(err)
	}
	coreFake := &fakeSelectionDaemonCore{fakeCurrentSelectionCore: fakeCurrentSelectionCore{
		snapshot: core.Snapshot{State: core.StateRunning, PID: 4321},
		selected: tag,
	}}
	runtime := &serverRuntime{core: coreFake, gate: NewOperationGate()}
	return store, document, coreFake, New(runtimepath.Paths{}).handler(store, runtime)
}

func checkedRequest(state apiv1.CurrentSelectionResponse, target domain.TargetRef) apiv1.CurrentSelectionCheckedRequest {
	return apiv1.CurrentSelectionCheckedRequest{
		Target: target, ExpectedSelectionRevision: state.SelectionRevision,
		ExpectedConfigRevision: state.ConfigRevision, ExpectedGenerationID: state.AppliedGenerationID,
		ExpectedDeclarationRevision: state.DeclarationRevision,
		ExpectedDeclarationSHA256:   state.DeclarationSHA256,
	}
}

func selectionAPICall(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var jsonBody strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		jsonBody = *strings.NewReader(string(raw))
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, path, &jsonBody))
	return recorder
}

func decodeSelectionAPI(t *testing.T, response *httptest.ResponseRecorder) apiv1.CurrentSelectionResponse {
	t.Helper()
	var value apiv1.CurrentSelectionResponse
	if err := json.NewDecoder(response.Body).Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestCheckedSelectionAPIBindsAppliedGenerationAndRejectsStaleAndInvalid(t *testing.T) {
	store, document, fake, handler := appliedSelectionFixture(t)
	defer store.Close()

	get := selectionAPICall(t, handler, http.MethodGet, "/v1/selection/current", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("GET = %d, %s", get.Code, get.Body.String())
	}
	initial := decodeSelectionAPI(t, get)
	if initial.SelectionRevision != 0 || initial.ConfigRevision != 1 ||
		initial.AppliedGenerationID == nil || initial.DeclarationRevision != 1 ||
		len(initial.DeclarationSHA256) != 64 || !initial.Applied {
		t.Fatalf("invalid checked GET contract: %+v", initial)
	}
	targetB := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-b"}
	request := checkedRequest(initial, targetB)

	wrongGeneration := request
	badID := *initial.AppliedGenerationID + 123
	wrongGeneration.ExpectedGenerationID = &badID
	rejected := selectionAPICall(t, handler, http.MethodPut, "/v1/selection/current/checked", wrongGeneration)
	if rejected.Code != http.StatusConflict || fake.selectCalls != 0 {
		t.Fatalf("stale applied generation accepted: %d, %s", rejected.Code, rejected.Body.String())
	}
	wrongHash := request
	wrongHash.ExpectedDeclarationSHA256 = strings.Repeat("f", 64)
	rejected = selectionAPICall(t, handler, http.MethodPut, "/v1/selection/current/checked", wrongHash)
	if rejected.Code != http.StatusConflict || fake.selectCalls != 0 {
		t.Fatalf("stale declaration SHA accepted: %d, %s", rejected.Code, rejected.Body.String())
	}
	invalid := request
	invalid.Target.NodeID = "missing"
	rejected = selectionAPICall(t, handler, http.MethodPut, "/v1/selection/current/checked", invalid)
	if rejected.Code != http.StatusUnprocessableEntity || fake.selectCalls != 0 {
		t.Fatalf("invalid member accepted: %d, %s", rejected.Code, rejected.Body.String())
	}
	invalid.ExpectedDeclarationSHA256 = ""
	rejected = selectionAPICall(t, handler, http.MethodPut, "/v1/selection/current/checked", invalid)
	if rejected.Code != http.StatusUnprocessableEntity || fake.selectCalls != 0 {
		t.Fatalf("incomplete binding accepted: %d, %s", rejected.Code, rejected.Body.String())
	}

	// A newer committed but UNAPPLIED declaration must not change the
	// target membership of the currently serving applied generation.
	originalDecl, err := store.CurrentDeclaration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	newDoc := []byte(strings.ReplaceAll(string(document), "node-b", "node-c"))
	if _, err := store.CommitDeclaration(context.Background(), originalDecl.Revision, newDoc, "test:unapplied-next"); err != nil {
		t.Fatal(err)
	}
	accepted := selectionAPICall(t, handler, http.MethodPut, "/v1/selection/current/checked", request)
	if accepted.Code != http.StatusOK {
		t.Fatalf("checked PUT = %d, %s", accepted.Code, accepted.Body.String())
	}
	next := decodeSelectionAPI(t, accepted)
	if next.SelectionRevision != 1 || next.Target != targetB || !next.Persisted || !next.Applied ||
		next.DeclarationRevision != 1 || next.AppliedGenerationID == nil || fake.selectCalls != 1 {
		t.Fatalf("applied-generation selection failed: %+v, calls=%d", next, fake.selectCalls)
	}
	rejected = selectionAPICall(t, handler, http.MethodPut, "/v1/selection/current/checked", request)
	if rejected.Code != http.StatusConflict || fake.selectCalls != 1 {
		t.Fatalf("stale check overwrote selector: %d, calls=%d", rejected.Code, fake.selectCalls)
	}
	legacyTarget := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	legacy := selectionAPICall(t, handler, http.MethodPut, "/v1/selection/current",
		apiv1.CurrentSelectionRequest{Target: legacyTarget})
	if legacy.Code != http.StatusOK {
		t.Fatalf("legacy PUT failed: %d, %s", legacy.Code, legacy.Body.String())
	}
	legacyState := decodeSelectionAPI(t, legacy)
	if legacyState.SelectionRevision != 2 || fake.selectCalls != 2 {
		t.Fatalf("legacy endpoint did not increment checked revision: %+v", legacyState)
	}
	// A replay of the first guarded request still fails after legacy write.
	rejected = selectionAPICall(t, handler, http.MethodPut, "/v1/selection/current/checked", request)
	if rejected.Code != http.StatusConflict || fake.selectCalls != 2 {
		t.Fatalf("stale guard survived legacy write: %d", rejected.Code)
	}
}

func TestCheckedSelectionLiveFailurePersistsIntentAndNeedsReadback(t *testing.T) {
	store, _, fake, handler := appliedSelectionFixture(t)
	defer store.Close()
	get := selectionAPICall(t, handler, http.MethodGet, "/v1/selection/current", nil)
	initial := decodeSelectionAPI(t, get)
	targetB := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-b"}
	request := checkedRequest(initial, targetB)
	fake.selectErr = errors.New("token=DO_NOT_DISCLOSE")
	failed := selectionAPICall(t, handler, http.MethodPut, "/v1/selection/current/checked", request)
	if failed.Code != http.StatusBadGateway || strings.Contains(failed.Body.String(), "DO_NOT_DISCLOSE") {
		t.Fatalf("live failure leaked or wrong code: %d, %s", failed.Code, failed.Body.String())
	}
	after := selectionAPICall(t, handler, http.MethodGet, "/v1/selection/current", nil)
	if after.Code != http.StatusOK {
		t.Fatalf("readback = %d, %s", after.Code, after.Body.String())
	}
	state := decodeSelectionAPI(t, after)
	if state.SelectionRevision != 1 || !state.Persisted || state.Target != targetB ||
		state.Applied || state.LiveRuntimeTag == state.RuntimeTag {
		t.Fatalf("uncertain live update not persisted and distinguished: %+v", state)
	}
	stale := selectionAPICall(t, handler, http.MethodPut, "/v1/selection/current/checked", request)
	if stale.Code != http.StatusConflict || fake.selectCalls != 1 {
		t.Fatalf("failed live update should still consume CAS: %d calls=%d", stale.Code, fake.selectCalls)
	}
}

func TestCheckedSelectionStoppedCorePersistsWithoutLiveClaim(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()
	doc := currentSelectionTestDeclaration()
	if _, err := store.CommitDeclaration(ctx, 0, doc, "test:selection-stopped-guard"); err != nil {
		t.Fatal(err)
	}
	fake := &fakeCurrentSelectionCore{snapshot: core.Snapshot{State: core.StateStopped}}
	coordinator, err := NewCurrentSelectionCoordinator(store, fake)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := coordinator.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	target := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-b"}
	result, err := coordinator.SetChecked(ctx, target, CheckedSelectionExpectation{
		SelectionRevision: initial.SelectionRevision, ConfigRevision: initial.ConfigRevision,
		AppliedGenerationID: initial.AppliedGenerationID, DeclarationRevision: initial.DeclarationRevision,
		DeclarationSHA256: initial.DeclarationSHA256,
	})
	if err != nil || !result.Persisted || result.Applied || result.SelectionRevision != 1 || fake.selectCalls != 0 {
		t.Fatalf("stopped-core result = %+v err=%v calls=%d", result, err, fake.selectCalls)
	}
	// A running core without a confirmed generation cannot accept a guarded
	// selector from an un-applied declaration.
	fake.snapshot.State = core.StateRunning
	_, err = coordinator.SetChecked(ctx, target, CheckedSelectionExpectation{
		SelectionRevision: result.SelectionRevision, ConfigRevision: result.ConfigRevision,
		DeclarationRevision: result.DeclarationRevision, DeclarationSHA256: result.DeclarationSHA256,
	})
	if !errors.Is(err, ErrCurrentSelectionUnavailable) || fake.selectCalls != 0 {
		t.Fatalf("unproven running core accepted checked selection: %v", err)
	}
}
