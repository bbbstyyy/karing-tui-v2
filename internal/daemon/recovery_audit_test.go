package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
)

func recoveryAuditHTTP(t *testing.T, handler http.Handler) apiv1.RecoveryAuditResponse {
	t.Helper()
	resp := routeEditCall(t, handler, http.MethodGet, "/v1/config/recovery/audit", nil)
	if resp.Code != http.StatusOK {
		t.Fatalf("recovery audit HTTP status=%d body=%s", resp.Code, resp.Body.String())
	}
	var audit apiv1.RecoveryAuditResponse
	if err := json.NewDecoder(resp.Body).Decode(&audit); err != nil {
		t.Fatal(err)
	}
	return audit
}

func TestRecoveryAuditReadOnlyCommittedHistoryAndManifestIntegrity(t *testing.T) {
	store, core, _, handler := checkedApplyHarness(t)
	defer store.Close()
	ctx := context.Background()

	empty := recoveryAuditHTTP(t, handler)
	if empty.RestoreSupported || len(empty.Generations) != 0 || len(core.events) != 0 ||
		empty.ConfigRevision != 0 || empty.Evidence != "committed_generation_history_and_retained_storage" {
		t.Fatalf("read-only audit advertised nonexistent rollback: %+v", empty)
	}
	preview := checkedPreviewTest(t, handler)
	committed := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", preview.Receipt)
	if committed.Code != http.StatusOK {
		t.Fatalf("fixture apply failed: %d", committed.Code)
	}
	beforeEvents := len(core.events)
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	report := recoveryAuditHTTP(t, handler)
	if report.APIVersion != apiv1.Version || report.ConfigRevision != 1 ||
		report.RestoreSupported || report.ActiveApply || report.RecoveryRequired ||
		report.AppliedGenerationID == nil || len(report.Generations) != 1 {
		t.Fatalf("invalid committed generation report: %+v", report)
	}
	gen := report.Generations[0]
	if gen.GenerationID != *report.AppliedGenerationID || !gen.Applied ||
		!gen.LastKnownGood || !gen.PayloadRetained || !gen.StoredIntegrityVerified ||
		!gen.RuleSetResourcesVerified || gen.Status != "stored_integrity_verified_only" ||
		gen.DeclarationRevision != preview.Receipt.DeclarationRevision ||
		gen.CommittedConfigRevision != 1 || gen.RestoreReady {
		t.Fatalf("a retained generation was misclassified: %+v", gen)
	}
	if _, err := store.PruneRetention(ctx); err != nil {
		t.Fatal(err)
	}
	archived := recoveryAuditHTTP(t, handler)
	if len(archived.Generations) != 1 ||
		archived.Generations[0].Status != "stored_integrity_verified_only" {
		t.Fatalf("archived successful generation missing: %+v", archived)
	}
	after, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if before.Revision != after.Revision ||
		!sameGenerationID(before.AppliedGenerationID, after.AppliedGenerationID) ||
		len(core.events) != beforeEvents {
		t.Fatal("read-only audit changed durable state or contacted the core")
	}
	if post := routeEditCall(t, handler, http.MethodPost, "/v1/config/recovery/audit", nil); post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unexpected recovery write endpoint: %d", post.Code)
	}
}

func TestRecoveryAuditFailClosedOnTamperedStoredManifest(t *testing.T) {
	store, _, _, handler := checkedApplyHarness(t)
	defer store.Close()
	preview := checkedPreviewTest(t, handler)
	if result := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", preview.Receipt); result.Code != http.StatusOK {
		t.Fatalf("seed apply failed: %d", result.Code)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil || snapshot.AppliedGenerationID == nil {
		t.Fatalf("no seed generation: %v", err)
	}
	// sqlite state is owned by the test; this mutation emulates silent on-disk
	// corruption without modifying native core code or revealing raw config.
	if err := corruptStoredGenerationManifestHash(store.Path(), *snapshot.AppliedGenerationID); err != nil {
		t.Fatal(err)
	}
	report := recoveryAuditHTTP(t, handler)
	if len(report.Generations) != 1 || report.Generations[0].StoredIntegrityVerified ||
		report.Generations[0].RuleSetResourcesVerified || report.Generations[0].RestoreReady ||
		report.Generations[0].Status != "payload_hash_or_json_invalid" {
		t.Fatalf("tampered generation was marked verified: %+v", report.Generations)
	}
}

func TestRecoveryAuditRuleSetClosureVerifiesPrivateContentAddressedPath(t *testing.T) {
	root := t.TempDir()
	repo, err := coreartifact.NewStore(filepath.Join(root, "core"))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"version":2,"rules":[]}`)
	sum := sha256.Sum256(payload)
	sha := hex.EncodeToString(sum[:])
	path, _, err := repo.PutRuleSet(context.Background(), bytes.NewReader(payload), sha, "source")
	if err != nil {
		t.Fatal(err)
	}
	rule := compiler.NativeRuleSetManifest{
		Ref: "test-rules", RuntimeTag: "rs-test", RuntimePath: path,
		SHA256: sha, Format: compiler.RuleSetFormatSource,
	}
	if !auditRuleSetResources(context.Background(), root, []compiler.NativeRuleSetManifest{rule}) {
		t.Fatal("valid private content-addressed resource was rejected")
	}
	other := rule
	other.RuntimePath = filepath.Join(t.TempDir(), sha+".json")
	if auditRuleSetResources(context.Background(), root, []compiler.NativeRuleSetManifest{other}) {
		t.Fatal("external arbitrary path was accepted as a retained resource")
	}
	if auditRuleSetResources(context.Background(), "", []compiler.NativeRuleSetManifest{rule}) {
		t.Fatal("missing resource root was treated as verified")
	}
	if err := os.WriteFile(path, []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if auditRuleSetResources(context.Background(), root, []compiler.NativeRuleSetManifest{rule}) {
		t.Fatal("tampered rule set hash was accepted")
	}
}

func TestRecoveryAuditNeverDisclosesStoredMetadataSecrets(t *testing.T) {
	store, _, _, handler := checkedApplyHarness(t)
	defer store.Close()
	preview := checkedPreviewTest(t, handler)
	if result := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", preview.Receipt); result.Code != http.StatusOK {
		t.Fatal("fixture")
	}
	resp := routeEditCall(t, handler, http.MethodGet, "/v1/config/recovery/audit", nil)
	for _, raw := range []string{"control_secret", "experimental", "outbounds", "inbounds",
		"runtime_path", "password", "rule_sets", "source_map_json"} {
		if strings.Contains(resp.Body.String(), raw) {
			t.Fatalf("recovery audit leaked source or native JSON field %q", raw)
		}
	}
}

func TestRecoveryAuditUnavailableStoreDoesNotOfferFallback(t *testing.T) {
	_, err := recoveryAudit(context.Background(), nil, "")
	if err == nil {
		t.Fatal("nil storage accepted")
	}
}

func corruptStoredGenerationManifestHash(path string, generation int64) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec("UPDATE generations SET manifest_sha256 = ? WHERE id = ?",
		strings.Repeat("f", 64), generation)
	return err
}
