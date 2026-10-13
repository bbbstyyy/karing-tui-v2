//go:build linux && integration

package backupclosure

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Managed-core CI supplies the locked real artifact, not a synthetic digest.
// This checks v2 encryption, offline authentication and exact core inclusion.
func TestApprovedCoreSealedArchiveWithRealBinary(t *testing.T) {
	corePath := os.Getenv("KARING_TUI_TEST_CORE")
	if corePath == "" {
		t.Skip("no approved Linux core artifact")
	}
	f := newFixture(t)
	f.commit(t, true)
	closure, err := BuildWithApprovedCore(context.Background(), f.store,
		f.stateRoot, f.parent, corePath)
	if err != nil {
		t.Fatal(err)
	}
	directory := testSealedDir(t, f)
	path := filepath.Join(directory, "approved-core.ktbackup")
	key := testSealedKey(t)
	receipt, err := closure.SealInertArchive(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Format != CoreManifestVersion ||
		receipt.InventorySHA256 != closure.InventorySHA256 {
		t.Fatalf("v2 core inventory was not sealed: %+v", receipt)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoBackupScopes(t, f)
	checked, err := VerifyInertArchive(context.Background(), path, key)
	if err != nil || checked != receipt {
		t.Fatalf("real approved core seal verification failed: %+v %v", checked, err)
	}
	preflight, err := PreflightInertArchive(context.Background(), path, key, nil)
	if err != nil || !preflight.TargetMetadataCompatible ||
		!preflight.CoreIncluded || !preflight.ResourceDigestsVerified ||
		!preflight.SQLiteLogicalVerified || !preflight.SchemaCatalogVerified ||
		preflight.DeclarationCount != 1 ||
		preflight.Format != CoreManifestVersion ||
		preflight.InventorySHA256 != receipt.InventorySHA256 ||
		preflight.RestoreReady || preflight.RestoreSupported ||
		len(preflight.Blockers) != 2 {
		t.Fatalf("real approved-core metadata preflight failed: %+v %v", preflight, err)
	}
	// Even the fully approved, real v2 core remains a nonactivating,
	// ciphertext-only candidate across Close and cross-process re-adoption.
	candidateParent := newInertCandidateParent(t, f.stateRoot)
	candidate, err := StageInertRestoreCandidate(context.Background(), path, candidateParent, key)
	if err != nil {
		t.Fatalf("real core candidate staging failed: %v", err)
	}
	candidateDir := candidate.Directory()
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := ReopenInertRestoreCandidate(context.Background(), candidateDir, key)
	if err != nil {
		t.Fatalf("real core candidate re-adoption failed: %v", err)
	}
	rechecked, err := reopened.Verify(context.Background(), key)
	if err != nil || !rechecked.TargetMetadataCompatible ||
		!rechecked.CoreIncluded || rechecked.RestoreSupported || rechecked.RestoreReady ||
		rechecked.ArchiveSHA256 != receipt.ArchiveSHA256 {
		t.Fatalf("real core ciphertext isolation changed restore boundary: %+v %v", rechecked, err)
	}
	// The real locked binary may be metadata-compatible but cannot turn
	// an optimistic read-only fence into an import or activation permit.
	dryRun, err := InspectInertRestoreDryRun(context.Background(), f.store, reopened, key)
	if err != nil || !dryRun.TargetMetadataCompatible ||
		!dryRun.ArchiveAuthenticated || !dryRun.SQLiteSchemaVerified ||
		dryRun.RestoreReady || dryRun.RestoreSupported ||
		dryRun.ArchiveSHA256 != receipt.ArchiveSHA256 {
		t.Fatalf("real core restore fence dry-run invalid: %+v %v", dryRun, err)
	}
	if err := RecheckInertRestoreDryRun(context.Background(), f.store,
		reopened, key, dryRun); err != nil {
		t.Fatalf("real core restore fence drifted: %v", err)
	}
	// Stage M4 ADR 0106 probes an atomic SQL write-intent CAS with rollback;
	// it never writes an apply record or activates the approved binary.
	if err := CheckInertRestoreWriteBoundary(context.Background(), f.store,
		reopened, key, dryRun); err != nil {
		t.Fatalf("real approved core inert write CAS refused: %v", err)
	}
	if err := reopened.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
}
