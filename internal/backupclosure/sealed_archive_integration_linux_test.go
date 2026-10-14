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
	// ADR 0107 persists only an encrypted-candidate identity and the
	// verified live CAS baseline; it cannot activate the approved core.
	journal, err := PrepareInertRestoreCandidateRecord(
		context.Background(), f.store, reopened, key, dryRun)
	if err != nil || journal.RestoreReady || journal.RestoreSupported ||
		!journal.RequiresRevalidation || journal.ArchiveSHA256 != receipt.ArchiveSHA256 {
		t.Fatalf("real core inert journal was not safe: %+v %v", journal, err)
	}
	if err := RevalidateInertRestoreCandidateRecord(
		context.Background(), f.store, reopened, key, journal.ID); err != nil {
		t.Fatalf("real core sealed preparation was not revalidated: %v", err)
	}
	// ADR 0108 requires a FRESH candidate directory flock and exact
	// journal/live CAS after the prior process lease is released. Even the
	// real sing-box v2 executable cannot be activated through this check.
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
	resourceLease, err := AcquireInertRestoreResourceLease(
		context.Background(), f.store, candidateParent, journal.ID, key)
	if err != nil {
		t.Fatalf("approved-core journal-bound resource lease failed: %v", err)
	}
	if err := resourceLease.Revalidate(context.Background(), key); err != nil {
		t.Fatalf("approved-core encrypted resource lease drifted: %v", err)
	}
	// ADR 0110 streams the real, repository-locked executable and rules only
	// through private UNLINKED Linux inodes; no executable or plaintext path
	// survives this call, and the existing journal/lease remains inert.
	scratch := filepath.Join(f.stateRoot, "anonymous-resource-probe")
	if err := os.Mkdir(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	probe, err := resourceLease.ProbeAnonymousResources(
		context.Background(), scratch, key)
	if err != nil || !probe.AnonymousFilesChecked || !probe.CoreIncluded ||
		probe.CoreBytes != closure.Inventory.Core.Size ||
		probe.RuleSetCount != len(closure.Inventory.RuleSets) ||
		probe.RestoreReady || probe.RestoreSupported {
		t.Fatalf("real approved-core anonymous probe failed: %+v %v", probe, err)
	}
	if entries, err := os.ReadDir(scratch); err != nil || len(entries) != 0 {
		t.Fatalf("probe left named plaintext resources: %+v %v", entries, err)
	}
	if resourceLease.Record().RestoreReady || resourceLease.Record().RestoreSupported {
		t.Fatal("approved binary gained restore permissions")
	}
	// ADR 0111: authenticated SQLite is inspected in memory only. The
	// source-native rule paths are rebound hypothetically to another Linux
	// state root. Neither rewritten config nor plaintext core is published.
	portable, err := resourceLease.PreviewPortableRulePaths(context.Background(),
		filepath.Join(f.stateRoot, "portable-dry-run"), key)
	if err != nil || portable.RestoreReady || portable.RestoreSupported ||
		portable.GenerationCount != len(closure.Inventory.Generations) ||
		portable.RuleSetCount != len(closure.Inventory.RuleSets) ||
		portable.RelocatedGenerationCount == 0 ||
		!validLowerSHA(portable.RelocatedConfigDigest) {
		t.Fatalf("real core portable path preview failed: %+v %v", portable, err)
	}
	if _, err := os.Lstat(filepath.Join(f.stateRoot, "portable-dry-run")); !os.IsNotExist(err) {
		t.Fatalf("real approved core preview wrote target files: %v", err)
	}
	// ADR 0112: inspect a separate existing 0700 target rule tree using
	// pinned O_NOFOLLOW directory FDs; every absent resource is counted,
	// never installed. Even an archive including the real approved binary
	// remains non-activating and does not create a target Core executable.
	targetRoot := filepath.Join(f.stateRoot, "portable-inspection-target")
	for _, directory := range []string{
		targetRoot, filepath.Join(targetRoot, "core"),
		filepath.Join(targetRoot, "core", "rule-sets"),
		filepath.Join(targetRoot, "core", "rule-sets", "sha256"),
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	targetReport, err := resourceLease.InspectPortableTargetRuleTree(
		context.Background(), targetRoot, key)
	if err != nil || !targetReport.DirectoriesPinned ||
		targetReport.RuleSetCount != len(closure.Inventory.RuleSets) ||
		targetReport.MissingRuleSets != len(closure.Inventory.RuleSets) ||
		targetReport.ExistingRuleSets != 0 ||
		targetReport.RestoreReady || targetReport.RestoreSupported {
		t.Fatalf("real core target-path inspection changed authority: %+v %v", targetReport, err)
	}
	if entries, err := os.ReadDir(filepath.Join(targetRoot, "core", "rule-sets", "sha256"));
		err != nil || len(entries) != 0 {
		t.Fatalf("real core target path inspection created resources: %+v %v", entries, err)
	}
	if err := resourceLease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AbandonInertRestoreRecord(
		context.Background(), journal.ID, journal.CandidateScope,
		journal.ArchiveSHA256); err != nil {
		t.Fatal(err)
	}
	cleanup, err := ReopenInertRestoreCandidate(context.Background(), candidateDir, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
}
