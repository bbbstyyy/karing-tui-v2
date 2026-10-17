//go:build linux && integration

package backupclosure

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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
	// ADR 0113: preserve the real repository-approved Core and rule data in
	// anonymous, NON-executable descriptors across independent same-process
	// checks, then drop every FD before progressing. Never publish a path.
	pins, err := resourceLease.PinAnonymousRestoreResources(
		context.Background(), scratch, key)
	if err != nil {
		t.Fatalf("real approved-core pinned resource stage failed: %v", err)
	}
	pinEvidence := pins.Evidence()
	if !pinEvidence.CoreIncluded || pinEvidence.CoreBytes != closure.Inventory.Core.Size ||
		pinEvidence.RuleSetCount != len(closure.Inventory.RuleSets) ||
		pinEvidence.DescriptorCount != pinEvidence.RuleSetCount+1 ||
		pinEvidence.RestoreReady || pinEvidence.RestoreSupported {
		t.Fatalf("approved-core descriptor bundle acquired restore authority: %+v", pinEvidence)
	}
	if err := pins.Revalidate(context.Background(), key); err != nil {
		t.Fatalf("approved-core anonymous pinned resource drifted: %v", err)
	}
	// ADR 0114 publishes RULES ONLY, under a private inactive directory.
	// The actual approved binary stays an unlinkable FD and is never copied
	// to this persisted scope or made executable.
	dormantParent := filepath.Join(f.stateRoot, "inert-rule-bundles")
	if err := os.Mkdir(dormantParent, 0o700); err != nil {
		t.Fatal(err)
	}
	dormant, err := pins.StageDormantRuleBundle(
		context.Background(), dormantParent, key)
	if err != nil || !dormant.Inactive || dormant.RestoreReady ||
		dormant.RestoreSupported ||
		dormant.RuleCount != len(closure.Inventory.RuleSets) {
		t.Fatalf("real approved-core dormant rule stage failed: %+v %v", dormant, err)
	}
	scopeEntries, err := os.ReadDir(dormantParent)
	if err != nil || len(scopeEntries) != 1 {
		t.Fatalf("inert rules publication not atomic: %+v %v", scopeEntries, err)
	}
	ruleEntries, err := os.ReadDir(filepath.Join(dormantParent, scopeEntries[0].Name()))
	if err != nil || len(ruleEntries) != len(closure.Inventory.RuleSets) {
		t.Fatalf("published historical core or unknown rules: %+v %v", ruleEntries, err)
	}
	if err := pins.Close(); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(scratch); err != nil || len(entries) != 0 {
		t.Fatalf("pinned approved Core left named plaintext: %+v %v", entries, err)
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
	if entries, err := os.ReadDir(filepath.Join(targetRoot, "core", "rule-sets", "sha256")); err != nil || len(entries) != 0 {
		t.Fatalf("real core target path inspection created resources: %+v %v", entries, err)
	}
	if err := resourceLease.Close(); err != nil {
		t.Fatal(err)
	}
	// ADR 0116: after the real approved-Core anonymous pins and original
	// ciphertext lease are CLOSED, reacquire a fresh authenticated candidate.
	// Independently rehash only the persisted inactive RULES, never install
	// or execute the historical Core and never grant restore permissions.
	freshLease, err := AcquireInertRestoreResourceLease(
		context.Background(), f.store, candidateParent, journal.ID, key)
	if err != nil {
		t.Fatalf("real core ciphertext lease could not be reopened: %v", err)
	}
	verifiedDormant, err := freshLease.AuthenticateDormantRuleBundle(context.Background(), key)
	if err != nil || !verifiedDormant.RuleBytesVerified ||
		!verifiedDormant.Inactive || !verifiedDormant.RequiresRevalidation ||
		verifiedDormant.RuleCount != len(closure.Inventory.RuleSets) ||
		verifiedDormant.RuleBytes != dormant.RuleBytes ||
		verifiedDormant.ArchiveSHA256 != receipt.ArchiveSHA256 ||
		verifiedDormant.RestoreSupported || verifiedDormant.RestoreReady {
		t.Fatalf("real approved-Core dormant rules reauthentication failed: %+v %v", verifiedDormant, err)
	}
	// ADR 0117: with the real approved Core still unexecuted, explicitly
	// quarantine only the authenticated inactive rule bundle. No plaintext
	// SQLite or approved Core executable is persisted, and no rule is removed.
	retired, err := freshLease.QuarantineDormantRuleBundle(
		context.Background(), key, verifiedDormant)
	if err != nil || !retired.Quarantined || !retired.RequiresManualReview ||
		retired.RestoreReady || retired.RestoreSupported ||
		retired.RuleCount != len(closure.Inventory.RuleSets) ||
		retired.RuleBytes != dormant.RuleBytes {
		t.Fatalf("approved-Core dormant quarantine changed recovery boundary: %+v %v", retired, err)
	}
	retiredEntries, err := os.ReadDir(dormantParent)
	if err != nil || len(retiredEntries) != 1 ||
		retiredEntries[0].Name() != dormantRuleRetiredPrefix+receipt.ArchiveSHA256 {
		t.Fatalf("real-core quarantine did not atomically rename only inactive rules: %+v %v", retiredEntries, err)
	}
	retiredFiles, err := os.ReadDir(filepath.Join(dormantParent, retiredEntries[0].Name()))
	if err != nil || len(retiredFiles) != len(closure.Inventory.RuleSets) {
		t.Fatalf("real-core retirement removed rules or retained executable: %+v %v", retiredFiles, err)
	}
	// ADR 0118: independently inspect the RETIRED scope and publish only
	// a durable, non-deleting reclamation intent. The real locked Core is
	// never written to this namespace or executed by this prerequisite.
	retiredCheck, err := freshLease.InspectRetiredDormantRuleBundle(context.Background(), key)
	if err != nil || !retiredCheck.ContentVerified ||
		!retiredCheck.RequiresRevalidation ||
		retiredCheck.RuleCount != len(closure.Inventory.RuleSets) ||
		retiredCheck.RuleBytes != dormant.RuleBytes ||
		retiredCheck.RestoreSupported || retiredCheck.RestoreReady {
		t.Fatalf("approved core retired-rule attestation failed: %+v %v", retiredCheck, err)
	}
	reclaimIntent, err := freshLease.BeginRetiredDormantRuleReclaim(
		context.Background(), key, retiredCheck)
	if err != nil || !reclaimIntent.IntentPublished ||
		reclaimIntent.BytesDeleted || !reclaimIntent.RequiresManualReview ||
		reclaimIntent.RuleCount != len(closure.Inventory.RuleSets) ||
		reclaimIntent.RuleBytes != dormant.RuleBytes ||
		reclaimIntent.RestoreSupported || reclaimIntent.RestoreReady {
		t.Fatalf("approved core reclaim intent unexpectedly removed resources: %+v %v", reclaimIntent, err)
	}
	toReclaim, err := os.ReadDir(dormantParent)
	if err != nil || len(toReclaim) != 1 ||
		toReclaim[0].Name() != dormantRuleReclaimPrefix+receipt.ArchiveSHA256 {
		t.Fatalf("real-core reclamation intent published unexpected scope: %+v %v", toReclaim, err)
	}
	stillPresent, err := os.ReadDir(filepath.Join(dormantParent, toReclaim[0].Name()))
	if err != nil || len(stillPresent) != len(closure.Inventory.RuleSets) {
		t.Fatalf("reclaim-intent lost rules or staged executable: %+v %v", stillPresent, err)
	}
	// ADR 0119: fsync a signed, complete one-scope deletion plan first.
	// Each private rule unlink requires a separate durable HMAC intent and
	// is never performed against the real live Core/rule-set tree.
	deletePlan, err := freshLease.PrepareDurableRuleReclaim(context.Background(), key)
	if err != nil || !validLowerSHA(deletePlan.PlanSHA256) ||
		deletePlan.ExpectedRules != len(closure.Inventory.RuleSets) ||
		deletePlan.UnlinkedRules != 0 || deletePlan.PreparedIntents != 0 ||
		deletePlan.RestoreReady || deletePlan.RestoreSupported {
		t.Fatalf("approved Core signed reclaim plan invalid: %+v %v", deletePlan, err)
	}
	deleteStep, err := freshLease.UnlinkNextDurableReclaimRule(
		context.Background(), key, deletePlan)
	if err != nil || !deleteStep.RuleUnlinked || deleteStep.RuleBytes <= 0 ||
		deleteStep.RestoreReady || deleteStep.RestoreSupported {
		t.Fatalf("approved Core private rule unlink refused: %+v %v", deleteStep, err)
	}
	deletedEvidence, err := freshLease.InspectDurableRuleReclaim(context.Background(), key)
	if err != nil || deletedEvidence.UnlinkedRules != 1 ||
		deletedEvidence.PreparedIntents != 1 ||
		deletedEvidence.PlanSHA256 != deletePlan.PlanSHA256 ||
		deletedEvidence.RestoreReady || deletedEvidence.RestoreSupported {
		t.Fatalf("approved Core durable deletion evidence refused: %+v %v", deletedEvidence, err)
	}
	if _, err := os.Stat(filepath.Join(dormantParent, toReclaim[0].Name(),
		reclaimPlanFileName)); err != nil {
		t.Fatalf("approved Core reclaim plan did not persist: %v", err)
	}
	// ADR 0120 is terminal EVIDENCE ONLY: explicitly complete any remaining
	// rule leaves in this test, then seal a signed completion marker without
	// deleting audit metadata, touching active files or running the Core.
	for i := 1; i < len(closure.Inventory.RuleSets); i++ {
		step, err := freshLease.UnlinkNextDurableReclaimRule(
			context.Background(), key, deletedEvidence)
		if err != nil || !step.RuleUnlinked {
			t.Fatalf("approved Core remaining private unlink failed: %+v %v", step, err)
		}
		deletedEvidence, err = freshLease.InspectDurableRuleReclaim(context.Background(), key)
		if err != nil || deletedEvidence.UnlinkedRules != i+1 {
			t.Fatalf("approved Core remaining evidence invalid: %+v %v", deletedEvidence, err)
		}
	}
	if !deletedEvidence.AllRulesUnlinked {
		t.Fatalf("terminal proof attempted before all private rules were absent: %+v", deletedEvidence)
	}
	sealed, err := freshLease.SealCompletedDurableReclaim(
		context.Background(), key, deletedEvidence)
	if err != nil || !sealed.CompletionSealed || !sealed.MetadataRetained ||
		sealed.RuleCount != len(closure.Inventory.RuleSets) ||
		sealed.PlanSHA256 != deletePlan.PlanSHA256 ||
		sealed.RestoreReady || sealed.RestoreSupported {
		t.Fatalf("approved Core terminal reclaim seal failed: %+v %v", sealed, err)
	}
	sealAgain, err := freshLease.InspectSealedDurableReclaim(context.Background(), key)
	if err != nil || sealAgain != sealed {
		t.Fatalf("approved Core terminal evidence not independently auditable: %+v %v", sealAgain, err)
	}
	sealedFiles, err := os.ReadDir(filepath.Join(dormantParent, toReclaim[0].Name()))
	if err != nil || len(sealedFiles) != len(closure.Inventory.RuleSets)+2 {
		t.Fatalf("terminal scope changed more than audit metadata: %+v %v", sealedFiles, err)
	}
	// ADR 0121: the signed completion can receive one independently
	// retained audit anchor outside the reclaim scope. Real approved-Core
	// bytes, active rule files and SQLite live state must remain untouched.
	beforeAnchor, err := f.store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := freshLease.AttestSealedDurableReclaim(context.Background(), key, sealed)
	if err != nil || !anchor.AttestationRetained || !anchor.OriginalEvidenceRetained ||
		anchor.ArchiveSHA256 != receipt.ArchiveSHA256 ||
		anchor.CompletionSHA256 != sealed.CompletionSHA256 ||
		anchor.RuleCount != len(closure.Inventory.RuleSets) ||
		anchor.RestoreReady || anchor.RestoreSupported {
		t.Fatalf("approved Core independent audit anchor refused: %+v %v", anchor, err)
	}
	verifiedAnchor, err := freshLease.InspectRetainedReclaimAttestation(context.Background(), key)
	if err != nil || verifiedAnchor != anchor {
		t.Fatalf("approved Core off-scope anchor could not be read back: %+v %v", verifiedAnchor, err)
	}
	originalProofs, err := os.ReadDir(filepath.Join(dormantParent, toReclaim[0].Name()))
	if err != nil || len(originalProofs) != len(sealedFiles) {
		t.Fatalf("off-scope audit destroyed original proof: %+v %v", originalProofs, err)
	}
	for _, rule := range closure.Inventory.RuleSets {
		if _, err := os.Stat(filepath.Join(f.stateRoot, "core", "rule-sets", "sha256",
			filepath.Base(rule.RelativePath))); err != nil {
			t.Fatalf("off-scope anchor removed active rule file: %v", err)
		}
	}
	afterAnchor, err := f.store.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(beforeAnchor, afterAnchor) {
		t.Fatalf("off-scope anchor modified live SQLite generation: %v", err)
	}
	// ADR 0122: a complete, bounded signed copy of the original audit
	// metadata can be retained outside the inactive scope. It never
	// copies or activates the approved Core or alters active rule paths.
	beforeMirror, err := f.store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	fullMirror, err := freshLease.MirrorSealedReclaimEvidence(context.Background(), key, anchor)
	if err != nil || !fullMirror.MirrorRetained || !fullMirror.OriginalProofsRetained ||
		fullMirror.RuleCount != len(closure.Inventory.RuleSets) ||
		fullMirror.MirroredProofFiles != len(closure.Inventory.RuleSets)+3 ||
		fullMirror.AttestationSHA256 != anchor.AttestationSHA256 ||
		fullMirror.RestoreReady || fullMirror.RestoreSupported {
		t.Fatalf("approved Core full proof mirror refused: %+v %v", fullMirror, err)
	}
	fullMirrorAgain, err := freshLease.InspectMirroredReclaimEvidence(context.Background(), key)
	if err != nil || fullMirrorAgain != fullMirror {
		t.Fatalf("approved Core full proof mirror did not authenticate: %+v %v", fullMirrorAgain, err)
	}
	// ADR 0123 checks only the retained historical signatures and
	// candidate/journal CAS. No source rule byte absence or metadata unlink
	// is certified by this separately scoped read-only operation.
	detached, err := freshLease.InspectDetachedReclaimMirror(context.Background(), key)
	if err != nil || !detached.ArchiveJournalVerified || !detached.HistoryMACsVerified ||
		detached.SourceScopeVerified || detached.RuleAbsenceVerified ||
		detached.DeletionAuthorized || detached.RestoreReady || detached.RestoreSupported ||
		detached.ArchiveSHA256 != receipt.ArchiveSHA256 ||
		detached.MirrorSHA256 != fullMirror.MirrorSHA256 ||
		detached.RuleCount != len(closure.Inventory.RuleSets) ||
		detached.DocumentedUnlinkedBytes != sealed.UnlinkedBytes {
		t.Fatalf("approved Core detached historic mirror audit refused: %+v %v", detached, err)
	}
	// ADR 0124: non-authorizing manual retention preview reconciles the
	// independent signed history with currently still-present source proofs.
	// It must not turn an audit receipt into cleanup/restore/Core authority.
	review, err := freshLease.ReviewTerminalReclaimRetention(context.Background(), key)
	if err != nil || !review.HistoricalProofsVerified || !review.SourceProofsVerified ||
		review.SourceStatus != reclaimSourceVerified ||
		review.ArchiveSHA256 != receipt.ArchiveSHA256 ||
		review.MirrorSHA256 != fullMirror.MirrorSHA256 ||
		review.RuleCount != len(closure.Inventory.RuleSets) ||
		review.DocumentedUnlinkedBytes != sealed.UnlinkedBytes ||
		review.RetentionPolicyApproved || review.PowerLossReplayVerified ||
		review.PhysicalCleanupAuthorized || review.RestoreSupported ||
		review.RestoreReady || !review.RequiresManualReview ||
		!review.RequiresRevalidation {
		t.Fatalf("approved Core non-authorizing retention review refused: %+v %v", review, err)
	}
	mirrorScope, err := os.ReadDir(filepath.Join(dormantParent, toReclaim[0].Name()))
	if err != nil || len(mirrorScope) != len(sealedFiles) {
		t.Fatalf("full proof mirror modified original private scope: %+v %v", mirrorScope, err)
	}
	for _, rule := range closure.Inventory.RuleSets {
		if _, err := os.Stat(filepath.Join(f.stateRoot, "core", "rule-sets", "sha256",
			filepath.Base(rule.RelativePath))); err != nil {
			t.Fatalf("full proof mirror removed an active rule: %v", err)
		}
	}
	afterMirror, err := f.store.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(beforeMirror, afterMirror) {
		t.Fatalf("full proof mirror modified live SQLite generation: %v", err)
	}
	if err := freshLease.Close(); err != nil {
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
