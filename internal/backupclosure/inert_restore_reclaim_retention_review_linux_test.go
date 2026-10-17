//go:build linux

package backupclosure

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestTerminalReclaimRetentionReviewSeparatesSourceAndHistory(t *testing.T) {
	f, lease, record, key, _, expected := makeMirroredReclaimFixture(t)
	ctx := context.Background()
	mirror, err := lease.MirrorSealedReclaimEvidence(ctx, key, expected)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := lease.ReviewTerminalReclaimRetention(ctx, key)
	if err != nil || !clean.HistoricalProofsVerified || !clean.SourceProofsVerified ||
		clean.SourceStatus != reclaimSourceVerified ||
		clean.ArchiveSHA256 != record.ArchiveSHA256 ||
		clean.MirrorSHA256 != mirror.MirrorSHA256 ||
		clean.RuleCount != mirror.RuleCount ||
		clean.DocumentedUnlinkedBytes != int64(len(f.ruleData)) {
		t.Fatalf("source-present review invalid: %+v %v", clean, err)
	}
	assertNeverAuthorizesReclaimCleanup(t, clean)

	// Retain the original namespace elsewhere, without erasing any bytes.
	// The detached historical proof remains valid while source verification
	// can no longer succeed. That is a review-only, not a cleanup, condition.
	stateParent := filepath.Dir(f.store.Path())
	root := filepath.Join(stateParent, dormantRuleRootName)
	held := filepath.Join(stateParent, "held-rules-review")
	if err := os.Rename(root, held); err != nil {
		t.Fatal(err)
	}
	unknown, err := lease.ReviewTerminalReclaimRetention(ctx, key)
	if err != nil || !unknown.HistoricalProofsVerified || unknown.SourceProofsVerified ||
		unknown.SourceStatus != reclaimSourceUnverifiable ||
		unknown.MirrorSHA256 != clean.MirrorSHA256 ||
		unknown.RuleCount != clean.RuleCount ||
		unknown.DocumentedUnlinkedBytes != clean.DocumentedUnlinkedBytes {
		t.Fatalf("missing source incorrectly made old history a cleanup permit: %+v %v", unknown, err)
	}
	assertNeverAuthorizesReclaimCleanup(t, unknown)
	if _, err := os.Stat(held); err != nil {
		t.Fatalf("historical inspection deleted the still-retained original source: %v", err)
	}

	candidateParent := lease.candidate.parent
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := AcquireInertRestoreResourceLease(ctx, f.store, candidateParent, record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	restarted, err := reopened.ReviewTerminalReclaimRetention(ctx, key)
	if err != nil || restarted != unknown {
		t.Fatalf("source-independent retention review changed after restart: %+v %v", restarted, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("review mutated active SQLite state: %v", err)
	}
	journals, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(journals) != 1 || journals[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("review changed original prepared restore journal: %+v %v", journals, err)
	}
	wrong := key
	wrong[0] ^= 1
	if got, err := reopened.ReviewTerminalReclaimRetention(ctx, wrong); err == nil || got != (ReclaimRetentionReview{}) {
		t.Fatalf("wrong key unexpectedly verified audit: %+v %v", got, err)
	}
	closedCtx, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := reopened.ReviewTerminalReclaimRetention(closedCtx, key); err == nil || got != (ReclaimRetentionReview{}) {
		t.Fatalf("canceled audit returned a successful report: %+v %v", got, err)
	}
	_, err = f.store.SetCurrentSelectionIntent(ctx, []byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := reopened.ReviewTerminalReclaimRetention(ctx, key); err == nil || got != (ReclaimRetentionReview{}) {
		t.Fatalf("stale live CAS unexpectedly accepted retention review: %+v %v", got, err)
	}
}

func assertNeverAuthorizesReclaimCleanup(t *testing.T, report ReclaimRetentionReview) {
	t.Helper()
	if report.RetentionPolicyApproved || report.PowerLossReplayVerified ||
		report.PhysicalCleanupAuthorized || report.RestoreSupported ||
		report.RestoreReady || !report.RequiresManualReview ||
		!report.RequiresRevalidation {
		t.Fatalf("historical proof review granted unauthorized cleanup or restore: %+v", report)
	}
}
