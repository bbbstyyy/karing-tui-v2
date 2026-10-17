//go:build linux

package backupclosure

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
	"golang.org/x/sys/unix"
)

func makeRetainedTriageFixture(t *testing.T) (
	*fixture, *InertRestoreResourceLease, storage.InertRestorePreparation, [32]byte,
) {
	t.Helper()
	f, lease, record, key, _, anchor := makeMirroredReclaimFixture(t)
	if _, err := lease.MirrorSealedReclaimEvidence(context.Background(), key, anchor); err != nil {
		t.Fatal(err)
	}
	return f, lease, record, key
}

func assertTriageNeverDeletes(t *testing.T, r RetainedEvidenceTriage) {
	t.Helper()
	if !r.HistoricalProofsVerified || !r.ForeignProofNamesOnly ||
		!r.AdvisoryLockHeldDuringReview || !r.ManualHoldRequired ||
		r.PolicyApproved || r.PowerLossReplayVerified ||
		r.PhysicalCleanupAuthorized || !r.RequiresRevalidation ||
		r.RestoreSupported || r.RestoreReady {
		t.Fatalf("read-only triage promoted evidence to deletion/restore authority: %+v", r)
	}
}

func TestRetainedTriageKeepsHistoryDistinctFromSourceAndForeignNames(t *testing.T) {
	f, lease, record, key := makeRetainedTriageFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	normal, err := lease.InspectRetainedEvidenceTriage(ctx, key)
	if err != nil || normal.ArchiveSHA256 != record.ArchiveSHA256 ||
		normal.SourceStatus != reclaimSourceVerified ||
		!normal.OriginalSourceProofsVerified ||
		normal.ReviewReason != retainedTriageManualPolicy ||
		normal.AttestationFiles != 1 || normal.MirrorFiles != 1 ||
		normal.NamedPairs != 1 || normal.UnpairedFiles != 0 ||
		normal.RetainedBytes <= 0 ||
		normal.FreeProofSlots != maxReclaimEvidenceProofFiles-2 ||
		normal.FreeProofBytes != maxReclaimEvidenceProofBytes-normal.RetainedBytes ||
		!normal.WorstCaseTwoProofsFit {
		t.Fatalf("original source/retained historical signatures mismatched: %+v %v", normal, err)
	}
	assertTriageNeverDeletes(t, normal)

	stateParent := filepath.Dir(f.store.Path())
	origin := filepath.Join(stateParent, reclaimAttestationPrefix+record.ArchiveSHA256)
	original, err := os.ReadFile(origin)
	if err != nil {
		t.Fatal(err)
	}
	foreignSHA := strings.Repeat("e", 64)
	if foreignSHA == record.ArchiveSHA256 {
		foreignSHA = strings.Repeat("f", 64)
	}
	foreign := filepath.Join(stateParent, reclaimAttestationPrefix+foreignSHA)
	if err := os.WriteFile(foreign, original, 0400); err != nil {
		t.Fatal(err)
	}
	unpaired, err := lease.InspectRetainedEvidenceTriage(ctx, key)
	if err != nil || unpaired.ReviewReason != retainedTriageUnpaired ||
		unpaired.SourceStatus != reclaimSourceVerified ||
		!unpaired.OriginalSourceProofsVerified ||
		unpaired.UnpairedFiles != 1 || unpaired.AttestationFiles != 2 ||
		unpaired.MirrorFiles != 1 || unpaired.NamedPairs != 1 ||
		unpaired.RetainedBytes != normal.RetainedBytes+int64(len(original)) {
		t.Fatalf("foreign lookalike HMAC was trusted rather than counted: %+v %v", unpaired, err)
	}
	assertTriageNeverDeletes(t, unpaired)

	// Keep the entire original audit source privately, but move it out of
	// its known namespace. Detached signed history remains authentic,
	// while current source proof becomes explicitly unverifiable.
	held := filepath.Join(stateParent, "kept-original-inactive-source")
	if err := os.Rename(filepath.Join(stateParent, dormantRuleRootName), held); err != nil {
		t.Fatal(err)
	}
	uncertain, err := lease.InspectRetainedEvidenceTriage(ctx, key)
	if err != nil || uncertain.ReviewReason != retainedTriageSource ||
		uncertain.SourceStatus != reclaimSourceUnverifiable ||
		uncertain.OriginalSourceProofsVerified ||
		uncertain.MirrorSHA256 != normal.MirrorSHA256 ||
		uncertain.NamedPairs != 1 || uncertain.UnpairedFiles != 1 {
		t.Fatalf("missing source was mistaken for safe deletion: %+v %v", uncertain, err)
	}
	assertTriageNeverDeletes(t, uncertain)
	if _, err := os.Stat(held); err != nil {
		t.Fatalf("triage erased original source directory: %v", err)
	}
	parent := lease.candidate.parent
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := AcquireInertRestoreResourceLease(ctx, f.store, parent, record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	restarted, err := fresh.InspectRetainedEvidenceTriage(ctx, key)
	if err != nil || restarted != uncertain {
		t.Fatalf("fresh ciphertext lease failed historical manual hold: %+v %v", restarted, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("triage changed live SQLite configuration: %v", err)
	}
	journal, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(journal) != 1 || journal[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("triage changed original prepared journal: %+v %v", journal, err)
	}
}

func TestRetainedTriageSharedFlockRejectsCooperatingWriterAndLateReplacement(t *testing.T) {
	f, lease, record, key := makeRetainedTriageFixture(t)
	ctx := context.Background()
	stateParent := filepath.Dir(f.store.Path())
	separate, err := os.Open(stateParent)
	if err != nil {
		t.Fatal(err)
	}
	defer separate.Close()
	stable, err := lease.inspectRetainedEvidenceTriage(ctx, key, func() error {
		// The read-only reviewer has SH lock. A separately opened FD used
		// by either ADR 0126 proof publisher cannot take the EX lock.
		if err := unix.Flock(int(separate.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			_ = unix.Flock(int(separate.Fd()), unix.LOCK_UN)
			t.Fatal("concurrent proof publisher bypassed manual triage shared lock")
		}
		return nil
	})
	if err != nil || stable.ReviewReason != retainedTriageManualPolicy {
		t.Fatalf("shared-lock manual review was rejected: %+v %v", stable, err)
	}
	assertTriageNeverDeletes(t, stable)

	// Correct signed bytes under a new inode must be refused, even if
	// another process ignores the advisory shared lock.
	mirror := filepath.Join(stateParent, reclaimMirrorPrefix+record.ArchiveSHA256)
	replaced, err := lease.inspectRetainedEvidenceTriage(ctx, key, func() error {
		original, err := os.ReadFile(mirror)
		if err != nil {
			return err
		}
		tmp := filepath.Join(stateParent, "unexpected-new-mirror-inode")
		if err := os.WriteFile(tmp, original, 0400); err != nil {
			return err
		}
		return os.Rename(tmp, mirror)
	})
	if err == nil || replaced != (RetainedEvidenceTriage{}) {
		t.Fatalf("noncooperating same-byte inode swap passed triage: %+v %v", replaced, err)
	}
	// Future explicit reads are allowed to reauthenticate but still
	// cannot treat the replacement as a deletion authorization.
	refreshed, err := lease.InspectRetainedEvidenceTriage(ctx, key)
	if err != nil || !refreshed.HistoricalProofsVerified {
		t.Fatalf("independent historical revalidation failed: %+v %v", refreshed, err)
	}
	assertTriageNeverDeletes(t, refreshed)
}

func TestRetainedTriageFailsClosedOnUntrustedLeaseOrLiveCAS(t *testing.T) {
	f, lease, _, key := makeRetainedTriageFixture(t)
	ctx := context.Background()
	wrong := key
	wrong[0] ^= 0x20
	if got, err := lease.InspectRetainedEvidenceTriage(ctx, wrong); err == nil ||
		got != (RetainedEvidenceTriage{}) {
		t.Fatalf("wrong key was accepted: %+v %v", got, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := lease.InspectRetainedEvidenceTriage(canceled, key); err == nil ||
		got != (RetainedEvidenceTriage{}) {
		t.Fatalf("canceled review was accepted: %+v %v", got, err)
	}
	_, err := f.store.SetCurrentSelectionIntent(ctx,
		[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := lease.InspectRetainedEvidenceTriage(ctx, key); err == nil ||
		got != (RetainedEvidenceTriage{}) {
		t.Fatalf("stale live state was treated as authenticated: %+v %v", got, err)
	}
}

func TestRetainedTriagePureHeadroomAndHoldPriority(t *testing.T) {
	archiveSHA := strings.Repeat("a", 64)
	review := ReclaimRetentionReview{
		ArchiveSHA256: archiveSHA, InventorySHA256: strings.Repeat("b", 64),
		PlanSHA256:        strings.Repeat("c", 64),
		CompletionSHA256:  strings.Repeat("d", 64),
		AttestationSHA256: strings.Repeat("e", 64),
		MirrorSHA256:      strings.Repeat("f", 64),
		RuleCount:         1, DocumentedUnlinkedBytes: 1,
		HistoricalProofsVerified: true, SourceProofsVerified: true,
		SourceStatus: reclaimSourceVerified, RequiresManualReview: true,
		RequiresRevalidation: true,
	}
	footprint := ReclaimEvidenceFootprint{
		ArchiveSHA256: archiveSHA, DirectoryEntriesSeen: 2,
		AttestationFiles: 1, MirrorFiles: 1, NamedPairs: 1,
		RetainedBytes: 1024, NamesOnly: true,
		RequiresManualReview: true, RequiresRevalidation: true,
		ReviewEntryLimit: maxReclaimEvidenceDirectoryEntries,
		ReviewFileLimit:  maxReclaimEvidenceProofFiles,
		ReviewByteLimit:  maxReclaimEvidenceProofBytes,
	}
	for _, tc := range []struct {
		name       string
		mutate     func(*ReclaimRetentionReview, *ReclaimEvidenceFootprint)
		wantReason string
		fit        bool
	}{
		{"normal", func(*ReclaimRetentionReview, *ReclaimEvidenceFootprint) {},
			retainedTriageManualPolicy, true},
		{"entry", func(_ *ReclaimRetentionReview, p *ReclaimEvidenceFootprint) {
			p.DirectoryEntriesSeen = maxReclaimEvidenceDirectoryEntries - 1
		}, retainedTriageHeadroom, false},
		{"bytes_exact", func(_ *ReclaimRetentionReview, p *ReclaimEvidenceFootprint) {
			p.RetainedBytes = maxReclaimEvidenceProofBytes -
				int64(maxReclaimAttestationBytes+maxReclaimMirrorBytes)
		}, retainedTriageManualPolicy, true},
		{"bytes_short", func(_ *ReclaimRetentionReview, p *ReclaimEvidenceFootprint) {
			p.RetainedBytes = maxReclaimEvidenceProofBytes -
				int64(maxReclaimAttestationBytes+maxReclaimMirrorBytes) + 1
		}, retainedTriageHeadroom, false},
		{"unpaired", func(_ *ReclaimRetentionReview, p *ReclaimEvidenceFootprint) {
			p.DirectoryEntriesSeen++
			p.AttestationFiles++
			p.UnpairedFiles++
		}, retainedTriageUnpaired, true},
		{"source_priority", func(r *ReclaimRetentionReview, p *ReclaimEvidenceFootprint) {
			r.SourceStatus = reclaimSourceUnverifiable
			r.SourceProofsVerified = false
			p.DirectoryEntriesSeen++
			p.AttestationFiles++
			p.UnpairedFiles++
		}, retainedTriageSource, true},
		{"slot_pressure", func(_ *ReclaimRetentionReview, p *ReclaimEvidenceFootprint) {
			p.AttestationFiles = 127
			p.MirrorFiles = 128
			p.NamedPairs = 127
			p.UnpairedFiles = 1
			p.DirectoryEntriesSeen = 255
		}, retainedTriageUnpaired, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, p := review, footprint
			tc.mutate(&r, &p)
			got, err := classifyRetainedEvidenceTriage(r, p)
			if err != nil || got.ReviewReason != tc.wantReason ||
				got.WorstCaseTwoProofsFit != tc.fit {
				t.Fatalf("invalid headroom classification: %+v %v", got, err)
			}
			assertTriageNeverDeletes(t, got)
		})
	}
	invalid := footprint
	invalid.DirectoryEntriesSeen = 1 // less than owned proof files
	if got, err := classifyRetainedEvidenceTriage(review, invalid); err == nil ||
		got != (RetainedEvidenceTriage{}) {
		t.Fatalf("impossible global file counts were accepted: %+v %v", got, err)
	}
}
