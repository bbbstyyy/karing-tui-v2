//go:build linux

package backupclosure

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRetainedReclaimEvidenceFootprintBoundsAndNeverCertifiesOtherArchives(t *testing.T) {
	f, lease, record, key, _, expected := makeMirroredReclaimFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	anchored, err := lease.InspectReclaimEvidenceFootprint(ctx, key)
	if err != nil || anchored.AttestationFiles != 1 ||
		anchored.MirrorFiles != 0 || anchored.NamedPairs != 0 ||
		anchored.UnpairedFiles != 1 || anchored.RetainedBytes <= 0 {
		t.Fatalf("single retained anchor was not counted: %+v %v", anchored, err)
	}
	assertFootprintCannotCleanup(t, anchored)
	_, err = lease.MirrorSealedReclaimEvidence(ctx, key, expected)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := lease.InspectReclaimEvidenceFootprint(ctx, key)
	if err != nil || pair.AttestationFiles != 1 || pair.MirrorFiles != 1 ||
		pair.NamedPairs != 1 || pair.UnpairedFiles != 0 ||
		pair.RetainedBytes <= anchored.RetainedBytes ||
		pair.ArchiveSHA256 != record.ArchiveSHA256 {
		t.Fatalf("mirrored evidence was miscounted: %+v %v", pair, err)
	}
	assertFootprintCannotCleanup(t, pair)

	// A foreign archive's attestation-like filename is not necessarily a
	// valid HMAC for that archive. Counting it must not authenticate it.
	stateDir := filepath.Dir(f.store.Path())
	source := filepath.Join(stateDir, reclaimAttestationPrefix+record.ArchiveSHA256)
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	foreignDigest := strings.Repeat("f", 64)
	if foreignDigest == record.ArchiveSHA256 {
		foreignDigest = strings.Repeat("e", 64)
	}
	foreign := filepath.Join(stateDir, reclaimAttestationPrefix+foreignDigest)
	if err := os.WriteFile(foreign, raw, 0400); err != nil {
		t.Fatal(err)
	}
	extra, err := lease.InspectReclaimEvidenceFootprint(ctx, key)
	if err != nil || extra.AttestationFiles != 2 || extra.MirrorFiles != 1 ||
		extra.NamedPairs != 1 || extra.UnpairedFiles != 1 ||
		extra.RetainedBytes != pair.RetainedBytes+int64(len(raw)) {
		t.Fatalf("unpaired foreign evidence was not accounted for: %+v %v", extra, err)
	}
	assertFootprintCannotCleanup(t, extra)
	unchanged, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, unchanged) {
		t.Fatalf("read-only footprint review changed SQLite: %v", err)
	}

	// Replacing a private file with identical bytes between complete
	// scans must be refused, never accepted as stable inode provenance.
	var denied ReclaimEvidenceFootprint
	denied, err = lease.inspectReclaimEvidenceFootprint(ctx, key, func() error {
		temp := filepath.Join(stateDir, "new-proof-inode")
		if err := os.WriteFile(temp, raw, 0400); err != nil {
			return err
		}
		return os.Rename(temp, foreign)
	})
	if err == nil || denied != (ReclaimEvidenceFootprint{}) {
		t.Fatalf("late same-byte inode substitution was certified: %+v %v", denied, err)
	}
	rechecked, err := lease.InspectReclaimEvidenceFootprint(ctx, key)
	if err != nil || rechecked != extra {
		t.Fatalf("fresh identity scan of still-private bytes failed: %+v %v", rechecked, err)
	}
	if err := os.Chmod(foreign, 0644); err != nil {
		t.Fatal(err)
	}
	if denied, err := lease.InspectReclaimEvidenceFootprint(ctx, key);
		err == nil || denied != (ReclaimEvidenceFootprint{}) {
		t.Fatalf("public evidence was counted as safe: %+v %v", denied, err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", foreign); err != nil {
		t.Fatal(err)
	}
	if denied, err := lease.InspectReclaimEvidenceFootprint(ctx, key);
		err == nil || denied != (ReclaimEvidenceFootprint{}) {
		t.Fatalf("symlink evidence was followed: %+v %v", denied, err)
	}
	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}
	if denied, err := lease.InspectReclaimEvidenceFootprint(ctx, [32]byte{1});
		err == nil || denied != (ReclaimEvidenceFootprint{}) {
		t.Fatalf("wrong key accepted census: %+v %v", denied, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if denied, err := lease.InspectReclaimEvidenceFootprint(cancelled, key);
		err == nil || denied != (ReclaimEvidenceFootprint{}) {
		t.Fatalf("cancelled census returned results: %+v %v", denied, err)
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
	restarted, err := fresh.InspectReclaimEvidenceFootprint(ctx, key)
	if err != nil || restarted != pair {
		t.Fatalf("cross-process-style lease reopen changed proof footprint: %+v %v", restarted, err)
	}
	_, err = f.store.SetCurrentSelectionIntent(ctx,
		[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"other"}`))
	if err != nil {
		t.Fatal(err)
	}
	if denied, err := fresh.InspectReclaimEvidenceFootprint(ctx, key);
		err == nil || denied != (ReclaimEvidenceFootprint{}) {
		t.Fatalf("stale selection CAS accepted footprint: %+v %v", denied, err)
	}
}

func assertFootprintCannotCleanup(t *testing.T, p ReclaimEvidenceFootprint) {
	t.Helper()
	if !p.NamesOnly || p.CryptographicProofsVerified || p.QuotaEnforced ||
		p.PhysicalCleanupAuthorized || !p.RequiresManualReview ||
		!p.RequiresRevalidation || p.RestoreSupported || p.RestoreReady ||
		p.ReviewFileLimit != maxReclaimEvidenceProofFiles ||
		p.ReviewEntryLimit != maxReclaimEvidenceDirectoryEntries ||
		p.ReviewByteLimit != maxReclaimEvidenceProofBytes {
		t.Fatalf("name-only evidence census claimed cleanup or signing authority: %+v", p)
	}
}
