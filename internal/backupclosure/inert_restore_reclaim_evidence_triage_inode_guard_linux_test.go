//go:build linux

package backupclosure

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRetainedTriagePreservesForeignPairNameOnlyAndFencesItsInode(t *testing.T) {
	f, lease, record, key := makeRetainedTriageFixture(t)
	ctx := context.Background()
	stateRoot := filepath.Dir(f.store.Path())
	otherSHA := strings.Repeat("e", 64)
	if otherSHA == record.ArchiveSHA256 {
		otherSHA = strings.Repeat("d", 64)
	}
	// Construct a matched name-only pair with bytes signed for *another*
	// archive. Its MACs are NOT valid for the fabricated archive suffix.
	for _, prefix := range []string{reclaimAttestationPrefix, reclaimMirrorPrefix} {
		raw, err := os.ReadFile(filepath.Join(stateRoot, prefix+record.ArchiveSHA256))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(stateRoot, prefix+otherSHA), raw, 0400); err != nil {
			t.Fatal(err)
		}
	}
	report, err := lease.InspectRetainedEvidenceTriage(ctx, key)
	if err != nil || report.NamedPairs != 2 || report.UnpairedFiles != 0 ||
		!report.ForeignProofNamesOnly || report.PolicyApproved ||
		report.PhysicalCleanupAuthorized || report.ReviewReason != retainedTriageManualPolicy {
		t.Fatalf("name-only pair was promoted to cryptographic or cleanup authority: %+v %v", report, err)
	}
	assertTriageNeverDeletes(t, report)

	// A non-cooperating process changes a *foreign* proof inode without
	// changing its name/bytes/count/size. The original archive's HMACs
	// remain valid; only the cross-review per-file identity fence detects it.
	p := filepath.Join(stateRoot, reclaimMirrorPrefix+otherSHA)
	denied, err := lease.inspectRetainedEvidenceTriage(ctx, key, func() error {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		temp := filepath.Join(stateRoot, "same-byte-foreign-inode-replacement")
		if err := os.WriteFile(temp, raw, 0400); err != nil {
			return err
		}
		return os.Rename(temp, p)
	})
	if err == nil || denied != (RetainedEvidenceTriage{}) {
		t.Fatalf("late foreign inode substitution passed the global fence: %+v %v", denied, err)
	}
	fresh, err := lease.InspectRetainedEvidenceTriage(ctx, key)
	if err != nil || !fresh.HistoricalProofsVerified || !fresh.ForeignProofNamesOnly {
		t.Fatalf("new explicit source-keyed audit incorrectly refused: %+v %v", fresh, err)
	}
	assertTriageNeverDeletes(t, fresh)
}

func TestRetainedTriageRefusesActiveExclusiveProofPublicationLock(t *testing.T) {
	f, lease, _, key := makeRetainedTriageFixture(t)
	ctx := context.Background()
	other, err := os.Open(filepath.Dir(f.store.Path()))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := unix.Flock(int(other.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	denied, err := lease.InspectRetainedEvidenceTriage(ctx, key)
	if err == nil || denied != (RetainedEvidenceTriage{}) {
		t.Fatalf("busy private parent lock did not block manual hold review: %+v %v", denied, err)
	}
	if err := unix.Flock(int(other.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	accepted, err := lease.InspectRetainedEvidenceTriage(ctx, key)
	if err != nil || !accepted.HistoricalProofsVerified || !accepted.ManualHoldRequired {
		t.Fatalf("released directory lock left a stale reviewer lock: %+v %v", accepted, err)
	}
	assertTriageNeverDeletes(t, accepted)
}
