//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestRetainedEvidenceAdmissionSerializesTwoIndependentDirectoryHandles(t *testing.T) {
	root := newPrivateAdmissionTestDir(t)
	firstFD, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer firstFD.Close()
	secondFD, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer secondFD.Close()
	ctx := context.Background()
	name := reclaimAttestationPrefix + strings.Repeat("a", 64)
	payload := []byte("private signed audit fixture")
	first, err := beginRetainedEvidenceAdmission(ctx, firstFD, name, payload)
	if err != nil {
		t.Fatalf("first writer cannot lock private state directory: %v", err)
	}
	if second, err := beginRetainedEvidenceAdmission(ctx, secondFD, name, payload); err == nil || second != nil || !errors.Is(err, ErrRetainedEvidenceAdmission) {
		t.Fatalf("second independent writer bypassed flock: %+v %v", second, err)
	}
	if err := first.checkBefore(ctx); err != nil {
		t.Fatal(err)
	}
	if err := publishPrivateReclaimMarker(ctx, firstFD, name, payload); err != nil {
		t.Fatal(err)
	}
	if err := firstFD.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := first.checkAfter(ctx); err != nil {
		t.Fatalf("fsynced O_EXCL proof not accepted: %v", err)
	}
	first.close()
	if second, err := beginRetainedEvidenceAdmission(ctx, secondFD, name, payload); err == nil || second != nil {
		t.Fatalf("duplicate proof name was not rejected: %+v %v", second, err)
	}
	newName := reclaimMirrorPrefix + strings.Repeat("b", 64)
	newPayload := []byte("separate proof")
	second, err := beginRetainedEvidenceAdmission(ctx, secondFD, newName, newPayload)
	if err != nil {
		t.Fatalf("released cross-process flock cannot be reacquired: %v", err)
	}
	defer second.close()
	if err := second.checkBefore(ctx); err != nil {
		t.Fatal(err)
	}
	if err := publishPrivateReclaimMirror(ctx, secondFD, newName, newPayload); err != nil {
		t.Fatal(err)
	}
	if err := secondFD.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := second.checkAfter(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRetainedEvidenceAdmissionRefusesLateForeignProofBeforePublishing(t *testing.T) {
	root := newPrivateAdmissionTestDir(t)
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	ctx := context.Background()
	name := reclaimAttestationPrefix + strings.Repeat("b", 64)
	first, err := beginRetainedEvidenceAdmission(ctx, dir, name, []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	defer first.close()
	// A noncooperating external writer remains a security limit. The final
	// pre-openat census must catch its newly appearing proof instead of
	// silently trusting the original admission snapshot.
	other := filepath.Join(root, reclaimMirrorPrefix+strings.Repeat("c", 64))
	if err := os.WriteFile(other, []byte("other"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := first.checkBefore(ctx); !errors.Is(err, ErrRetainedEvidenceAdmission) {
		t.Fatalf("late audit file evaded revalidation: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, name)); !os.IsNotExist(err) {
		t.Fatalf("rejected admission created a file: %v", err)
	}
}

func TestRetainedEvidenceAdmissionBudgetLimitsAndNoAutoRepair(t *testing.T) {
	const name = ".ktui-inert-reclaim-attest-v1-"
	entry := name + strings.Repeat("e", 64)
	for _, tc := range []struct {
		title string
		state retainedEvidenceSnapshot
	}{
		{"entry_limit", retainedEvidenceSnapshot{directoryEntries: maxReclaimEvidenceDirectoryEntries}},
		{"proof_limit", retainedEvidenceSnapshot{proofs: make(map[string]retainedProofObservation, maxReclaimEvidenceProofFiles)}},
		{"byte_limit", retainedEvidenceSnapshot{bytes: maxReclaimEvidenceProofBytes}},
		{"negative", retainedEvidenceSnapshot{bytes: -1}},
	} {
		t.Run(tc.title, func(t *testing.T) {
			if tc.title == "proof_limit" {
				for i := 0; i < maxReclaimEvidenceProofFiles; i++ {
					tc.state.proofs[string(rune(i+1))] = retainedProofObservation{}
				}
			}
			if admitRetainedEvidenceSize(tc.state, entry, 1) {
				t.Fatalf("%s unexpectedly granted write budget", tc.title)
			}
		})
	}
	for _, bad := range []string{
		"", "other", name, name + strings.Repeat("A", 64),
		reclaimMirrorPrefix + strings.Repeat("a", 63),
		reclaimMirrorPrefix + strings.Repeat("a", 64) + "/other",
	} {
		if validRetainedEvidenceName(bad) {
			t.Fatalf("accepted noncanonical proof name %q", bad)
		}
	}
}

func TestRetainedEvidencePublishersUseSharedBudgetAndPreserveLiveState(t *testing.T) {
	f, lease, record, key, _, expected := makeFinishedRuleReclaimFixture(t)
	ctx := context.Background()
	sealed, err := lease.SealCompletedDurableReclaim(ctx, key, expected)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stateParent := filepath.Dir(f.store.Path())
	outsideLock, err := os.Open(stateParent)
	if err != nil {
		t.Fatal(err)
	}
	defer outsideLock.Close()
	// Direct OS lock simulates a different process with a different
	// encrypted archive; no database lockfile or cleanup state is created.
	locked, err := beginRetainedEvidenceAdmission(ctx, outsideLock,
		reclaimMirrorPrefix+strings.Repeat("e", 64), []byte("reserved"))
	if err != nil {
		t.Fatal(err)
	}
	if report, err := lease.AttestSealedDurableReclaim(ctx, key, sealed); err == nil || report != (RetainedReclaimAttestation{}) {
		t.Fatalf("attestation bypassed shared parent lock: %+v %v", report, err)
	}
	locked.close()
	anchor, err := lease.AttestSealedDurableReclaim(ctx, key, sealed)
	if err != nil || !anchor.AttestationRetained || anchor.RestoreReady ||
		anchor.RestoreSupported {
		t.Fatalf("attestation failed after budget lock release: %+v %v", anchor, err)
	}

	locked, err = beginRetainedEvidenceAdmission(ctx, outsideLock,
		reclaimMirrorPrefix+strings.Repeat("f", 64), []byte("reserved"))
	if err != nil {
		t.Fatal(err)
	}
	if report, err := lease.MirrorSealedReclaimEvidence(ctx, key, anchor); err == nil || report != (ReclaimEvidenceMirrorReceipt{}) {
		t.Fatalf("mirror bypassed shared state-parent lock: %+v %v", report, err)
	}
	locked.close()
	mirror, err := lease.MirrorSealedReclaimEvidence(ctx, key, anchor)
	if err != nil || !mirror.MirrorRetained || mirror.RestoreSupported ||
		mirror.RestoreReady || mirror.ArchiveSHA256 != record.ArchiveSHA256 {
		t.Fatalf("mirror failed after budget lock release: %+v %v", mirror, err)
	}
	rechecked, err := lease.InspectMirroredReclaimEvidence(ctx, key)
	if err != nil || rechecked != mirror {
		t.Fatalf("shared-budget publication compromised source signatures: %+v %v", rechecked, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("both proof publishers changed live SQLite: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(stateParent,
		reclaimAttestationPrefix+record.ArchiveSHA256))
	if err != nil || !bytes.Contains(raw, []byte(record.ArchiveSHA256)) {
		t.Fatalf("retained signature evidence missing: %v", err)
	}
}

func TestRetainedEvidencePublicationRefusesOccupiedProofBudget(t *testing.T) {
	f, lease, record, key, _, expected := makeFinishedRuleReclaimFixture(t)
	ctx := context.Background()
	sealed, err := lease.SealCompletedDurableReclaim(ctx, key, expected)
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(f.store.Path())
	for i := 0; i < maxReclaimEvidenceProofFiles; i++ {
		name := filepath.Join(root, reclaimMirrorPrefix+
			fmtReclaimBudgetDigest(i))
		if err := os.WriteFile(name, []byte("x"), 0400); err != nil {
			t.Fatal(err)
		}
	}
	if receipt, err := lease.AttestSealedDurableReclaim(ctx, key, sealed); err == nil || receipt != (RetainedReclaimAttestation{}) {
		t.Fatalf("proof budget exceeded but writer published: %+v %v", receipt, err)
	}
	if _, err := os.Lstat(filepath.Join(root,
		reclaimAttestationPrefix+record.ArchiveSHA256)); !os.IsNotExist(err) {
		t.Fatalf("failed admission left a new attestation: %v", err)
	}
}

func fmtReclaimBudgetDigest(i int) string {
	// A fixed lower-case canonical 64-nibble name. These entries do NOT
	// possess original keys or authenticate as real other-archive proofs.
	hex := "0123456789abcdef"
	var b [64]byte
	for j := range b {
		b[j] = '0'
	}
	b[61] = hex[(i>>8)&15]
	b[62] = hex[(i>>4)&15]
	b[63] = hex[i&15]
	return string(b[:])
}

func newPrivateAdmissionTestDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	// GitHub runner temp-directory permissions are environment-dependent.
	// The production evidence boundary requires exactly owner-private 0700;
	// fix ONLY the test fixture rather than weakening the filesystem check.
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}
