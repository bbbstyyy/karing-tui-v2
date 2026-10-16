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

func TestOffScopeReclaimAttestationRetainsSourceEvidence(t *testing.T) {
	f, lease, record, key, parent, expected := makeFinishedRuleReclaimFixture(t)
	ctx := context.Background()
	sealed, err := lease.SealCompletedDurableReclaim(ctx, key, expected)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	attestation, err := lease.AttestSealedDurableReclaim(ctx, key, sealed)
	if err != nil || !attestation.AttestationRetained || !attestation.OriginalEvidenceRetained ||
		!attestation.RequiresRevalidation || attestation.RestoreReady || attestation.RestoreSupported ||
		attestation.ArchiveSHA256 != record.ArchiveSHA256 ||
		attestation.CompletionSHA256 != sealed.CompletionSHA256 ||
		!validLowerSHA(attestation.AttestationSHA256) {
		t.Fatalf("bad independent attestation: %+v %v", attestation, err)
	}
	scope := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
	entries, err := os.ReadDir(scope)
	if err != nil || len(entries) != 3 {
		t.Fatalf("original signed proofs lost: %v %v", entries, err)
	}
	name := filepath.Join(filepath.Dir(f.store.Path()), reclaimAttestationPrefix+record.ArchiveSHA256)
	stat, err := os.Lstat(name)
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0400 {
		t.Fatalf("attestation not private: %v %v", stat, err)
	}
	observed, err := lease.InspectRetainedReclaimAttestation(ctx, key)
	if err != nil || !reflect.DeepEqual(attestation, observed) {
		t.Fatalf("same-lease audit mismatch: %+v %v", observed, err)
	}
	if duplicate, err := lease.AttestSealedDurableReclaim(ctx, key, sealed); err == nil ||
		!reflect.DeepEqual(duplicate, RetainedReclaimAttestation{}) {
		t.Fatalf("duplicate replaced durable attestation: %+v %v", duplicate, err)
	}
	candidateParent := lease.candidate.parent
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := AcquireInertRestoreResourceLease(ctx, f.store, candidateParent, record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	reread, err := restarted.InspectRetainedReclaimAttestation(ctx, key)
	if err != nil || !reflect.DeepEqual(attestation, reread) {
		t.Fatalf("cross-restart independent audit failed: %+v %v", reread, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("audit mutated live config: %v", err)
	}
}

func TestOffScopeReclaimAttestationFailClosed(t *testing.T) {
	for _, fault := range []string{"wrong_key", "forged_expected", "unknown_scope_file", "after_publish", "tamper_marker", "public_marker", "symlink_marker", "missing_original", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent, expected := makeFinishedRuleReclaimFixture(t)
			ctx := context.Background()
			sealed, err := lease.SealCompletedDurableReclaim(ctx, key, expected)
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(filepath.Dir(f.store.Path()), reclaimAttestationPrefix+record.ArchiveSHA256)
			if fault == "wrong_key" {
				key[1] ^= 99
			}
			if fault == "forged_expected" {
				sealed.PlanSHA256 = strings.Repeat("0", 64)
			}
			if fault == "unknown_scope_file" {
				err = os.WriteFile(filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256, "unknown"), []byte("x"), 0600)
				if err != nil {
					t.Fatal(err)
				}
			}
			if fault == "cancel" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			var receipt RetainedReclaimAttestation
			if fault == "after_publish" {
				receipt, err = lease.attestSealedDurableReclaim(ctx, key, sealed, nil, func() error { return ErrRetainedReclaimAttestation })
			} else if fault == "tamper_marker" || fault == "public_marker" || fault == "symlink_marker" || fault == "missing_original" {
				if _, err = lease.AttestSealedDurableReclaim(ctx, key, sealed); err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "tamper_marker":
					err = os.Chmod(marker, 0600)
					if err == nil {
						err = os.WriteFile(marker, []byte("forged"), 0600)
					}
				case "public_marker":
					err = os.Chmod(marker, 0644)
				case "symlink_marker":
					err = os.Remove(marker)
					if err == nil {
						err = os.Symlink("/etc/passwd", marker)
					}
				case "missing_original":
					err = os.Remove(filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256, reclaimPlanFileName))
				}
				if err != nil {
					t.Fatal(err)
				}
				receipt, err = lease.InspectRetainedReclaimAttestation(ctx, key)
			} else {
				receipt, err = lease.AttestSealedDurableReclaim(ctx, key, sealed)
			}
			if err == nil || !reflect.DeepEqual(receipt, RetainedReclaimAttestation{}) {
				t.Fatalf("%s accepted: %+v %v", fault, receipt, err)
			}
			if fault == "after_publish" {
				verified, err := lease.InspectRetainedReclaimAttestation(context.Background(), key)
				if err != nil || !verified.AttestationRetained {
					t.Fatalf("uncertain but visible proof not rechecked: %+v %v", verified, err)
				}
			}
		})
	}
}
