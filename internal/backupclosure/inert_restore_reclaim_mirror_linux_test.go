//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func makeMirroredReclaimFixture(t *testing.T) (
	*fixture, *InertRestoreResourceLease, storage.InertRestorePreparation,
	[32]byte, string, RetainedReclaimAttestation,
) {
	t.Helper()
	f, lease, record, key, parent, finished := makeFinishedRuleReclaimFixture(t)
	sealed, err := lease.SealCompletedDurableReclaim(context.Background(), key, finished)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := lease.AttestSealedDurableReclaim(context.Background(), key, sealed)
	if err != nil {
		t.Fatal(err)
	}
	return f, lease, record, key, parent, anchor
}

func TestReclaimMirrorCopiesEveryProofButNeverOriginalRules(t *testing.T) {
	f, lease, record, key, parent, expected := makeMirroredReclaimFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mirror, err := lease.MirrorSealedReclaimEvidence(ctx, key, expected)
	if err != nil || !mirror.MirrorRetained || !mirror.OriginalProofsRetained ||
		!mirror.RequiresRevalidation || mirror.RestoreSupported || mirror.RestoreReady ||
		mirror.RuleCount != 1 || mirror.MirroredProofFiles != 4 ||
		mirror.MirroredProofBytes <= 0 ||
		!validLowerSHA(mirror.MirrorSHA256) ||
		mirror.AttestationSHA256 != expected.AttestationSHA256 ||
		mirror.ArchiveSHA256 != record.ArchiveSHA256 {
		t.Fatalf("mirror contract incorrect: %+v %v", mirror, err)
	}
	scope := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
	proofs, err := os.ReadDir(scope)
	if err != nil || len(proofs) != 3 {
		t.Fatalf("source evidence was deleted: %v %v", proofs, err)
	}
	originPlan, err := os.ReadFile(filepath.Join(scope, reclaimPlanFileName))
	if err != nil {
		t.Fatal(err)
	}
	originCompletion, err := os.ReadFile(filepath.Join(scope, reclaimCompletionName))
	if err != nil {
		t.Fatal(err)
	}
	originIntent, err := os.ReadFile(filepath.Join(scope, reclaimIntentPrefix+"000"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(f.store.Path())
	originAnchor, err := os.ReadFile(filepath.Join(dir, reclaimAttestationPrefix+record.ArchiveSHA256))
	if err != nil {
		t.Fatal(err)
	}
	mirrorPath := filepath.Join(dir, reclaimMirrorPrefix+record.ArchiveSHA256)
	stat, err := os.Lstat(mirrorPath)
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0o400 {
		t.Fatalf("mirror not owner-private immutable file: %v %v", stat, err)
	}
	mirrorData, err := os.ReadFile(mirrorPath)
	if err != nil {
		t.Fatal(err)
	}
	var signed reclaimSignedMirror
	if err := json.Unmarshal(mirrorData, &signed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(signed.Body.Plan, originPlan) ||
		!bytes.Equal(signed.Body.Completion, originCompletion) ||
		!bytes.Equal(signed.Body.Attestation, originAnchor) ||
		len(signed.Body.Intents) != 1 ||
		signed.Body.Intents[0].Name != reclaimIntentPrefix+"000" ||
		signed.Body.Intents[0].MAC != string(originIntent) ||
		signed.Body.RuleCount != 1 ||
		signed.Body.PlanSHA256 != expected.PlanSHA256 ||
		signed.Body.AttestationSHA256 != expected.AttestationSHA256 ||
		bytes.Contains(mirrorData, f.ruleData) {
		t.Fatal("mirror lost proofs or copied raw rule/config bytes")
	}
	if observed, err := lease.InspectMirroredReclaimEvidence(ctx, key); err != nil || !reflect.DeepEqual(observed, mirror) {
		t.Fatalf("same-process signed mirror verification failed: %+v %v", observed, err)
	}
	if duplicate, err := lease.MirrorSealedReclaimEvidence(ctx, key, expected); err == nil || !reflect.DeepEqual(duplicate, ReclaimEvidenceMirrorReceipt{}) {
		t.Fatalf("repeated mirror publication overwrote proof: %+v %v", duplicate, err)
	}
	if anchorAgain, err := lease.InspectRetainedReclaimAttestation(ctx, key); err != nil || anchorAgain != expected {
		t.Fatalf("original independent attestation was invalidated: %+v %v", anchorAgain, err)
	}
	if _, err := os.Stat(filepath.Join(f.stateRoot, "core", "rule-sets", "sha256",
		f.ruleHash+".json")); err != nil {
		t.Fatalf("mirroring changed live ruleset: %v", err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("mirroring mutated live generation state: %v", err)
	}
	records, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(records) != 1 || records[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("mirroring changed recovery journal: %+v %v", records, err)
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
	verified, err := reopened.InspectMirroredReclaimEvidence(ctx, key)
	if err != nil || verified != mirror {
		t.Fatalf("independent cross-restart proof mismatch: %+v %v", verified, err)
	}
}

func TestReclaimMirrorRefusesUntrustedOrIncompleteEvidence(t *testing.T) {
	for _, fault := range []string{
		"wrong_key", "forged_receipt", "missing_anchor", "missing_intent",
		"unknown_scope_entry", "source_scope_public", "selection_change",
		"canceled", "closed_lease", "late_source_swap",
		"late_unknown_entry", "late_selection", "after_file_fsync",
		"mirror_tamper", "mirror_public", "mirror_symlink",
	} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent, expected := makeMirroredReclaimFixture(t)
			ctx := context.Background()
			scope := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
			anchorPath := filepath.Join(filepath.Dir(f.store.Path()), reclaimAttestationPrefix+record.ArchiveSHA256)
			mirrorPath := filepath.Join(filepath.Dir(f.store.Path()), reclaimMirrorPrefix+record.ArchiveSHA256)
			var err error
			switch fault {
			case "wrong_key":
				key[0] ^= 0x55
			case "forged_receipt":
				expected.PlanSHA256 = strings.Repeat("0", 64)
			case "missing_anchor":
				err = os.Remove(anchorPath)
			case "missing_intent":
				err = os.Remove(filepath.Join(scope, reclaimIntentPrefix+"000"))
			case "unknown_scope_entry":
				err = os.WriteFile(filepath.Join(scope, "unknown"), []byte("x"), 0600)
			case "source_scope_public":
				err = os.Chmod(scope, 0755)
			case "selection_change":
				_, err = f.store.SetCurrentSelectionIntent(ctx,
					[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"altered"}`))
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed_lease":
				err = lease.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			var result ReclaimEvidenceMirrorReceipt
			switch fault {
			case "late_source_swap", "late_unknown_entry", "late_selection":
				result, err = lease.mirrorSealedReclaimEvidence(ctx, key, expected, func() error {
					switch fault {
					case "late_source_swap":
						name := filepath.Join(scope, reclaimIntentPrefix+"000")
						other := filepath.Join(scope, "replacement")
						b, e := os.ReadFile(name)
						if e != nil {
							return e
						}
						if e = os.WriteFile(other, b, 0400); e != nil {
							return e
						}
						return os.Rename(other, name)
					case "late_unknown_entry":
						return os.WriteFile(filepath.Join(scope, "late"), []byte("x"), 0600)
					case "late_selection":
						_, e := f.store.SetCurrentSelectionIntent(context.Background(),
							[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`))
						return e
					}
					return nil
				}, nil)
			case "after_file_fsync":
				result, err = lease.mirrorSealedReclaimEvidence(ctx, key, expected, nil,
					func() error { return ErrReclaimEvidenceMirror })
			case "mirror_tamper", "mirror_public", "mirror_symlink":
				if _, err = lease.MirrorSealedReclaimEvidence(ctx, key, expected); err != nil {
					t.Fatal(err)
				}
				switch fault {
				case "mirror_tamper":
					err = os.Chmod(mirrorPath, 0600)
					if err == nil {
						err = os.WriteFile(mirrorPath, []byte("not signed"), 0600)
					}
					if err == nil {
						err = os.Chmod(mirrorPath, 0400)
					}
				case "mirror_public":
					err = os.Chmod(mirrorPath, 0644)
				case "mirror_symlink":
					err = os.Remove(mirrorPath)
					if err == nil {
						err = os.Symlink("/etc/passwd", mirrorPath)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				result, err = lease.InspectMirroredReclaimEvidence(ctx, key)
			default:
				result, err = lease.MirrorSealedReclaimEvidence(ctx, key, expected)
			}
			if err == nil || !reflect.DeepEqual(result, ReclaimEvidenceMirrorReceipt{}) {
				t.Fatalf("mirror accepted %s: %+v %v", fault, result, err)
			}
			switch fault {
			case "after_file_fsync":
				verified, err := lease.InspectMirroredReclaimEvidence(context.Background(), key)
				if err != nil || !verified.MirrorRetained {
					t.Fatalf("uncertain visible mirror could not be independently verified: %+v %v", verified, err)
				}
			case "mirror_tamper", "mirror_public", "mirror_symlink":
				// The private source proof directory remains unchanged.
			default:
				if _, err := os.Lstat(mirrorPath); !os.IsNotExist(err) {
					t.Fatalf("refused %s nevertheless created mirror: %v", fault, err)
				}
			}
		})
	}
}
