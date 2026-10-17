//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestDetachedMirrorAuthenticatesHistoryWithoutSourceScope(t *testing.T) {
	f, lease, record, key, _, expected := makeMirroredReclaimFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	mirror, err := lease.MirrorSealedReclaimEvidence(ctx, key, expected)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := lease.InspectDetachedReclaimMirror(ctx, key)
	if err != nil || !observed.ArchiveJournalVerified || !observed.HistoryMACsVerified ||
		observed.SourceScopeVerified || observed.RuleAbsenceVerified ||
		observed.DeletionAuthorized || observed.RestoreSupported || observed.RestoreReady ||
		!observed.RequiresRevalidation || observed.MirrorSHA256 != mirror.MirrorSHA256 ||
		observed.AttestationSHA256 != mirror.AttestationSHA256 ||
		observed.RuleCount != mirror.RuleCount ||
		observed.DocumentedUnlinkedBytes != int64(len(f.ruleData)) ||
		observed.MirroredProofFiles != mirror.MirroredProofFiles ||
		observed.MirroredProofBytes != mirror.MirroredProofBytes {
		t.Fatalf("detached proof advertised unsafe authority: %+v %v", observed, err)
	}

	// Retain the entire source as a separately named private directory.
	// The normal source-bound inspector MUST now fail, while the off-scope
	// audit can reauthenticate historical proofs without even opening it.
	stateParent := filepath.Dir(f.store.Path())
	root := filepath.Join(stateParent, dormantRuleRootName)
	held := filepath.Join(stateParent, "held-reclaim-for-audit")
	if err := os.Rename(root, held); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.InspectMirroredReclaimEvidence(ctx, key); err == nil {
		t.Fatal("source-bound inspector silently ignored missing source directory")
	}
	rechecked, err := lease.InspectDetachedReclaimMirror(ctx, key)
	if err != nil || rechecked != observed {
		t.Fatalf("detached evidence relied on a source directory: %+v %v", rechecked, err)
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
	restarted, err := reopened.InspectDetachedReclaimMirror(ctx, key)
	if err != nil || restarted != observed {
		t.Fatalf("detached proof could not be reauthenticated after lease restart: %+v %v", restarted, err)
	}
	if entries, err := os.ReadDir(held); err != nil || len(entries) != 1 {
		t.Fatalf("independent inspection modified held original scope: %+v %v", entries, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("detached proof audit changed active state: %v", err)
	}
	records, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(records) != 1 || records[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("detached audit changed v18 recovery journal: %+v %v", records, err)
	}
}

func TestDetachedMirrorFailsClosedOnUnavailableAuthority(t *testing.T) {
	for _, fault := range []string{
		"wrong_key", "canceled", "closed_lease", "journal_abandon", "live_selection",
		"missing_mirror", "missing_attestation", "public_mirror", "linked_mirror",
		"symlink_mirror", "tampered_mirror", "tampered_attestation", "unknown_source",
	} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent, expected := makeMirroredReclaimFixture(t)
			ctx := context.Background()
			if _, err := lease.MirrorSealedReclaimEvidence(ctx, key, expected); err != nil {
				t.Fatal(err)
			}
			stateParent := filepath.Dir(f.store.Path())
			mirrorPath := filepath.Join(stateParent, reclaimMirrorPrefix+record.ArchiveSHA256)
			anchorPath := filepath.Join(stateParent, reclaimAttestationPrefix+record.ArchiveSHA256)
			var err error
			switch fault {
			case "wrong_key":
				key[1] ^= 0x48
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed_lease":
				err = lease.Close()
			case "journal_abandon":
				err = f.store.AbandonInertRestoreRecord(
					ctx, record.ID, record.CandidateScope, record.ArchiveSHA256)
			case "live_selection":
				_, err = f.store.SetCurrentSelectionIntent(ctx,
					[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"stale"}`))
			case "missing_mirror":
				err = os.Remove(mirrorPath)
			case "missing_attestation":
				err = os.Remove(anchorPath)
			case "public_mirror":
				err = os.Chmod(mirrorPath, 0644)
			case "linked_mirror":
				err = os.Link(mirrorPath, filepath.Join(stateParent, "mirror-second-link"))
			case "symlink_mirror":
				err = os.Remove(mirrorPath)
				if err == nil {
					err = os.Symlink("/etc/passwd", mirrorPath)
				}
			case "tampered_mirror":
				err = os.Chmod(mirrorPath, 0600)
				if err == nil {
					err = os.WriteFile(mirrorPath, []byte("bad"), 0600)
				}
				if err == nil {
					err = os.Chmod(mirrorPath, 0400)
				}
			case "tampered_attestation":
				err = os.Chmod(anchorPath, 0600)
				if err == nil {
					err = os.WriteFile(anchorPath, []byte("bad"), 0600)
				}
				if err == nil {
					err = os.Chmod(anchorPath, 0400)
				}
			case "unknown_source":
				// The original source namespace is deliberately not read:
				// moving it changes nothing about authenticated *history*.
				root := filepath.Join(stateParent, dormantRuleRootName)
				err = os.Rename(root, filepath.Join(stateParent, "separate-held-source"))
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := lease.InspectDetachedReclaimMirror(ctx, key)
			if fault == "unknown_source" {
				if err != nil || !got.HistoryMACsVerified ||
					got.SourceScopeVerified || got.RuleAbsenceVerified ||
					got.DeletionAuthorized {
					t.Fatalf("historical mirror implied live source authority: %+v %v", got, err)
				}
				return
			}
			if err == nil || !reflect.DeepEqual(got, DetachedReclaimMirrorAudit{}) {
				t.Fatalf("detached audit accepted %s: %+v %v", fault, got, err)
			}
			_ = parent
		})
	}
}

// Re-sign the OUTER mirror with the original test key. A valid outer HMAC
// must never bypass the independently checked inner plan, completion,
// attestation or per-leaf intent identities and counts.
func TestDetachedMirrorRejectsValidOuterMACWithFalseNestedClaims(t *testing.T) {
	for _, fault := range []string{
		"wrong_journal", "wrong_scope_inode", "wrong_rule_count",
		"forged_absent_bytes", "forged_intent", "forged_plan",
		"wrong_completion_digest", "wrong_anchor_digest", "extra_intent",
	} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, _, expected := makeMirroredReclaimFixture(t)
			ctx := context.Background()
			if _, err := lease.MirrorSealedReclaimEvidence(ctx, key, expected); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(filepath.Dir(f.store.Path()), reclaimMirrorPrefix+record.ArchiveSHA256)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var mirror reclaimSignedMirror
			if err := json.Unmarshal(raw, &mirror); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "wrong_journal":
				mirror.Body.JournalID++
			case "wrong_scope_inode":
				mirror.Body.ScopeInode++
			case "wrong_rule_count":
				mirror.Body.RuleCount++
			case "forged_absent_bytes":
				mirror.Body.UnlinkedBytes++
			case "forged_intent":
				mirror.Body.Intents[0].MAC = strings.Repeat("1", 64)
			case "forged_plan":
				var plan reclaimSignedPlan
				if err := json.Unmarshal(mirror.Body.Plan, &plan); err != nil {
					t.Fatal(err)
				}
				plan.Body.Rules[0].Size++
				replaced, err := json.Marshal(plan)
				if err != nil {
					t.Fatal(err)
				}
				mirror.Body.Plan = replaced
				mirror.Body.PlanSHA256 = shaHex(replaced)
			case "wrong_completion_digest":
				mirror.Body.CompletionSHA256 = strings.Repeat("a", 64)
			case "wrong_anchor_digest":
				mirror.Body.AttestationSHA256 = strings.Repeat("b", 64)
			case "extra_intent":
				mirror.Body.Intents = append(mirror.Body.Intents, mirror.Body.Intents[0])
			}
			body, err := json.Marshal(mirror.Body)
			if err != nil {
				t.Fatal(err)
			}
			mac := hmac.New(sha256.New, key[:])
			_, _ = mac.Write([]byte("karing-tui-v2/durable-rule-reclaim/full-proof-mirror-v1\x00"))
			_, _ = mac.Write(body)
			mirror.MAC = hex.EncodeToString(mac.Sum(nil))
			forged, err := json.Marshal(mirror)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(forged, raw) {
				t.Fatal("test did not forge proof")
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, forged, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0400); err != nil {
				t.Fatal(err)
			}
			audit, err := lease.InspectDetachedReclaimMirror(ctx, key)
			if err == nil || !reflect.DeepEqual(audit, DetachedReclaimMirrorAudit{}) {
				t.Fatalf("signed but false nested claims accepted for %s: %+v %v", fault, audit, err)
			}
		})
	}
}

// Even if all five historical signatures are recomputed with the correct test
// key, no mirrored history can override the immutable encrypted archive's
// actual rule digest/length inventory. This guards against "trust signed
// metadata alone" regressions in the detached source-less verifier.
func TestDetachedMirrorRejectsFullyResignedInventoryMismatch(t *testing.T) {
	f, lease, record, key, _, expected := makeMirroredReclaimFixture(t)
	ctx := context.Background()
	if _, err := lease.MirrorSealedReclaimEvidence(ctx, key, expected); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Dir(f.store.Path())
	mirrorPath := filepath.Join(parent, reclaimMirrorPrefix+record.ArchiveSHA256)
	anchorPath := filepath.Join(parent, reclaimAttestationPrefix+record.ArchiveSHA256)
	raw, err := os.ReadFile(mirrorPath)
	if err != nil {
		t.Fatal(err)
	}
	var mirror reclaimSignedMirror
	if err := json.Unmarshal(raw, &mirror); err != nil {
		t.Fatal(err)
	}
	var plan reclaimSignedPlan
	if err := json.Unmarshal(mirror.Body.Plan, &plan); err != nil {
		t.Fatal(err)
	}
	plan.Body.Rules[0].Size++
	plan.MAC, err = reclaimPlanMAC(plan.Body, key)
	if err != nil {
		t.Fatal(err)
	}
	newPlan, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	mirror.Body.Plan = newPlan
	mirror.Body.PlanSHA256 = shaHex(newPlan)
	mirror.Body.Intents[0].MAC = reclaimIntentMAC(
		key, mirror.Body.PlanSHA256, 0, plan.Body.Rules[0].Name)

	var completion reclaimSignedCompletion
	if err := json.Unmarshal(mirror.Body.Completion, &completion); err != nil {
		t.Fatal(err)
	}
	completion.Body.PlanSHA256 = mirror.Body.PlanSHA256
	completion.Body.UnlinkedBytes++
	completion.MAC, err = reclaimCompletionMAC(completion.Body, key)
	if err != nil {
		t.Fatal(err)
	}
	newCompletion, err := json.Marshal(completion)
	if err != nil {
		t.Fatal(err)
	}
	mirror.Body.Completion = newCompletion
	mirror.Body.CompletionSHA256 = shaHex(newCompletion)

	var anchor reclaimSignedAttestation
	if err := json.Unmarshal(mirror.Body.Attestation, &anchor); err != nil {
		t.Fatal(err)
	}
	anchor.Body.PlanSHA256 = mirror.Body.PlanSHA256
	anchor.Body.CompletionSHA256 = mirror.Body.CompletionSHA256
	anchor.Body.UnlinkedBytes++
	rawAnchorBody, err := json.Marshal(anchor.Body)
	if err != nil {
		t.Fatal(err)
	}
	anchorMAC := hmac.New(sha256.New, key[:])
	_, _ = anchorMAC.Write([]byte("karing-tui-v2/durable-rule-reclaim/off-scope-attestation-v1\x00"))
	_, _ = anchorMAC.Write(rawAnchorBody)
	anchor.MAC = hex.EncodeToString(anchorMAC.Sum(nil))
	newAnchor, err := json.Marshal(anchor)
	if err != nil {
		t.Fatal(err)
	}
	mirror.Body.Attestation = newAnchor
	mirror.Body.AttestationSHA256 = shaHex(newAnchor)
	mirror.Body.UnlinkedBytes++
	rawMirrorBody, err := json.Marshal(mirror.Body)
	if err != nil {
		t.Fatal(err)
	}
	mirrorMAC := hmac.New(sha256.New, key[:])
	_, _ = mirrorMAC.Write([]byte("karing-tui-v2/durable-rule-reclaim/full-proof-mirror-v1\x00"))
	_, _ = mirrorMAC.Write(rawMirrorBody)
	mirror.MAC = hex.EncodeToString(mirrorMAC.Sum(nil))
	newMirror, err := json.Marshal(mirror)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []struct {
		path string
		data []byte
	}{{anchorPath, newAnchor}, {mirrorPath, newMirror}} {
		if err := os.Chmod(file.path, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file.path, file.data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file.path, 0400); err != nil {
			t.Fatal(err)
		}
	}
	if audit, err := lease.InspectDetachedReclaimMirror(ctx, key); err == nil || !reflect.DeepEqual(audit, DetachedReclaimMirrorAudit{}) {
		t.Fatalf("re-signed but archive-inconsistent rule inventory accepted: %+v %v", audit, err)
	}
}
