//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func createInertDryRunFixture(
	t *testing.T,
) (*fixture, *InertRestoreCandidate, [32]byte) {
	t.Helper()
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	archiveParent := testSealedDir(t, f)
	source := filepath.Join(archiveParent, "transaction-fixture.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	// The phase marker is a constant diagnostic label, never a path, key,
	// domain, archive digest, or other potentially sensitive input.
	phase := "admission"
	candidate, err := stageInertRestoreCandidate(context.Background(), source, parent, key,
		func(current string) bool {
			phase = current
			return true
		})
	if err != nil {
		// Race shard regressions occasionally fail in the staging fixture,
		// before any write-boundary assertion runs. Preserve the refusal but
		// distinguish storage pressure from cryptographic/SQLite rejection.
		// Diagnostic preflight is read-only and cannot retry or adopt a candidate.
		var fs syscall.Statfs_t
		fsErr := syscall.Statfs(parent, &fs)
		rechecked, preflightErr := PreflightInertArchive(context.Background(), source, key, nil)
		spaceErr := requireSealedArchiveSpace(parent, rechecked.ArchiveBytes)
		t.Fatalf("encrypted candidate staging refused: %v; stage=%s; fs_error=%v block_size=%d available_blocks=%d; independent_preflight_error=%v archive_bytes=%d schema_verified=%t sqlite_verified=%t reserve_check=%v",
			err, phase, fsErr, fs.Bsize, fs.Bavail, preflightErr, rechecked.ArchiveBytes,
			rechecked.SchemaCatalogVerified, rechecked.SQLiteLogicalVerified, spaceErr)
	}
	t.Cleanup(func() {
		// Tests changing the ciphertext still clean up explicitly and never
		// create an actual recovery attempt.
		if candidate.dir != nil {
			_ = candidate.Discard(context.Background())
		}
	})
	return f, candidate, key
}

func TestInertRestoreDryRunIsReadOnlyAndAlwaysUnauthorized(t *testing.T) {
	f, candidate, key := createInertDryRunFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fenceBefore, err := f.store.ReadInertRestoreFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
	if err != nil || !plan.ArchiveAuthenticated ||
		!plan.SQLiteSchemaVerified || plan.ArchiveBytes <= 0 ||
		plan.RestoreReady || plan.RestoreSupported ||
		plan.Baseline != fenceBefore || !validLowerSHA(plan.ArchiveSHA256) {
		t.Fatalf("inert CAS dry run failed: %+v %v", plan, err)
	}
	if err := RecheckInertRestoreDryRun(ctx, f.store, candidate, key, plan); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("dry run changed live apply state: %+v -> %+v: %v", before, after, err)
	}
	refs, _, err := f.store.ConfirmedGenerationRefs(ctx, 12)
	if err != nil || len(refs) != 1 {
		t.Fatalf("dry run inserted an apply attempt or changed success history: %+v %v", refs, err)
	}
	if _, err := os.Stat(candidate.archive); err != nil {
		t.Fatalf("dry run modified/deleted candidate ciphertext: %v", err)
	}
	if before.ActiveAttemptID != nil {
		t.Fatal("inert dry run created an active attempt")
	}
}

func TestInertRestoreDryRunFaultInjectionCatchesLiveChanges(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		at     string
		change func(*testing.T, *fixture)
	}{
		{"selection_after_fence", dryRunAfterInitialFence, func(t *testing.T, f *fixture) {
			t.Helper()
			if _, err := f.store.SetCurrentSelectionIntent(context.Background(),
				[]byte(`{"kind":"specific_node","profile_id":"test","node_id":"changed"}`)); err != nil {
				t.Fatal(err)
			}
		}},
		{"declaration_after_candidate", dryRunAfterCandidateVerify, func(t *testing.T, f *fixture) {
			t.Helper()
			if _, err := f.store.CommitDeclaration(context.Background(), f.declarationRevision,
				[]byte(`{"version":1,"new":"value"}`), "test:backup-closure"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f, candidate, key := createInertDryRunFixture(t)
			before, err := f.store.Snapshot(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			plan, err := inspectInertRestoreDryRun(
				context.Background(), f.store, candidate, key,
				func(phase string) error {
					if phase == scenario.at {
						scenario.change(t, f)
					}
					return nil
				},
			)
			if !errors.Is(err, ErrInertRestoreDryRunChanged) ||
				!reflect.DeepEqual(plan, InertRestoreDryRun{}) {
				t.Fatalf("stale CAS fence escaped injection: %+v %v", plan, err)
			}
			after, err := f.store.Snapshot(context.Background())
			if err != nil || after.Revision != before.Revision ||
				after.ActiveAttemptID != nil {
				t.Fatalf("dry run staged an apply during fault injection: %+v %v", after, err)
			}
		})
	}
}

func TestInertRestoreDryRunRejectsCandidateTamperAndAbortedPhases(t *testing.T) {
	for _, scenario := range []string{"tamper_after_verify", "hook_failure", "cancel_context"} {
		t.Run(scenario, func(t *testing.T) {
			f, candidate, key := createInertDryRunFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result, err := inspectInertRestoreDryRun(ctx, f.store, candidate, key, func(phase string) error {
				if phase != dryRunAfterCandidateVerify {
					return nil
				}
				switch scenario {
				case "tamper_after_verify":
					file, openErr := os.OpenFile(candidate.archive, os.O_RDWR, 0)
					if openErr != nil {
						return openErr
					}
					var data [1]byte
					if _, openErr := file.ReadAt(data[:], int64(sealedArchiveHeaderBytes+16)); openErr != nil {
						_ = file.Close()
						return openErr
					}
					data[0] ^= 0x80
					_, writeErr := file.WriteAt(data[:], int64(sealedArchiveHeaderBytes+16))
					closeErr := file.Close()
					if writeErr != nil {
						return writeErr
					}
					return closeErr
				case "hook_failure":
					return errors.New("injected read-only planning failure")
				case "cancel_context":
					cancel()
				}
				return nil
			})
			if !reflect.DeepEqual(result, InertRestoreDryRun{}) {
				t.Fatalf("failed dry run leaked a valid-looking report: %+v", result)
			}
			if !errors.Is(err, ErrInertRestoreDryRunRejected) &&
				!errors.Is(err, context.Canceled) {
				t.Fatalf("fault-injected boundary accepted: %v", err)
			}
			after, snapErr := f.store.Snapshot(context.Background())
			if snapErr != nil || after.ActiveAttemptID != nil || after.Revision != 1 {
				t.Fatalf("dry run fault changed live state: %+v %v", after, snapErr)
			}
		})
	}
}

func TestInertRestoreDryRunRecheckRefusesStaleAndForgedEvidence(t *testing.T) {
	f, candidate, key := createInertDryRunFixture(t)
	ctx := context.Background()
	original, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"restore_ready", "changed_digest", "changed_fence"} {
		forged := original
		switch field {
		case "restore_ready":
			forged.RestoreReady = true
		case "changed_digest":
			forged.ArchiveSHA256 = strings.Repeat("a", 64)
		case "changed_fence":
			forged.Baseline.ConfigRevision++
		}
		err := RecheckInertRestoreDryRun(ctx, f.store, candidate, key, forged)
		if !errors.Is(err, ErrInertRestoreDryRunRejected) &&
			!errors.Is(err, ErrInertRestoreDryRunChanged) {
			t.Fatalf("forged %s accepted: %v", field, err)
		}
	}
	if _, err := f.store.SetCurrentSelectionIntent(ctx,
		[]byte(`{"kind":"specific_node","profile_id":"one","node_id":"two"}`)); err != nil {
		t.Fatal(err)
	}
	if err := RecheckInertRestoreDryRun(ctx, f.store, candidate, key, original); !errors.Is(err, ErrInertRestoreDryRunChanged) {
		t.Fatalf("stale preflight did not fail recheck: %v", err)
	}
}

func TestInertRestoreDryRunRejectsActiveApplyAndRecoveryRequired(t *testing.T) {
	for _, failure := range []string{"active_apply", "recovery_required"} {
		t.Run(failure, func(t *testing.T) {
			f, candidate, key := createInertDryRunFixture(t)
			ctx := context.Background()
			if failure == "active_apply" {
				if _, err := f.store.PrepareApply(ctx, f.configRevision, []byte(`{"inbounds":[]}`)); err != nil {
					t.Fatal(err)
				}
			} else {
				// Recovery-required is exercised through the public store
				// lifecycle: an interrupted activating journal sets it.
				attempt, err := f.store.PrepareApply(ctx, f.configRevision, []byte(`{"inbounds":[]}`))
				if err != nil {
					t.Fatal(err)
				}
				if err := f.store.BeginActivation(ctx, attempt.ID); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.RecoverInterrupted(ctx); err != nil {
					t.Fatal(err)
				}
			}
			plan, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
			if !errors.Is(err, ErrInertRestoreDryRunRejected) ||
				!reflect.DeepEqual(plan, InertRestoreDryRun{}) {
				t.Fatalf("unsafe live state generated inert restore dry-run: %+v %v", plan, err)
			}
		})
	}
}

func TestInertRestoreDryRunRequiresLockedCandidate(t *testing.T) {
	f, candidate, key := createInertDryRunFixture(t)
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	plan, err := InspectInertRestoreDryRun(context.Background(), f.store, candidate, key)
	if !errors.Is(err, ErrInertRestoreDryRunRejected) ||
		!reflect.DeepEqual(plan, InertRestoreDryRun{}) {
		t.Fatalf("closed candidate permitted a dry run: %+v %v", plan, err)
	}
	// Never auto-delete a ciphertext scope just because its lease was lost.
	if _, err := os.Lstat(candidate.Directory()); err != nil {
		t.Fatalf("closed candidate was removed: %v", err)
	}
}
