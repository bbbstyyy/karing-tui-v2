//go:build linux

package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

func TestInertRestorePrepareCrashHelper(t *testing.T) {
	mode := os.Getenv("KTUI_INERT_PREP_HELPER")
	if mode != "inside" && mode != "committed" {
		return
	}
	ctx := context.Background()
	s, err := Open(ctx, os.Getenv("KTUI_INERT_PREP_DATABASE"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fence, err := s.ReadInertRestoreFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	input := inertPreparationInput(fence)
	if mode == "inside" {
		_, err := s.prepareInertRestoreRecord(ctx, input, func() error {
			if _, err := os.Stdout.Write([]byte("inside\n")); err != nil {
				return err
			}
			time.Sleep(3 * time.Minute)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := s.PrepareInertRestoreRecord(ctx, input); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.Write([]byte("committed\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Minute)
}

func TestInertRestorePreparationSIGKILLBeforeAndAfterCommit(t *testing.T) {
	for _, mode := range []string{"inside", "committed"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			s, fence := newCommittedInertFenceFixture(t)
			before, err := s.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			childCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(childCtx, os.Args[0],
				"-test.run=^TestInertRestorePrepareCrashHelper$")
			cmd.Env = append(os.Environ(),
				"KTUI_INERT_PREP_HELPER="+mode,
				"KTUI_INERT_PREP_DATABASE="+s.Path())
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reaped := false
			t.Cleanup(func() {
				if !reaped {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			})
			signal := make([]byte, len(mode)+1)
			if _, err := io.ReadFull(stdout, signal); err != nil ||
				string(signal) != mode+"\n" {
				t.Fatalf("helper failed to reach crash boundary: %q %v", signal, err)
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			reaped = true
			if err := s.quickCheck(ctx); err != nil {
				t.Fatalf("SIGKILL corrupted SQLite: %v", err)
			}
			after, err := s.Snapshot(ctx)
			if err != nil || !reflect.DeepEqual(before, after) ||
				after.ActiveAttemptID != nil {
				t.Fatalf("crash modified live apply state: %+v -> %+v %v", before, after, err)
			}
			records, err := s.InspectInertRestoreRecords(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "inside" {
				if len(records) != 0 {
					t.Fatalf("SIGKILL committed an uncommitted inert row: %+v", records)
				}
				if _, err := s.PrepareInertRestoreRecord(ctx, inertPreparationInput(fence)); err != nil {
					t.Fatalf("uncommitted transaction kept writer lock: %v", err)
				}
			} else {
				if len(records) != 1 || records[0].Phase != InertRestorePrepared ||
					records[0].RestoreReady || records[0].RestoreSupported ||
					!records[0].RequiresRevalidation {
					t.Fatalf("crash lost or promoted a durable inert row: %+v", records)
				}
				if _, err := s.PrepareInertRestoreRecord(ctx, inertPreparationInput(fence));
					!errors.Is(err, ErrInertRestorePreparationBusy) {
					t.Fatalf("SIGKILL reopened a duplicate pending slot: %v", err)
				}
				if err := s.AbandonInertRestoreRecord(ctx,
					records[0].ID, records[0].CandidateScope,
					records[0].ArchiveSHA256); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
