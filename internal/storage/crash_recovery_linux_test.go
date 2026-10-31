//go:build linux

package storage

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStoreRecoversInterruptedJournalAfterAbruptProcessDeath(t *testing.T) {
	const helperEnv = "KARING_TUI_STORAGE_CRASH_HELPER"
	if os.Getenv(helperEnv) == "1" {
		runStorageCrashHelper(t)
		return
	}

	cases := []struct {
		name           string
		phase          string
		needsReconcile bool
	}{
		{name: "prepared", phase: "prepared", needsReconcile: false},
		{name: "activating", phase: "activating", needsReconcile: true},
		{name: "verifying", phase: "verifying", needsReconcile: true},
		{name: "rolling-back", phase: "rolling_back", needsReconcile: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "state.db")
			store, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}

			baseline, err := store.PrepareApply(ctx, 0, []byte("{\"baseline\":true}"))
			if err != nil {
				t.Fatal(err)
			}
			if err := store.BeginActivation(ctx, baseline.ID); err != nil {
				t.Fatal(err)
			}
			if err := store.BeginVerification(ctx, baseline.ID); err != nil {
				t.Fatal(err)
			}
			if err := store.CommitApplied(ctx, baseline.ID, true); err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			attemptID := launchAndKillStorageHelper(t, path, tc.phase)

			reopened, err := Open(ctx, path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()

			recovery, err := reopened.RecoverInterrupted(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if recovery.NeedsReconcile != tc.needsReconcile {
				t.Fatalf("NeedsReconcile = %t, want %t", recovery.NeedsReconcile, tc.needsReconcile)
			}
			if len(recovery.InterruptedAttemptIDs) != 1 || recovery.InterruptedAttemptIDs[0] != attemptID {
				t.Fatalf("interrupted attempts = %#v, want [%d]", recovery.InterruptedAttemptIDs, attemptID)
			}

			snapshot, err := reopened.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.RecoveryRequired != tc.needsReconcile {
				t.Fatalf("recovery flag = %t, want %t", snapshot.RecoveryRequired, tc.needsReconcile)
			}
			if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != baseline.GenerationID {
				t.Fatalf("confirmed generation changed across abrupt death: %+v", snapshot)
			}

			attempt, err := reopened.Attempt(ctx, attemptID)
			if err != nil {
				t.Fatal(err)
			}
			if attempt.Phase != PhaseInterrupted {
				t.Fatalf("interrupted phase = %q, want %q", attempt.Phase, PhaseInterrupted)
			}
		})
	}
}

func runStorageCrashHelper(t *testing.T) {
	t.Helper()
	path := os.Getenv("KARING_TUI_STORAGE_CRASH_PATH")
	phase := os.Getenv("KARING_TUI_STORAGE_CRASH_PHASE")
	if path == "" || phase == "" {
		t.Fatal("storage crash helper is missing path or phase")
	}

	ctx := context.Background()
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := store.PrepareApply(ctx, 1, []byte("{\"candidate\":true}"))
	if err != nil {
		t.Fatal(err)
	}
	switch phase {
	case "prepared":
	case "activating":
		if err := store.BeginActivation(ctx, attempt.ID); err != nil {
			t.Fatal(err)
		}
	case "verifying":
		if err := store.BeginActivation(ctx, attempt.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.BeginVerification(ctx, attempt.ID); err != nil {
			t.Fatal(err)
		}
	case "rolling_back":
		if err := store.BeginActivation(ctx, attempt.ID); err != nil {
			t.Fatal(err)
		}
		if err := store.BeginRollback(ctx, attempt.ID, "forced crash fixture"); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unsupported crash phase %q", phase)
	}

	fmt.Printf("READY %d\n", attempt.ID)
	for {
		time.Sleep(time.Hour)
	}
}

func launchAndKillStorageHelper(t *testing.T, path, phase string) int64 {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestStoreRecoversInterruptedJournalAfterAbruptProcessDeath$")
	cmd.Env = append(
		os.Environ(),
		"KARING_TUI_STORAGE_CRASH_HELPER=1",
		"KARING_TUI_STORAGE_CRASH_PATH="+path,
		"KARING_TUI_STORAGE_CRASH_PHASE="+phase,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(stdout)
	var attemptID int64
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || fields[0] != "READY" {
			continue
		}
		attemptID, err = strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			t.Fatalf("parse helper attempt id %q: %v", fields[1], err)
		}
		break
	}
	if attemptID <= 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("storage crash helper did not become ready: scan=%v stderr=%s", scanner.Err(), stderr.String())
	}

	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	return attemptID
}
