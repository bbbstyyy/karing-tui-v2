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

func TestInertWriteCASProcessCrashHelper(t *testing.T) {
	if os.Getenv("KTUI_INERT_WRITE_CAS_HELPER") != "yes" {
		return
	}
	ctx := context.Background()
	s, err := Open(ctx, os.Getenv("KTUI_INERT_WRITE_CAS_DATABASE"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	fence, err := s.ReadInertRestoreFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Parent SIGKILL occurs while the child owns the SQLite writer
	// reservation. Nothing has been committed to any live table.
	err = s.checkInertRestoreWriteCAS(ctx, fence, func() error {
		if _, writeErr := os.Stdout.Write([]byte("locked\n")); writeErr != nil {
			return writeErr
		}
		time.Sleep(3 * time.Minute)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestInertWriteCASCrashDropsUncommittedWriterTransaction(t *testing.T) {
	s, fence := newCommittedInertFenceFixture(t)
	ctx := context.Background()
	before, err := s.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	childCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0],
		"-test.run=^TestInertWriteCASProcessCrashHelper$")
	cmd.Env = append(os.Environ(),
		"KTUI_INERT_WRITE_CAS_HELPER=yes",
		"KTUI_INERT_WRITE_CAS_DATABASE="+s.Path())
	pipe, err := cmd.StdoutPipe()
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
	signal := make([]byte, len("locked\n"))
	if _, err := io.ReadFull(pipe, signal); err != nil || string(signal) != "locked\n" {
		t.Fatalf("child failed to acquire SQLite writer lease: %q: %v", signal, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	reaped = true
	if err := s.quickCheck(ctx); err != nil {
		t.Fatalf("child death corrupted SQLite state: %v", err)
	}
	after, err := s.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) || after.ActiveAttemptID != nil {
		t.Fatalf("SIGKILL persisted a write-probe mutation: before=%+v after=%+v err=%v", before, after, err)
	}
	if err := s.CheckInertRestoreWriteCAS(ctx, fence); err != nil {
		t.Fatalf("child death leaked SQLite write lock: %v", err)
	}
	_, err = s.SetCurrentSelectionIntent(ctx,
		[]byte(`{"kind":"specific_node","profile_id":"stable","node_id":"post-crash"}`))
	if err != nil {
		t.Fatalf("actual writer could not proceed after child death: %v", err)
	}
	if err := s.CheckInertRestoreWriteCAS(ctx, fence); !errors.Is(err, ErrInertRestoreFenceChanged) {
		t.Fatalf("post-crash config drift not fenced: %v", err)
	}
}
