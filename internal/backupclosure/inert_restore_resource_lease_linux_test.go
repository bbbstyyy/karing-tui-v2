//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func makeJournalBoundLeaseFixture(t *testing.T) (
	*fixture, string, storage.InertRestorePreparation, [32]byte,
) {
	t.Helper()
	f, candidate, key := createInertDryRunFixture(t)
	ctx := context.Background()
	dryRun, err := InspectInertRestoreDryRun(ctx, f.store, candidate, key)
	if err != nil {
		t.Fatal(err)
	}
	record, err := PrepareInertRestoreCandidateRecord(ctx, f.store, candidate, key, dryRun)
	if err != nil {
		t.Fatal(err)
	}
	directory := candidate.Directory()
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	return f, directory, record, key
}

func TestInertRestoreResourceLeaseReacquireAndSerialize(t *testing.T) {
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatalf("pending journal cannot reacquire ciphertext: %v", err)
	}
	if got := lease.Record(); got.ID != record.ID || got.RestoreReady ||
		got.RestoreSupported || !got.RequiresRevalidation || got.Baseline != record.Baseline {
		t.Fatalf("resource lease gained authority: %+v", got)
	}
	if err := lease.Revalidate(ctx, key); err != nil {
		t.Fatalf("held ciphertext and live CAS changed: %v", err)
	}
	if _, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key); !errors.Is(err, ErrInertRestoreCandidateBusy) {
		t.Fatalf("second opener stole active flock: %v", err)
	}
	if err := lease.Revalidate(ctx, [32]byte{}); !errors.Is(err, ErrInertRestoreResourceLeaseRefused) {
		t.Fatalf("zero key was accepted by held lease: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Revalidate(ctx, key); !errors.Is(err, ErrInertRestoreResourceLeaseRefused) {
		t.Fatalf("closed lease was reusable: %v", err)
	}
	if lease.Record().ID != 0 {
		t.Fatal("closed lease exposed a live-looking record")
	}
	if _, err := os.Lstat(directory); err != nil {
		t.Fatalf("Close removed encrypted candidate: %v", err)
	}
	again, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatalf("reacquisition after process release failed: %v", err)
	}
	if err := again.Revalidate(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AbandonInertRestoreRecord(ctx,
		record.ID, record.CandidateScope, record.ArchiveSHA256); err != nil {
		t.Fatal(err)
	}
	if err := again.Revalidate(ctx, key); !errors.Is(err, ErrInertRestoreResourceLeaseRefused) {
		t.Fatalf("abandoned journal remained leased: %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("lease changed live daemon state: %+v -> %+v %v", before, after, err)
	}
	cleanup, err := ReopenInertRestoreCandidate(ctx, directory, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cleanup.Discard(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestInertRestoreResourceLeaseRejectsSameByteInodeReplacement(t *testing.T) {
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	cipher := filepath.Join(directory, inertRestoreCipherName)
	contents, err := os.ReadFile(cipher)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(directory, "swap-temp")
	if err := os.WriteFile(replacement, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, cipher); err != nil {
		t.Fatal(err)
	}
	if actual, err := os.ReadFile(cipher); err != nil || !bytes.Equal(actual, contents) {
		t.Fatalf("fixture changed ciphertext, not just inode: %v", err)
	}
	if err := lease.Revalidate(ctx, key); !errors.Is(err, ErrInertRestoreResourceLeaseRefused) {
		t.Fatalf("same-byte inode substitution passed lease revalidation: %v", err)
	}
	// The SQLite row and ciphertext must remain untouched on a refused
	// lease; neither replacement nor tamper automatically prunes resources.
	records, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(records) != 1 ||
		records[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("failed revalidation silently changed journal: %+v %v", records, err)
	}
}

func TestInertRestoreResourceLeaseDetectsLiveAndJournalChanges(t *testing.T) {
	for _, kind := range []string{"selection", "journal_digest", "unknown_sibling", "wrong_key"} {
		t.Run(kind, func(t *testing.T) {
			f, directory, record, key := makeJournalBoundLeaseFixture(t)
			ctx := context.Background()
			lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
				filepath.Dir(directory), record.ID, key)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			switch kind {
			case "selection":
				if _, err := f.store.SetCurrentSelectionIntent(ctx,
					[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"moved"}`)); err != nil {
					t.Fatal(err)
				}
			case "journal_digest":
				if err := f.store.AbandonInertRestoreRecord(ctx,
					record.ID, record.CandidateScope, record.ArchiveSHA256); err != nil {
					t.Fatal(err)
				}
			case "unknown_sibling":
				if err := os.WriteFile(filepath.Join(directory, "unknown"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "wrong_key":
				another := key
				another[0] ^= 0x55
				if err := lease.Revalidate(ctx, another); !errors.Is(err, ErrInertRestoreResourceLeaseRefused) {
					t.Fatalf("wrong key passed revalidation: %v", err)
				}
				// No permanent poisoning: the right key still works.
				if err := lease.Revalidate(ctx, key); err != nil {
					t.Fatalf("wrong key destroyed a valid lease: %v", err)
				}
				return
			}
			if err := lease.Revalidate(ctx, key); !errors.Is(err, ErrInertRestoreResourceLeaseRefused) {
				t.Fatalf("%s was accepted by resource lease: %v", kind, err)
			}
		})
	}
}

func TestInertResourceLeaseProcessHelper(t *testing.T) {
	if os.Getenv("KTUI_INERT_RESOURCE_LEASE_HELPER") != "yes" {
		return
	}
	ctx := context.Background()
	path := os.Getenv("KTUI_INERT_RESOURCE_LEASE_DB")
	s, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := strconv.ParseInt(os.Getenv("KTUI_INERT_RESOURCE_LEASE_ID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	buf, err := hex.DecodeString(os.Getenv("KTUI_INERT_RESOURCE_LEASE_KEY"))
	if err != nil || len(buf) != 32 {
		t.Fatal("invalid helper key")
	}
	var key [32]byte
	copy(key[:], buf)
	lease, err := AcquireInertRestoreResourceLease(ctx, s,
		os.Getenv("KTUI_INERT_RESOURCE_LEASE_PARENT"), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	if _, err := os.Stdout.Write([]byte("held\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Minute)
}

func TestInertRestoreResourceLeaseSIGKILLReacquisition(t *testing.T) {
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	childCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0],
		"-test.run=^TestInertResourceLeaseProcessHelper$")
	cmd.Env = append(os.Environ(),
		"KTUI_INERT_RESOURCE_LEASE_HELPER=yes",
		"KTUI_INERT_RESOURCE_LEASE_DB="+f.store.Path(),
		"KTUI_INERT_RESOURCE_LEASE_PARENT="+filepath.Dir(directory),
		"KTUI_INERT_RESOURCE_LEASE_ID="+strconv.FormatInt(record.ID, 10),
		"KTUI_INERT_RESOURCE_LEASE_KEY="+hex.EncodeToString(key[:]))
	reader, err := cmd.StdoutPipe()
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
	msg := make([]byte, 5)
	if _, err := io.ReadFull(reader, msg); err != nil || string(msg) != "held\n" {
		t.Fatalf("child never acquired journal-bound resource lease: %q %v", msg, err)
	}
	if _, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key); !errors.Is(err, ErrInertRestoreCandidateBusy) {
		t.Fatalf("process-held lease stolen: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	reaped = true
	newLease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatalf("fresh verification after crash failed: %v", err)
	}
	if err := newLease.Revalidate(ctx, key); err != nil {
		t.Fatalf("reopened lease not authentically bound to journal: %v", err)
	}
	if err := newLease.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) ||
		after.ActiveAttemptID != nil || after.RecoveryRequired {
		t.Fatalf("lease crash changed current/LKG state: %+v -> %+v %v", before, after, err)
	}
}
