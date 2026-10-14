//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func newAnonymousProbeScratch(t *testing.T, f *fixture) string {
	t.Helper()
	path := filepath.Join(f.stateRoot, "anonymous-probe")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func requireEmptyAnonymousProbeScratch(t *testing.T, path string) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 0 {
		t.Fatalf("anonymous resource probe left named plaintext: %+v %v", entries, err)
	}
}

func TestAnonymousRestoreProbeStreamsRuleWithoutPlaintextFiles(t *testing.T) {
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	scratch := newAnonymousProbeScratch(t, f)
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		probe, err := lease.ProbeAnonymousResources(ctx, scratch, key)
		if err != nil || !probe.AnonymousFilesChecked ||
			probe.RuleSetCount != 1 || probe.RuleSetBytes != int64(len(f.ruleData)) ||
			probe.CoreIncluded || probe.CoreBytes != 0 ||
			probe.ArchiveSHA256 != record.ArchiveSHA256 ||
			probe.InventorySHA256 != record.InventorySHA256 ||
			probe.RestoreReady || probe.RestoreSupported {
			t.Fatalf("anonymous probe gained authority or lost resources: %+v %v", probe, err)
		}
		requireEmptyAnonymousProbeScratch(t, scratch)
	}
	rows, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(rows) != 1 ||
		rows[0].Phase != storage.InertRestorePrepared || rows[0].ID != record.ID {
		t.Fatalf("probe changed durable recovery journal: %+v %v", rows, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("probe changed live state: %+v -> %+v %v", before, after, err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if probe, err := lease.ProbeAnonymousResources(ctx, scratch, key); !errors.Is(err, ErrInertRestoreAnonymousProbe) ||
		!reflect.DeepEqual(probe, InertRestoreAnonymousProbe{}) {
		t.Fatalf("released resource lease still allowed staging: %+v %v", probe, err)
	}
	if _, err := os.Lstat(filepath.Join(directory, inertRestoreCipherName)); err != nil {
		t.Fatalf("probe removed durable ciphertext: %v", err)
	}
}

func TestAnonymousRestoreProbeRejectsWrongKeyScratchAndCancellation(t *testing.T) {
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	scratch := newAnonymousProbeScratch(t, f)
	lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	wrong := key
	wrong[0] ^= 0xa5
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		parent string
		key    [32]byte
	}{
		{"wrong_key", ctx, scratch, wrong},
		{"zero_key", ctx, scratch, [32]byte{}},
		{"canceled", cancelled, scratch, key},
		{"candidate_scope", ctx, directory, key},
		{"candidate_parent", ctx, filepath.Dir(directory), key},
		{"relative", ctx, "relative", key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := lease.ProbeAnonymousResources(tc.ctx, tc.parent, tc.key)
			if err == nil || !reflect.DeepEqual(probe, InertRestoreAnonymousProbe{}) {
				t.Fatalf("invalid %s obtained probe: %+v %v", tc.name, probe, err)
			}
		})
	}
	if err := os.Chmod(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	if probe, err := lease.ProbeAnonymousResources(ctx, scratch, key); !errors.Is(err, ErrInertRestoreAnonymousProbe) ||
		!reflect.DeepEqual(probe, InertRestoreAnonymousProbe{}) {
		t.Fatalf("public scratch directory accepted: %+v %v", probe, err)
	}
	if err := os.Chmod(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.stateRoot, "anonymous-probe-link")
	if err := os.Symlink(scratch, link); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.ProbeAnonymousResources(ctx, link, key); !errors.Is(err, ErrInertRestoreAnonymousProbe) {
		t.Fatalf("scratch symlink was followed: %v", err)
	}
	// Do not let scratch files pollute the ciphertext-candidate namespace,
	// whose parent is intentionally restricted to known encrypted scopes.
	nested := filepath.Join(filepath.Dir(directory), "unsafe-scratch")
	if err := os.Mkdir(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.ProbeAnonymousResources(ctx, nested, key); !errors.Is(err, ErrInertRestoreAnonymousProbe) {
		t.Fatalf("scratch nested in encrypted candidate parent was accepted: %v", err)
	}
	if err := os.Remove(nested); err != nil {
		t.Fatal(err)
	}
	if _, err := lease.ProbeAnonymousResources(ctx, scratch, key); err != nil {
		t.Fatalf("invalid probe poisoned a valid lease: %v", err)
	}
	requireEmptyAnonymousProbeScratch(t, scratch)
}

func TestAnonymousRestoreProbeDetectsLiveJournalAndScratchDrift(t *testing.T) {
	for _, fault := range []string{"selection", "abandon", "replace_scratch"} {
		t.Run(fault, func(t *testing.T) {
			f, directory, record, key := makeJournalBoundLeaseFixture(t)
			ctx := context.Background()
			scratch := newAnonymousProbeScratch(t, f)
			lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
				filepath.Dir(directory), record.ID, key)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			probe, err := lease.probeAnonymousResources(ctx, scratch, key, func() error {
				switch fault {
				case "selection":
					_, err := f.store.SetCurrentSelectionIntent(ctx,
						[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`))
					return err
				case "abandon":
					return f.store.AbandonInertRestoreRecord(ctx,
						record.ID, record.CandidateScope, record.ArchiveSHA256)
				case "replace_scratch":
					if err := os.Rename(scratch, scratch+".old"); err != nil {
						return err
					}
					return os.Mkdir(scratch, 0o700)
				}
				return errors.New("invalid injected fault")
			})
			if !errors.Is(err, ErrInertRestoreAnonymousProbe) ||
				!reflect.DeepEqual(probe, InertRestoreAnonymousProbe{}) {
				t.Fatalf("%s retained staged plaintext or authority: %+v %v", fault, probe, err)
			}
			requireEmptyAnonymousProbeScratch(t, scratch)
			if fault == "replace_scratch" {
				requireEmptyAnonymousProbeScratch(t, scratch+".old")
			}
			snapshot, err := f.store.Snapshot(ctx)
			if err != nil || snapshot.ActiveAttemptID != nil {
				t.Fatalf("probe created an apply attempt: %+v %v", snapshot, err)
			}
		})
	}
}

func TestAnonymousResourceFileIsUnlinkedNonExecutableAndHashChecked(t *testing.T) {
	f := newFixture(t)
	scratch := newAnonymousProbeScratch(t, f)
	dir, _, err := openAnonymousScratchParent(scratch)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	payload := []byte("secret inert rule bytes - never a path")
	digest := shaHex(payload)
	if err := materializeOneAnonymousResource(context.Background(),
		bytes.NewReader(payload), dir, int64(len(payload)), digest); err != nil {
		t.Fatalf("anonymous file cannot be verified: %v", err)
	}
	requireEmptyAnonymousProbeScratch(t, scratch)
	for _, test := range []struct {
		name string
		data []byte
		size int64
		hash string
	}{
		{"hash", payload, int64(len(payload)), shaHex([]byte("other"))},
		{"truncated", payload[:4], int64(len(payload)), digest},
		{"zero_size", payload, 0, digest},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := materializeOneAnonymousResource(context.Background(),
				bytes.NewReader(test.data), dir, test.size, test.hash); !errors.Is(err, ErrInertRestoreAnonymousProbe) {
				t.Fatalf("invalid anonymous payload accepted: %v", err)
			}
			requireEmptyAnonymousProbeScratch(t, scratch)
		})
	}
}

func TestAnonymousProbeKeepsLeaseOpenThroughResourceStage(t *testing.T) {
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	scratch := newAnonymousProbeScratch(t, f)
	lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	probed := make(chan error, 1)
	go func() {
		_, err := lease.probeAnonymousResources(ctx, scratch, key, func() error {
			close(started)
			<-release
			return nil
		})
		probed <- err
	}()
	select {
	case <-started:
	case <-time.After(12 * time.Second):
		t.Fatal("probe never reached materialization boundary")
	}
	closed := make(chan error, 1)
	go func() { closed <- lease.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("lease released ciphertext flock before probe finished: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-probed:
		if err != nil {
			t.Fatalf("held probe failed: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("probe deadlocked on Close")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("Close did not release after probe")
	}
	requireEmptyAnonymousProbeScratch(t, scratch)
}
