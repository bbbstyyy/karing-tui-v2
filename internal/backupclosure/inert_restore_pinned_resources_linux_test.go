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

func TestPinnedAnonymousRestoreResourcesRetainUnlinkedFilesWithoutAuthority(t *testing.T) {
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
	defer lease.Close()
	pins, err := lease.PinAnonymousRestoreResources(ctx, scratch, key)
	if err != nil {
		t.Fatal(err)
	}
	evidence := pins.Evidence()
	if evidence.ArchiveSHA256 != record.ArchiveSHA256 ||
		evidence.InventorySHA256 != record.InventorySHA256 ||
		evidence.RuleSetCount != 1 ||
		evidence.RuleSetBytes != int64(len(f.ruleData)) ||
		evidence.CoreIncluded || evidence.CoreBytes != 0 ||
		evidence.DescriptorCount != 1 ||
		evidence.RestoreReady || evidence.RestoreSupported {
		t.Fatalf("pinned anonymous lease gained activation authority: %+v", evidence)
	}
	if len(pins.rules) != 1 || pins.rules[0].file == nil ||
		pins.rules[0].identity == nil ||
		!validAnonymousResourceFile(pins.rules[0].identity,
			int64(len(f.ruleData)), 0o400) {
		t.Fatal("pin did not retain an unnamed readonly rule descriptor")
	}
	requireEmptyAnonymousProbeScratch(t, scratch)
	for i := 0; i < 2; i++ {
		if err := pins.Revalidate(ctx, key); err != nil {
			t.Fatalf("pinned resource cannot be revalidated: %v", err)
		}
	}
	fd := pins.rules[0].file
	if err := pins.Close(); err != nil {
		t.Fatal(err)
	}
	if err := pins.Close(); err != nil {
		t.Fatal("duplicate Close must be idempotent")
	}
	if !reflect.DeepEqual(pins.Evidence(), InertPinnedResourceEvidence{}) {
		t.Fatal("closed anonymous resource lease retained evidence")
	}
	if _, err := fd.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("Close left a resource descriptor usable: %v", err)
	}
	if err := pins.Revalidate(ctx, key); !errors.Is(err, ErrInertPinnedRestoreResources) {
		t.Fatalf("closed pinned lease revalidated: %v", err)
	}
	requireEmptyAnonymousProbeScratch(t, scratch)
	if _, err := os.Lstat(filepath.Join(directory, inertRestoreCipherName)); err != nil {
		t.Fatal("pin closing removed durable ciphertext")
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("pin operation changed current state: %+v -> %+v %v", before, after, err)
	}
	rows, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(rows) != 1 ||
		rows[0].Phase != storage.InertRestorePrepared || rows[0].ID != record.ID {
		t.Fatalf("pinned rule materialization wrote recovery journal: %+v %v", rows, err)
	}
}

func TestPinnedAnonymousRestoreResourcePartialFailureCleansEveryFD(t *testing.T) {
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	scratch := newAnonymousProbeScratch(t, f)
	lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	pins, err := lease.pinAnonymousRestoreResources(ctx, scratch, key,
		func() error { return errors.New("injected phase crash") })
	if !errors.Is(err, ErrInertPinnedRestoreResources) || pins != nil {
		t.Fatalf("partial resource stage returned usable pins: %+v %v", pins, err)
	}
	requireEmptyAnonymousProbeScratch(t, scratch)
	pins, err = lease.PinAnonymousRestoreResources(ctx, scratch, key)
	if err != nil {
		t.Fatalf("rejected stage poisoned original lease: %v", err)
	}
	if err := pins.Close(); err != nil {
		t.Fatal(err)
	}
	requireEmptyAnonymousProbeScratch(t, scratch)
}

func TestPinnedAnonymousRestoreResourcesRejectWrongKeysAndUnsafeScratch(t *testing.T) {
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
	wrong[0] ^= 0x2a
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	for _, tc := range []struct {
		name string
		ctx context.Context
		root string
		key [32]byte
	}{
		{"wrong_key", ctx, scratch, wrong},
		{"zero_key", ctx, scratch, [32]byte{}},
		{"cancelled", cancelled, scratch, key},
		{"relative", ctx, "relative", key},
		{"candidate_parent", ctx, filepath.Dir(directory), key},
		{"candidate_scope", ctx, directory, key},
		{"missing", ctx, scratch+"-absent", key},
		{"noncanonical", ctx, scratch+"/../bad", key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pins, err := lease.PinAnonymousRestoreResources(tc.ctx, tc.root, tc.key)
			if err == nil || pins != nil {
				t.Fatalf("%s obtained anonymous pinned resources: %+v %v", tc.name, pins, err)
			}
		})
	}
	if err := os.Chmod(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	if pins, err := lease.PinAnonymousRestoreResources(ctx, scratch, key);
		pins != nil || !errors.Is(err, ErrInertPinnedRestoreResources) {
		t.Fatalf("public scratch accepted: %v %v", pins, err)
	}
	if err := os.Chmod(scratch, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(f.stateRoot, "pinned-scratch-link")
	if err := os.Symlink(scratch, link); err != nil {
		t.Fatal(err)
	}
	if pins, err := lease.PinAnonymousRestoreResources(ctx, link, key);
		pins != nil || !errors.Is(err, ErrInertPinnedRestoreResources) {
		t.Fatalf("scratch symlink followed: %v %v", pins, err)
	}
	requireEmptyAnonymousProbeScratch(t, scratch)
}

func TestPinnedAnonymousRestoreResourcesDetectFdAndNamespaceDrift(t *testing.T) {
	for _, kind := range []string{"corrupt", "executable", "scratch_swap", "selection", "abandon", "parent_close"} {
		t.Run(kind, func(t *testing.T) {
			f, directory, record, key := makeJournalBoundLeaseFixture(t)
			ctx := context.Background()
			scratch := newAnonymousProbeScratch(t, f)
			lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
				filepath.Dir(directory), record.ID, key)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			pins, err := lease.PinAnonymousRestoreResources(ctx, scratch, key)
			if err != nil {
				t.Fatal(err)
			}
			defer pins.Close()
			switch kind {
			case "corrupt":
				if _, err := pins.rules[0].file.WriteAt(bytes.Repeat([]byte("z"), len(f.ruleData)), 0); err != nil {
					t.Fatal(err)
				}
			case "executable":
				if err := pins.rules[0].file.Chmod(0o700); err != nil {
					t.Fatal(err)
				}
			case "scratch_swap":
				if err := os.Rename(scratch, scratch+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(scratch, 0o700); err != nil {
					t.Fatal(err)
				}
			case "selection":
				if _, err := f.store.SetCurrentSelectionIntent(ctx,
					[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`)); err != nil {
					t.Fatal(err)
				}
			case "abandon":
				if err := f.store.AbandonInertRestoreRecord(ctx,
					record.ID, record.CandidateScope, record.ArchiveSHA256); err != nil {
					t.Fatal(err)
				}
			case "parent_close":
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := pins.Revalidate(ctx, key); !errors.Is(err, ErrInertPinnedRestoreResources) {
				t.Fatalf("%s drift retained a valid in-process resource lease: %v", kind, err)
			}
			requireEmptyAnonymousProbeScratch(t, scratch)
			if kind == "scratch_swap" {
				requireEmptyAnonymousProbeScratch(t, scratch+".old")
			}
			snap, err := f.store.Snapshot(ctx)
			if err != nil || snap.ActiveAttemptID != nil {
				t.Fatalf("anonymous pinned resource changed apply journal: %+v %v", snap, err)
			}
		})
	}
}

func TestPinnedAnonymousRestoreResourceStageSerializesParentClose(t *testing.T) {
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	scratch := newAnonymousProbeScratch(t, f)
	lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	stage := make(chan struct{})
	release := make(chan struct{})
	outcome := make(chan error, 1)
	go func() {
		pins, err := lease.pinAnonymousRestoreResources(ctx, scratch, key, func() error {
			close(stage)
			<-release
			return nil
		})
		if pins != nil {
			err = errors.Join(err, pins.Close())
		}
		outcome <- err
	}()
	select {
	case <-stage:
	case <-time.After(12*time.Second):
		t.Fatal("pin stage did not reach all-resource verification boundary")
	}
	closed := make(chan error, 1)
	go func() { closed <- lease.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("parent ciphertext flock released during pin stage: %v", err)
	case <-time.After(50*time.Millisecond):
	}
	close(release)
	select {
	case err := <-outcome:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12*time.Second):
		t.Fatal("pin stage deadlocked")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12*time.Second):
		t.Fatal("parent Close deadlocked")
	}
	requireEmptyAnonymousProbeScratch(t, scratch)
}

func TestPinnedAnonymousResourceReaderRejectsHashAndTruncation(t *testing.T) {
	f := newFixture(t)
	scratch := newAnonymousProbeScratch(t, f)
	dir, _, err := openAnonymousScratchParent(scratch)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	payload := []byte("an inert rule resource with no path")
	digest := shaHex(payload)
	item, err := openPinnedAnonymousResource(context.Background(), bytes.NewReader(payload),
		dir, int64(len(payload)), digest)
	if err != nil {
		t.Fatal(err)
	}
	if verifyPinnedAnonymousResource(context.Background(), &item) != nil {
		t.Fatal("freshly staged anonymous resource lost digest")
	}
	if err := item.file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{
		name string
		bytes []byte
		n int64
		digest string
	}{
		{"hash", payload, int64(len(payload)), shaHex([]byte("not the resource"))},
		{"short", payload[:2], int64(len(payload)), digest},
		{"empty", payload, 0, digest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item, err := openPinnedAnonymousResource(context.Background(),
				bytes.NewReader(tc.bytes), dir, tc.n, tc.digest)
			if item.file != nil || !errors.Is(err, ErrInertPinnedRestoreResources) {
				t.Fatalf("bad file materialization succeeded: %+v %v", item, err)
			}
			requireEmptyAnonymousProbeScratch(t, scratch)
		})
	}
}
