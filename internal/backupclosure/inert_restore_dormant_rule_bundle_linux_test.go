//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func makeDormantRuleBundleFixture(t *testing.T) (
	*fixture, *InertRestoreResourceLease, *InertPinnedRestoreResources,
	storage.InertRestorePreparation, [32]byte, string,
) {
	t.Helper()
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	scratch := newAnonymousProbeScratch(t, f)
	pins, err := lease.PinAnonymousRestoreResources(ctx, scratch, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pins.Close() })
	parent := filepath.Join(f.stateRoot, "inert-private-rule-stage")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return f, lease, pins, record, key, parent
}

func dormantStageEntries(t *testing.T, parent string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func TestDormantRuleStagePublishesOnlyRulesAtomicallyAndNeverActivates(t *testing.T) {
	f, lease, pins, record, key, parent := makeDormantRuleBundleFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	stage, err := pins.StageDormantRuleBundle(ctx, parent, key)
	if err != nil {
		t.Fatal(err)
	}
	if !stage.Inactive || stage.RestoreSupported || stage.RestoreReady ||
		stage.RuleCount != 1 || stage.RuleBytes != int64(len(f.ruleData)) ||
		stage.ArchiveSHA256 != record.ArchiveSHA256 ||
		stage.InventorySHA256 != record.InventorySHA256 ||
		!validLowerSHA(stage.ScopeSHA256) {
		t.Fatalf("inert publication granted activation authority: %+v", stage)
	}
	entries := dormantStageEntries(t, parent)
	if len(entries) != 1 ||
		entries[0].Name() != dormantRuleBundlePrefix+record.ArchiveSHA256 {
		t.Fatalf("atomic stage left incomplete/unknown roots: %+v", entries)
	}
	dir := filepath.Join(parent, entries[0].Name())
	dirStat, err := os.Stat(dir)
	if err != nil || !privatePortableDirectory(dirStat) {
		t.Fatalf("published bundle directory not private: %+v %v", dirStat, err)
	}
	leaves := dormantStageEntries(t, dir)
	if len(leaves) != 1 || leaves[0].Name() != f.ruleHash+".json" {
		t.Fatalf("stage leaked unapproved core or other resources: %+v", leaves)
	}
	staged := filepath.Join(dir, leaves[0].Name())
	info, err := os.Stat(staged)
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0o400 || info.Size() != int64(len(f.ruleData)) {
		t.Fatalf("staged rule not private and readonly: %+v %v", info, err)
	}
	found, err := os.ReadFile(staged)
	if err != nil || !bytes.Equal(found, f.ruleData) {
		t.Fatalf("published inactive rule had incorrect authenticated bytes: %v", err)
	}
	if err := pins.Revalidate(ctx, key); err != nil {
		t.Fatalf("publisher linked/mutated original anonymous FD: %v", err)
	}
	if duplicate, err := pins.StageDormantRuleBundle(ctx, parent, key); !errors.Is(err, ErrDormantRuleBundle) ||
		!reflect.DeepEqual(duplicate, DormantRuleBundleReceipt{}) {
		t.Fatalf("a second stage silently overwrote durable bundle: %+v %v", duplicate, err)
	}
	if err := pins.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if afterStage, err := os.ReadFile(staged); err != nil || !bytes.Equal(found, afterStage) {
		t.Fatalf("inert staged rule did not survive lease closure: %v", err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("staging altered live daemon state: %+v -> %+v %v", before, after, err)
	}
	rows, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(rows) != 1 ||
		rows[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("staging changed durable journal: %+v %v", rows, err)
	}
	if _, err := os.Lstat(filepath.Join(f.stateRoot, "core", "rule-sets", "sha256",
		f.ruleHash+".json")); err != nil {
		t.Fatalf("existing live rule was disrupted: %v", err)
	}
}

func TestDormantRuleStageInjectionCleansOnlyOwnedTemporaryDirectory(t *testing.T) {
	_, _, pins, record, key, parent := makeDormantRuleBundleFixture(t)
	ctx := context.Background()
	report, err := pins.stageDormantRuleBundle(ctx, parent, key,
		func() error { return errors.New("fault just before directory publish") })
	if !errors.Is(err, ErrDormantRuleBundle) ||
		!reflect.DeepEqual(report, DormantRuleBundleReceipt{}) {
		t.Fatalf("failed stage returned usable report: %+v %v", report, err)
	}
	if entries := dormantStageEntries(t, parent); len(entries) != 0 {
		t.Fatalf("fault left named plaintext in private staging root: %+v", entries)
	}
	report, err = pins.StageDormantRuleBundle(ctx, parent, key)
	if err != nil || report.ArchiveSHA256 != record.ArchiveSHA256 {
		t.Fatalf("retry after fault could not safely publish: %+v %v", report, err)
	}
}

func TestDormantRuleStageRejectsUnrecognizedOrUnfinishedScopes(t *testing.T) {
	for _, state := range []string{"unknown", "pending", "bad_mode", "symlink", "missing_root"} {
		t.Run(state, func(t *testing.T) {
			_, _, pins, _, key, parent := makeDormantRuleBundleFixture(t)
			switch state {
			case "unknown":
				if err := os.WriteFile(filepath.Join(parent, "untrusted"), []byte("x"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.Mkdir(filepath.Join(parent, dormantRulePendingPrefix+"orphan"), 0o700); err != nil {
					t.Fatal(err)
				}
			case "bad_mode":
				if err := os.Chmod(parent, 0o755); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(parent, parent+".real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent+".real", parent); err != nil {
					t.Fatal(err)
				}
			case "missing_root":
				if err := os.Remove(parent); err != nil {
					t.Fatal(err)
				}
			}
			report, err := pins.StageDormantRuleBundle(context.Background(), parent, key)
			if !errors.Is(err, ErrDormantRuleBundle) ||
				!reflect.DeepEqual(report, DormantRuleBundleReceipt{}) {
				t.Fatalf("unsafe stage parent was accepted: %+v %v", report, err)
			}
		})
	}
}

func TestDormantRuleStageRejectsWrongKeyAndSourceDriftBeforePublish(t *testing.T) {
	for _, fault := range []string{"wrong_key", "cancelled", "selection", "abandon", "mutate_pin"} {
		t.Run(fault, func(t *testing.T) {
			f, _, pins, record, key, parent := makeDormantRuleBundleFixture(t)
			ctx := context.Background()
			report := DormantRuleBundleReceipt{}
			var err error
			switch fault {
			case "wrong_key":
				bad := key
				bad[0] ^= 0x88
				report, err = pins.StageDormantRuleBundle(ctx, parent, bad)
			case "cancelled":
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				report, err = pins.StageDormantRuleBundle(cancelled, parent, key)
			default:
				report, err = pins.stageDormantRuleBundle(ctx, parent, key, func() error {
					switch fault {
					case "selection":
						_, err := f.store.SetCurrentSelectionIntent(ctx,
							[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`))
						return err
					case "abandon":
						return f.store.AbandonInertRestoreRecord(ctx,
							record.ID, record.CandidateScope, record.ArchiveSHA256)
					case "mutate_pin":
						return pins.rules[0].file.Chmod(0o700)
					}
					return nil
				})
			}
			if err == nil || !reflect.DeepEqual(report, DormantRuleBundleReceipt{}) {
				t.Fatalf("unsafe %s published an inactive bundle: %+v %v", fault, report, err)
			}
			if entries := dormantStageEntries(t, parent); len(entries) != 0 {
				t.Fatalf("failed %s stage left plaintext bundle: %+v", fault, entries)
			}
		})
	}
}

func TestDormantRuleStageSerializesPinCloseAndParentClose(t *testing.T) {
	_, lease, pins, _, key, parent := makeDormantRuleBundleFixture(t)
	ctx := context.Background()
	entered := make(chan struct{})
	release := make(chan struct{})
	outcome := make(chan error, 1)
	go func() {
		_, err := pins.stageDormantRuleBundle(ctx, parent, key,
			func() error {
				close(entered)
				<-release
				return nil
			})
		outcome <- err
	}()
	select {
	case <-entered:
	case <-time.After(12 * time.Second):
		t.Fatal("stage never reached precommit boundary")
	}
	pinClosed := make(chan error, 1)
	parentClosed := make(chan error, 1)
	go func() { pinClosed <- pins.Close() }()
	go func() { parentClosed <- lease.Close() }()
	select {
	case err := <-pinClosed:
		t.Fatalf("pins closed before atomic directory rename: %v", err)
	case err := <-parentClosed:
		t.Fatalf("ciphertext lease closed before atomic directory rename: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-outcome:
		if err != nil {
			t.Fatalf("published stage failed under competing closes: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("stage stalled forever")
	}
	for _, completed := range []<-chan error{pinClosed, parentClosed} {
		select {
		case err := <-completed:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(12 * time.Second):
			t.Fatal("Close deadlocked after stage")
		}
	}
	entries := dormantStageEntries(t, parent)
	if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), dormantRuleBundlePrefix) {
		t.Fatalf("concurrent close interrupted final atomic publication: %+v", entries)
	}
}

func TestDormantRuleStageFailsClosedOnLateStagedFileDrift(t *testing.T) {
	for _, fault := range []string{"extra", "modified", "same_inode_swap", "directory_swap"} {
		t.Run(fault, func(t *testing.T) {
			f, _, pins, _, key, parent := makeDormantRuleBundleFixture(t)
			report, err := pins.stageDormantRuleBundle(context.Background(), parent, key,
				func() error {
					entries, err := os.ReadDir(parent)
					if err != nil || len(entries) != 1 {
						return errors.New("stage is not private and singular")
					}
					temporary := filepath.Join(parent, entries[0].Name())
					path := filepath.Join(temporary, f.ruleHash+".json")
					switch fault {
					case "extra":
						return os.WriteFile(filepath.Join(temporary, "unexpected"), []byte("x"), 0o600)
					case "modified":
						if err := os.Chmod(path, 0o600); err != nil {
							return err
						}
						if err := os.WriteFile(path, bytes.Repeat([]byte("z"), len(f.ruleData)), 0o600); err != nil {
							return err
						}
						return os.Chmod(path, 0o400)
					case "same_inode_swap":
						other := filepath.Join(temporary, "replacement")
						if err := os.WriteFile(other, f.ruleData, 0o400); err != nil {
							return err
						}
						return os.Rename(other, path)
					case "directory_swap":
						if err := os.Rename(temporary, temporary+".old"); err != nil {
							return err
						}
						return os.Mkdir(temporary, 0o700)
					}
					return errors.New("unknown fault")
				})
			if !errors.Is(err, ErrDormantRuleBundle) ||
				!reflect.DeepEqual(report, DormantRuleBundleReceipt{}) {
				t.Fatalf("%s published changed rules after audit: %+v %v", fault, report, err)
			}
			for _, entry := range dormantStageEntries(t, parent) {
				if strings.HasPrefix(entry.Name(), dormantRuleBundlePrefix) {
					t.Fatalf("%s published invalid final scope: %s", fault, entry.Name())
				}
			}
			// An ambiguous orphan is safer than recursive deletion of
			// content an independent actor added/replaced mid-publication.
			if fault == "extra" || fault == "same_inode_swap" || fault == "directory_swap" {
				if len(dormantStageEntries(t, parent)) == 0 {
					t.Fatal("ambiguous tampered pending scope was silently erased")
				}
			}
		})
	}
}
