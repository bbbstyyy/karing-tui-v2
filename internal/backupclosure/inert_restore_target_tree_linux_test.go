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

func makePrivatePortableTargetTree(t *testing.T, f *fixture) (root, rules string) {
	t.Helper()
	root = filepath.Join(f.stateRoot, "portable-target-state")
	for _, directory := range []string{
		root, filepath.Join(root, "core"),
		filepath.Join(root, "core", "rule-sets"),
		filepath.Join(root, "core", "rule-sets", "sha256"),
	} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return root, filepath.Join(root, "core", "rule-sets", "sha256")
}

func makeTargetRuleLease(t *testing.T) (
	*fixture, *InertRestoreResourceLease, storage.InertRestorePreparation, [32]byte,
) {
	t.Helper()
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	lease, err := AcquireInertRestoreResourceLease(context.Background(), f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	return f, lease, record, key
}

func TestPortableTargetTreeMissingAndExistingRuleAreOnlyInspected(t *testing.T) {
	f, lease, record, key := makeTargetRuleLease(t)
	ctx := context.Background()
	root, ruleDir := makePrivatePortableTargetTree(t, f)
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	report, err := lease.InspectPortableTargetRuleTree(ctx, root, key)
	if err != nil || !report.DirectoriesPinned ||
		report.ArchiveSHA256 != record.ArchiveSHA256 ||
		report.InventorySHA256 != record.InventorySHA256 ||
		report.RuleSetCount != 1 || report.ExistingRuleSets != 0 ||
		report.MissingRuleSets != 1 || report.ExistingRuleSetBytes != 0 ||
		report.TargetRootSHA256 != shaHex([]byte(root)) ||
		report.RestoreReady || report.RestoreSupported {
		t.Fatalf("empty safe target falsely certified: %+v %v", report, err)
	}
	entry := filepath.Join(ruleDir, f.ruleHash+".json")
	if _, err := os.Lstat(entry); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("inspection silently installed missing rule: %v", err)
	}
	if err := os.WriteFile(entry, f.ruleData, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = lease.InspectPortableTargetRuleTree(ctx, root, key)
	if err != nil || report.ExistingRuleSets != 1 || report.MissingRuleSets != 0 ||
		report.ExistingRuleSetBytes != int64(len(f.ruleData)) ||
		!report.DirectoriesPinned || report.RestoreReady || report.RestoreSupported {
		t.Fatalf("valid existing immutable rule refused: %+v %v", report, err)
	}
	for _, dir := range []string{root, filepath.Join(root, "core"),
		filepath.Join(root, "core", "rule-sets"), ruleDir} {
		info, err := os.Lstat(dir)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
			t.Fatalf("read-only inspection modified target dir: %s %+v %v", dir, info, err)
		}
	}
	contents, err := os.ReadFile(entry)
	if err != nil || !bytes.Equal(contents, f.ruleData) {
		t.Fatalf("inspection overwrote existing rule: %v", err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("target inspection changed live state: %+v -> %+v %v", before, after, err)
	}
	rows, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(rows) != 1 || rows[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("inspection mutated inert journal: %+v %v", rows, err)
	}
}

func TestPortableTargetTreeRejectsUnsafeFileAndDirectory(t *testing.T) {
	for _, kind := range []string{
		"corrupt_same_size", "public", "executable", "hardlink",
		"symlink", "directory_instead", "core_directory_symlink",
		"world_readable_root", "public_rule_directory", "missing_rule_directory",
	} {
		t.Run(kind, func(t *testing.T) {
			f, lease, _, key := makeTargetRuleLease(t)
			root, rules := makePrivatePortableTargetTree(t, f)
			path := filepath.Join(rules, f.ruleHash+".json")
			switch kind {
			case "corrupt_same_size":
				if err := os.WriteFile(path, bytes.Repeat([]byte("z"), len(f.ruleData)), 0o600); err != nil {
					t.Fatal(err)
				}
			case "public", "executable":
				if err := os.WriteFile(path, f.ruleData, 0o600); err != nil {
					t.Fatal(err)
				}
				mode := os.FileMode(0o644)
				if kind == "executable" {
					mode = 0o700
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(f.rulePath, path); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(f.rulePath, path); err != nil {
					t.Fatal(err)
				}
			case "directory_instead":
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			case "core_directory_symlink":
				core := filepath.Join(root, "core")
				if err := os.Rename(core, core+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(core+".old", core); err != nil {
					t.Fatal(err)
				}
			case "world_readable_root":
				if err := os.Chmod(root, 0o755); err != nil {
					t.Fatal(err)
				}
			case "public_rule_directory":
				if err := os.Chmod(rules, 0o777); err != nil {
					t.Fatal(err)
				}
			case "missing_rule_directory":
				if err := os.Remove(rules); err != nil {
					t.Fatal(err)
				}
			}
			report, err := lease.InspectPortableTargetRuleTree(context.Background(), root, key)
			if !errors.Is(err, ErrInertPortableTargetTree) ||
				!reflect.DeepEqual(report, InertPortableTargetTreeReport{}) {
				t.Fatalf("unsafe %s certified: %+v %v", kind, report, err)
			}
		})
	}
}

func TestPortableTargetTreeRejectsInvalidPathKeyAndCancellation(t *testing.T) {
	f, lease, _, key := makeTargetRuleLease(t)
	root, _ := makePrivatePortableTargetTree(t, f)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	wrong := key
	wrong[0] ^= 0x11
	for _, tc := range []struct {
		name string
		ctx context.Context
		root string
		key [32]byte
	}{
		{"relative", context.Background(), "relative", key},
		{"noncanonical", context.Background(), root+"/../other", key},
		{"filesystem_root", context.Background(), "/", key},
		{"nul", context.Background(), root+"\x00", key},
		{"oversized", context.Background(), "/"+strings.Repeat("p", 1100), key},
		{"missing", context.Background(), root+"-missing", key},
		{"wrong_key", context.Background(), root, wrong},
		{"zero_key", context.Background(), root, [32]byte{}},
		{"cancelled", cancelled, root, key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report, err := lease.InspectPortableTargetRuleTree(tc.ctx, tc.root, tc.key)
			if err == nil || !reflect.DeepEqual(report, InertPortableTargetTreeReport{}) {
				t.Fatalf("invalid target path/key accepted: %+v %v", report, err)
			}
		})
	}
	if _, err := lease.InspectPortableTargetRuleTree(context.Background(), root, key); err != nil {
		t.Fatalf("refusal poisoned healthy lease: %v", err)
	}
}

func TestPortableTargetTreeRejectsInodeReplacementsAndCASDrift(t *testing.T) {
	for _, change := range []string{
		"same_bytes", "was_missing_now_present", "replace_rule_dir",
		"selection", "journal_abandon",
	} {
		t.Run(change, func(t *testing.T) {
			f, lease, record, key := makeTargetRuleLease(t)
			ctx := context.Background()
			root, ruleDir := makePrivatePortableTargetTree(t, f)
			path := filepath.Join(ruleDir, f.ruleHash+".json")
			if change == "same_bytes" {
				if err := os.WriteFile(path, f.ruleData, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			report, err := lease.inspectPortableTargetRuleTree(ctx, root, key, func() error {
				switch change {
				case "same_bytes":
					replacement := path+".new"
					if err := os.WriteFile(replacement, f.ruleData, 0o600); err != nil {
						return err
					}
					return os.Rename(replacement, path)
				case "was_missing_now_present":
					return os.WriteFile(path, f.ruleData, 0o600)
				case "replace_rule_dir":
					if err := os.Rename(ruleDir, ruleDir+".old"); err != nil {
						return err
					}
					return os.Mkdir(ruleDir, 0o700)
				case "selection":
					_, err := f.store.SetCurrentSelectionIntent(ctx,
						[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`))
					return err
				case "journal_abandon":
					return f.store.AbandonInertRestoreRecord(ctx,
						record.ID, record.CandidateScope, record.ArchiveSHA256)
				}
				return errors.New("invalid test fault")
			})
			if !errors.Is(err, ErrInertPortableTargetTree) ||
				!reflect.DeepEqual(report, InertPortableTargetTreeReport{}) {
				t.Fatalf("late %s drift accepted: %+v %v", change, report, err)
			}
			snapshot, err := f.store.Snapshot(ctx)
			if err != nil || snapshot.ActiveAttemptID != nil || snapshot.RecoveryRequired {
				t.Fatalf("target scanner started apply: %+v %v", snapshot, err)
			}
		})
	}
}

func TestPortableTargetTreeSerializesCiphertextLeaseClose(t *testing.T) {
	f, lease, _, key := makeTargetRuleLease(t)
	root, _ := makePrivatePortableTargetTree(t, f)
	ctx := context.Background()
	started := make(chan struct{})
	release := make(chan struct{})
	outcome := make(chan error, 1)
	go func() {
		_, err := lease.inspectPortableTargetRuleTree(ctx, root, key, func() error {
			close(started)
			<-release
			return nil
		})
		outcome <- err
	}()
	select {
	case <-started:
	case <-time.After(12*time.Second):
		t.Fatal("target inspector did not reach validation seam")
	}
	closed := make(chan error, 1)
	go func() { closed <- lease.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close dropped lease before target inspection ended: %v", err)
	case <-time.After(50*time.Millisecond):
	}
	close(release)
	select {
	case err := <-outcome:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12*time.Second):
		t.Fatal("inspector blocked forever")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12*time.Second):
		t.Fatal("Close deadlocked")
	}
}
