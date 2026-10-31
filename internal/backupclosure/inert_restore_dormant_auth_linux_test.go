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
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

// Close the original publisher's anonymous pin and ciphertext lease, then
// independently reopen both SQLite and the candidate as a fresh client.
func makeReopenedDormantAuthenticationFixture(t *testing.T) (
	*fixture, *InertRestoreResourceLease,
	storage.InertRestorePreparation, [32]byte, string,
) {
	t.Helper()
	f, original, pins, record, key, parent := makeDormantRuleBundleFixture(t)
	ctx := context.Background()
	if _, err := pins.StageDormantRuleBundle(ctx, parent, key); err != nil {
		t.Fatal(err)
	}
	candidateParent := original.candidate.parent
	if err := pins.Close(); err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := storage.Open(ctx, f.store.Path())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	lease, err := AcquireInertRestoreResourceLease(
		ctx, fresh, candidateParent, record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	return f, lease, record, key, parent
}

func TestDormantAuthenticationReopensCiphertextAndRehashesRuleWithoutActivation(t *testing.T) {
	f, lease, record, key, parent := makeReopenedDormantAuthenticationFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	report, err := lease.AuthenticateDormantRuleBundle(ctx, key)
	if err != nil || !report.RuleBytesVerified || !report.Inactive ||
		!report.RequiresRevalidation || report.RestoreSupported ||
		report.RestoreReady || report.RuleCount != 1 ||
		report.RuleBytes != int64(len(f.ruleData)) ||
		report.ArchiveSHA256 != record.ArchiveSHA256 ||
		report.InventorySHA256 != record.InventorySHA256 ||
		report.ScopeSHA256 != shaHex([]byte(dormantRuleBundlePrefix+record.ArchiveSHA256)) {
		t.Fatalf("restarted client did not independently authenticate inert rules: %+v %v", report, err)
	}
	if entries := dormantStageEntries(t, parent); len(entries) != 1 {
		t.Fatalf("read-only authentication altered scope inventory: %+v", entries)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("authentication changed active/LKG state: %+v -> %+v %v", before, after, err)
	}
	journal, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(journal) != 1 ||
		journal[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("authentication changed recovery journal: %+v %v", journal, err)
	}
	badKey := key
	badKey[0] ^= 0x8f
	if result, err := lease.AuthenticateDormantRuleBundle(ctx, badKey); err == nil ||
		!reflect.DeepEqual(result, AuthenticatedDormantRuleReport{}) {
		t.Fatalf("incorrect key authenticated archived rules: %+v %v", result, err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if result, err := lease.AuthenticateDormantRuleBundle(ctx, key); err == nil ||
		!reflect.DeepEqual(result, AuthenticatedDormantRuleReport{}) {
		t.Fatalf("closed lease was reused: %+v %v", result, err)
	}
}

func TestDormantAuthenticationRejectsTamperedOrAmbiguousNamespaces(t *testing.T) {
	for _, fault := range []string{
		"modified_bytes", "public_file", "symlink_file", "hard_link",
		"extra_file", "missing_file", "public_scope", "pending_scope",
		"unknown_root", "public_root", "replaced_root",
	} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent := makeReopenedDormantAuthenticationFixture(t)
			ctx := context.Background()
			scope := filepath.Join(parent, dormantRuleBundlePrefix+record.ArchiveSHA256)
			rule := filepath.Join(scope, f.ruleHash+".json")
			var err error
			switch fault {
			case "modified_bytes":
				err = os.Chmod(rule, 0o600)
				if err == nil {
					err = os.WriteFile(rule, bytes.Repeat([]byte("x"), len(f.ruleData)), 0o600)
				}
				if err == nil {
					err = os.Chmod(rule, 0o400)
				}
			case "public_file":
				err = os.Chmod(rule, 0o644)
			case "symlink_file":
				err = os.Remove(rule)
				if err == nil {
					err = os.Symlink("/etc/passwd", rule)
				}
			case "hard_link":
				err = os.Link(rule, filepath.Join(scope, f.ruleHash+".copy"))
			case "extra_file":
				err = os.WriteFile(filepath.Join(scope, strings.Repeat("0", 64)+".srs"),
					[]byte("not an authenticated rule"), 0o400)
			case "missing_file":
				err = os.Remove(rule)
			case "public_scope":
				err = os.Chmod(scope, 0o755)
			case "pending_scope":
				err = os.Mkdir(filepath.Join(parent, dormantRulePendingPrefix+"ABCDEF"), 0o700)
			case "unknown_root":
				err = os.WriteFile(filepath.Join(parent, "unexpected"), []byte("x"), 0o600)
			case "public_root":
				err = os.Chmod(parent, 0o755)
			case "replaced_root":
				err = os.Rename(parent, parent+".old")
				if err == nil {
					err = os.Mkdir(parent, 0o700)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := f.store.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			got, err := lease.AuthenticateDormantRuleBundle(ctx, key)
			if !errors.Is(err, ErrDormantRuleAuthentication) ||
				!reflect.DeepEqual(got, AuthenticatedDormantRuleReport{}) {
				t.Fatalf("accepted %s: %+v %v", fault, got, err)
			}
			after, err := f.store.Snapshot(ctx)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatalf("failed authentication changed live state: %+v -> %+v %v", before, after, err)
			}
		})
	}
}

func TestDormantAuthenticationRejectsDriftDuringAuthenticatedScan(t *testing.T) {
	for _, fault := range []string{
		"late_inode_swap", "late_bytes", "late_extra", "late_selection",
		"late_abandon", "late_root_swap", "cancel",
	} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent := makeReopenedDormantAuthenticationFixture(t)
			ctx := context.Background()
			scope := filepath.Join(parent, dormantRuleBundlePrefix+record.ArchiveSHA256)
			rule := filepath.Join(scope, f.ruleHash+".json")
			bounded, cancel := context.WithCancel(ctx)
			defer cancel()
			got, err := lease.authenticateDormantRuleBundle(bounded, key, func() error {
				switch fault {
				case "late_inode_swap":
					replacement := filepath.Join(scope, "replacement")
					if err := os.WriteFile(replacement, f.ruleData, 0o400); err != nil {
						return err
					}
					return os.Rename(replacement, rule)
				case "late_bytes":
					if err := os.Chmod(rule, 0o600); err != nil {
						return err
					}
					if err := os.WriteFile(rule, bytes.Repeat([]byte("z"), len(f.ruleData)), 0o600); err != nil {
						return err
					}
					return os.Chmod(rule, 0o400)
				case "late_extra":
					return os.WriteFile(filepath.Join(scope, "unexpected"), []byte("x"), 0o600)
				case "late_selection":
					_, err := f.store.SetCurrentSelectionIntent(ctx,
						[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`))
					return err
				case "late_abandon":
					return f.store.AbandonInertRestoreRecord(ctx, record.ID,
						record.CandidateScope, record.ArchiveSHA256)
				case "late_root_swap":
					if err := os.Rename(parent, parent+".moved"); err != nil {
						return err
					}
					return os.Mkdir(parent, 0o700)
				case "cancel":
					cancel()
				}
				return nil
			})
			if err == nil || !reflect.DeepEqual(got, AuthenticatedDormantRuleReport{}) {
				t.Fatalf("accepted %s after authenticated scan: %+v %v", fault, got, err)
			}
		})
	}
}

func TestDormantAuthenticationProcessHelper(t *testing.T) {
	if os.Getenv("KTUI_DORMANT_AUTH_HELPER") != "yes" {
		return
	}
	ctx := context.Background()
	s, err := storage.Open(ctx, os.Getenv("KTUI_DORMANT_AUTH_DB"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := strconv.ParseInt(os.Getenv("KTUI_DORMANT_AUTH_ID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	rawKey, err := hex.DecodeString(os.Getenv("KTUI_DORMANT_AUTH_KEY"))
	if err != nil || len(rawKey) != 32 {
		t.Fatal("invalid test key")
	}
	var key [32]byte
	copy(key[:], rawKey)
	lease, err := AcquireInertRestoreResourceLease(ctx, s,
		os.Getenv("KTUI_DORMANT_AUTH_PARENT"), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	result, err := lease.AuthenticateDormantRuleBundle(ctx, key)
	if err != nil || !result.RuleBytesVerified || result.RestoreReady ||
		result.RestoreSupported || !result.RequiresRevalidation {
		t.Fatalf("subprocess cannot reauthenticate dormant bundle: %+v %v", result, err)
	}
	if _, err := os.Stdout.Write([]byte("verified\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Minute)
}

func TestDormantAuthenticationSurvivesFreshProcessSIGKILL(t *testing.T) {
	f, original, pins, record, key, _ := makeDormantRuleBundleFixture(t)
	ctx := context.Background()
	parent := filepath.Join(f.stateRoot, dormantRuleRootName)
	if _, err := pins.StageDormantRuleBundle(ctx, parent, key); err != nil {
		t.Fatal(err)
	}
	candidateParent := original.candidate.parent
	if err := pins.Close(); err != nil {
		t.Fatal(err)
	}
	if err := original.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	childCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0],
		"-test.run=^TestDormantAuthenticationProcessHelper$")
	cmd.Env = append(os.Environ(),
		"KTUI_DORMANT_AUTH_HELPER=yes",
		"KTUI_DORMANT_AUTH_DB="+f.store.Path(),
		"KTUI_DORMANT_AUTH_PARENT="+candidateParent,
		"KTUI_DORMANT_AUTH_ID="+strconv.FormatInt(record.ID, 10),
		"KTUI_DORMANT_AUTH_KEY="+hex.EncodeToString(key[:]))
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
	message := make([]byte, len("verified\n"))
	if _, err := io.ReadFull(reader, message); err != nil ||
		string(message) != "verified\n" {
		t.Fatalf("child did not authenticate staged rule: %q %v", message, err)
	}
	if _, err := AcquireInertRestoreResourceLease(ctx, f.store,
		candidateParent, record.ID, key); !errors.Is(err, ErrInertRestoreCandidateBusy) {
		t.Fatalf("cross-process candidate lock was stolen: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	reaped = true
	newLease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		candidateParent, record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer newLease.Close()
	result, err := newLease.AuthenticateDormantRuleBundle(ctx, key)
	if err != nil || !result.RuleBytesVerified || result.RestoreReady ||
		result.RestoreSupported {
		t.Fatalf("post-SIGKILL reauthentication refused or enabled restore: %+v %v", result, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("fresh process recovery changed active daemon: %+v -> %+v %v", before, after, err)
	}
}
