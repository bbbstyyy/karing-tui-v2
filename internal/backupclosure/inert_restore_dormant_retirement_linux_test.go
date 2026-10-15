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

func TestDormantRetirementQuarantinesAuthenticatedBundleWithoutDeletion(t *testing.T) {
	f, lease, record, key, parent := makeReopenedDormantAuthenticationFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := lease.AuthenticateDormantRuleBundle(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	report, err := lease.QuarantineDormantRuleBundle(ctx, key, auth)
	if err != nil || !report.Quarantined || !report.RequiresManualReview ||
		report.RestoreReady || report.RestoreSupported ||
		report.RuleCount != 1 || report.RuleBytes != int64(len(f.ruleData)) ||
		report.ArchiveSHA256 != record.ArchiveSHA256 ||
		report.InventorySHA256 != record.InventorySHA256 ||
		report.RetiredScopeSHA256 != shaHex([]byte(dormantRuleRetiredPrefix+record.ArchiveSHA256)) {
		t.Fatalf("inactive retirement failed or granted restore: %+v %v", report, err)
	}
	if _, err := os.Lstat(filepath.Join(parent,
		dormantRuleBundlePrefix+record.ArchiveSHA256)); !os.IsNotExist(err) {
		t.Fatalf("original published-looking name survived retirement: %v", err)
	}
	retired := filepath.Join(parent, dormantRuleRetiredPrefix+record.ArchiveSHA256)
	privateInfo, err := os.Stat(retired)
	if err != nil || !privatePortableDirectory(privateInfo) {
		t.Fatalf("retired directory was not private: %+v %v", privateInfo, err)
	}
	payload, err := os.ReadFile(filepath.Join(retired, f.ruleHash+".json"))
	if err != nil || !bytes.Equal(payload, f.ruleData) {
		t.Fatalf("retirement deleted/modified rule bytes: %v", err)
	}
	if entries := dormantStageEntries(t, parent); len(entries) != 1 ||
		entries[0].Name() != dormantRuleRetiredPrefix+record.ArchiveSHA256 {
		t.Fatalf("retirement left ambiguous names: %+v", entries)
	}
	if _, err := InspectDormantRuleBundles(ctx, f.store); !errors.Is(err, ErrDormantRuleBundleAudit) {
		t.Fatalf("ordinary untrusted inventory silently adopted retired namespace: %v", err)
	}
	if got, err := lease.AuthenticateDormantRuleBundle(ctx, key); err == nil ||
		!reflect.DeepEqual(got, AuthenticatedDormantRuleReport{}) {
		t.Fatalf("quarantined rules became available as active-looking bundle: %+v %v", got, err)
	}
	if got, err := lease.QuarantineDormantRuleBundle(ctx, key, auth); err == nil ||
		!reflect.DeepEqual(got, DormantRuleRetirementReceipt{}) {
		t.Fatalf("repeat retirement should not overwrite old quarantine: %+v %v", got, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("quarantine changed Applied/LKG/live: %+v -> %+v %v", before, after, err)
	}
	records, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(records) != 1 || records[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("quarantine changed durable journal: %+v %v", records, err)
	}
	if _, err := os.Lstat(filepath.Join(f.stateRoot, "core",
		"rule-sets", "sha256", f.ruleHash+".json")); err != nil {
		t.Fatalf("live rule tree changed: %v", err)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(retired, f.ruleHash+".json")); err != nil ||
		!bytes.Equal(data, payload) {
		t.Fatalf("quarantined rules did not survive all lease closes: %v", err)
	}
}

func TestDormantRetirementRequiresExactReadOnlyExpectation(t *testing.T) {
	for _, fault := range []string{
		"zero", "wrong_archive", "wrong_inventory", "wrong_scope",
		"wrong_count", "wrong_bytes", "forged_ready", "not_authenticated",
		"wrong_key", "canceled", "closed_lease",
	} {
		t.Run(fault, func(t *testing.T) {
			_, lease, record, key, parent := makeReopenedDormantAuthenticationFixture(t)
			ctx := context.Background()
			auth, err := lease.AuthenticateDormantRuleBundle(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			useKey := key
			switch fault {
			case "zero":
				auth = AuthenticatedDormantRuleReport{}
			case "wrong_archive":
				auth.ArchiveSHA256 = strings.Repeat("0", 64)
			case "wrong_inventory":
				auth.InventorySHA256 = strings.Repeat("0", 64)
			case "wrong_scope":
				auth.ScopeSHA256 = strings.Repeat("0", 64)
			case "wrong_count":
				auth.RuleCount++
			case "wrong_bytes":
				auth.RuleBytes++
			case "forged_ready":
				auth.RestoreReady = true
			case "not_authenticated":
				auth.RuleBytesVerified = false
			case "wrong_key":
				useKey[0] ^= 0xaf
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed_lease":
				if err := lease.Close(); err != nil {
					t.Fatal(err)
				}
			}
			report, err := lease.QuarantineDormantRuleBundle(ctx, useKey, auth)
			if err == nil || !reflect.DeepEqual(report, DormantRuleRetirementReceipt{}) {
				t.Fatalf("accepted %s: %+v %v", fault, report, err)
			}
			if _, err := os.Stat(filepath.Join(parent, dormantRuleBundlePrefix+
				record.ArchiveSHA256)); err != nil {
				t.Fatalf("failed retirement damaged published scope: %v", err)
			}
			if _, err := os.Lstat(filepath.Join(parent, dormantRuleRetiredPrefix+
				record.ArchiveSHA256)); !os.IsNotExist(err) {
				t.Fatalf("failed retirement created quarantine: %v", err)
			}
		})
	}
}

func TestDormantRetirementRefusesFaultsBeforeAtomicRename(t *testing.T) {
	for _, fault := range []string{
		"hook_error", "inode_swap", "corrupt", "unknown", "pending",
		"directory_swap", "selection_drift", "journal_abandon", "cancel",
	} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent := makeReopenedDormantAuthenticationFixture(t)
			ctx := context.Background()
			auth, err := lease.AuthenticateDormantRuleBundle(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			published := filepath.Join(parent, dormantRuleBundlePrefix+record.ArchiveSHA256)
			rule := filepath.Join(published, f.ruleHash+".json")
			limited, cancel := context.WithCancel(ctx)
			defer cancel()
			got, err := lease.quarantineDormantRuleBundle(limited, key, auth, func() error {
				switch fault {
				case "hook_error":
					return errors.New("before rename injection")
				case "inode_swap":
					alternate := filepath.Join(published, "substitute")
					if err := os.WriteFile(alternate, f.ruleData, 0o400); err != nil {
						return err
					}
					return os.Rename(alternate, rule)
				case "corrupt":
					if err := os.Chmod(rule, 0o600); err != nil {
						return err
					}
					if err := os.WriteFile(rule,
						bytes.Repeat([]byte("x"), len(f.ruleData)), 0o600); err != nil {
						return err
					}
					return os.Chmod(rule, 0o400)
				case "unknown":
					return os.WriteFile(filepath.Join(parent, "unknown"), []byte("x"), 0o600)
				case "pending":
					return os.Mkdir(filepath.Join(parent,
						dormantRulePendingPrefix+"ABCDEF"), 0o700)
				case "directory_swap":
					if err := os.Rename(published, published+".old"); err != nil {
						return err
					}
					return os.Mkdir(published, 0o700)
				case "selection_drift":
					_, err := f.store.SetCurrentSelectionIntent(ctx,
						[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"different"}`))
					return err
				case "journal_abandon":
					return f.store.AbandonInertRestoreRecord(ctx, record.ID,
						record.CandidateScope, record.ArchiveSHA256)
				case "cancel":
					cancel()
				}
				return nil
			}, nil)
			if err == nil || !reflect.DeepEqual(got, DormantRuleRetirementReceipt{}) {
				t.Fatalf("accepted %s before rename: %+v %v", fault, got, err)
			}
			if _, err := os.Lstat(filepath.Join(parent,
				dormantRuleRetiredPrefix+record.ArchiveSHA256)); !os.IsNotExist(err) {
				t.Fatalf("%s published an untrusted quarantine: %v", fault, err)
			}
		})
	}
}

func TestDormantRetirementAfterRenameFaultLeavesPrivateScopeForReview(t *testing.T) {
	f, lease, record, key, parent := makeReopenedDormantAuthenticationFixture(t)
	ctx := context.Background()
	auth, err := lease.AuthenticateDormantRuleBundle(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := lease.quarantineDormantRuleBundle(ctx, key, auth, nil,
		func() error { return errors.New("power loss between rename and fsync") })
	if !errors.Is(err, ErrDormantRuleRetirement) ||
		!reflect.DeepEqual(got, DormantRuleRetirementReceipt{}) {
		t.Fatalf("post-rename uncertainty was reported as success: %+v %v", got, err)
	}
	retired := filepath.Join(parent, dormantRuleRetiredPrefix+record.ArchiveSHA256)
	data, err := os.ReadFile(filepath.Join(retired, f.ruleHash+".json"))
	if err != nil || !bytes.Equal(data, f.ruleData) {
		t.Fatalf("post-rename failure deleted retained bytes: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(parent, dormantRuleBundlePrefix+
		record.ArchiveSHA256)); !os.IsNotExist(err) {
		t.Fatalf("ambiguous commit created two active-looking names: %v", err)
	}
	if report, err := lease.QuarantineDormantRuleBundle(ctx, key, auth); err == nil ||
		!reflect.DeepEqual(report, DormantRuleRetirementReceipt{}) {
		t.Fatalf("retirement silently adopted a previously uncertain commit: %+v %v", report, err)
	}
}

func TestDormantRetirementSubprocessHelper(t *testing.T) {
	if os.Getenv("KTUI_DORMANT_RETIRE_HELPER") != "yes" {
		return
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, os.Getenv("KTUI_DORMANT_RETIRE_DB"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, err := strconv.ParseInt(os.Getenv("KTUI_DORMANT_RETIRE_ID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(os.Getenv("KTUI_DORMANT_RETIRE_KEY"))
	if err != nil || len(raw) != 32 {
		t.Fatal("bad test key")
	}
	var key [32]byte
	copy(key[:], raw)
	lease, err := AcquireInertRestoreResourceLease(ctx, store,
		os.Getenv("KTUI_DORMANT_RETIRE_PARENT"), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	auth, err := lease.AuthenticateDormantRuleBundle(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = lease.quarantineDormantRuleBundle(ctx, key, auth, nil, func() error {
		if _, err := os.Stdout.Write([]byte("renamed\n")); err != nil {
			return err
		}
		time.Sleep(3 * time.Minute)
		return nil
	})
	t.Fatal("subprocess was not SIGKILLed at post-rename fault boundary")
}

func TestDormantRetirementSIGKILLAfterAtomicRename(t *testing.T) {
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
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	childCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0],
		"-test.run=^TestDormantRetirementSubprocessHelper$")
	cmd.Env = append(os.Environ(),
		"KTUI_DORMANT_RETIRE_HELPER=yes",
		"KTUI_DORMANT_RETIRE_DB="+f.store.Path(),
		"KTUI_DORMANT_RETIRE_PARENT="+candidateParent,
		"KTUI_DORMANT_RETIRE_ID="+strconv.FormatInt(record.ID, 10),
		"KTUI_DORMANT_RETIRE_KEY="+hex.EncodeToString(key[:]))
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
	ready := make([]byte, len("renamed\n"))
	if _, err := io.ReadFull(reader, ready); err != nil ||
		string(ready) != "renamed\n" {
		t.Fatalf("subprocess did not reach atomic rename: %q %v", ready, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	reaped = true
	retired := filepath.Join(parent, dormantRuleRetiredPrefix+record.ArchiveSHA256)
	info, err := os.Stat(retired)
	if err != nil || !privatePortableDirectory(info) {
		t.Fatalf("SIGKILL left a missing/public retirement: %+v %v", info, err)
	}
	if data, err := os.ReadFile(filepath.Join(retired, f.ruleHash+".json")); err != nil ||
		!bytes.Equal(data, f.ruleData) {
		t.Fatalf("SIGKILL removed/modified inactive rule content: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(parent,
		dormantRuleBundlePrefix+record.ArchiveSHA256)); !os.IsNotExist(err) {
		t.Fatalf("SIGKILL preserved a misleading published name: %v", err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("SIGKILL retirement changed live state: %+v -> %+v %v", before, after, err)
	}
	// A fresh process can still authenticate the original ciphertext, but
	// the retired rule path is deliberately NOT silently adopted.
	fresh, err := AcquireInertRestoreResourceLease(ctx, f.store, candidateParent,
		record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.AuthenticateDormantRuleBundle(ctx, key); !errors.Is(err, ErrDormantRuleAuthentication) {
		t.Fatalf("orphan retirement unexpectedly became restorable: %v", err)
	}
}
