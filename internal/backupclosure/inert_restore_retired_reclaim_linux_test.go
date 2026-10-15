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

func makeRetiredReclaimFixture(t *testing.T) (
	*fixture, *InertRestoreResourceLease,
	storage.InertRestorePreparation, [32]byte, string,
) {
	t.Helper()
	f, initial, record, key, parent := makeReopenedDormantAuthenticationFixture(t)
	ctx := context.Background()
	original, err := initial.AuthenticateDormantRuleBundle(ctx, key)
	if err != nil { t.Fatal(err) }
	retired, err := initial.QuarantineDormantRuleBundle(ctx, key, original)
	if err != nil || !retired.Quarantined { t.Fatalf("fixture quarantine: %+v %v", retired, err) }
	candidateParent := initial.candidate.parent
	if err := initial.Close(); err != nil { t.Fatal(err) }
	fresh, err := AcquireInertRestoreResourceLease(ctx, f.store, candidateParent, record.ID, key)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func() { _ = fresh.Close() })
	return f, fresh, record, key, parent
}

func TestRetiredReclaimInspectionAndIntentNeverDeleteOrActivate(t *testing.T) {
	f, lease, record, key, parent := makeRetiredReclaimFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil { t.Fatal(err) }
	if _, err := InspectDormantRuleBundles(ctx, f.store); !errors.Is(err, ErrDormantRuleBundleAudit) {
		t.Fatalf("ordinary inventory accepted retired namespace: %v", err)
	}
	report, err := lease.InspectRetiredDormantRuleBundle(ctx, key)
	if err != nil || !report.ContentVerified || !report.RequiresRevalidation ||
		report.RestoreSupported || report.RestoreReady ||
		report.ArchiveSHA256 != record.ArchiveSHA256 ||
		report.InventorySHA256 != record.InventorySHA256 ||
		report.RetiredScopeSHA256 != shaHex([]byte(dormantRuleRetiredPrefix+record.ArchiveSHA256)) ||
		report.RuleCount != 1 || report.RuleBytes != int64(len(f.ruleData)) {
		t.Fatalf("post-restart retired rule attestation incorrect: %+v %v", report, err)
	}
	intent, err := lease.BeginRetiredDormantRuleReclaim(ctx, key, report)
	if err != nil || !intent.IntentPublished || intent.BytesDeleted ||
		!intent.RequiresManualReview || intent.RestoreSupported || intent.RestoreReady ||
		intent.RuleCount != report.RuleCount || intent.RuleBytes != report.RuleBytes ||
		intent.ReclaimScopeSHA256 != shaHex([]byte(dormantRuleReclaimPrefix+record.ArchiveSHA256)) {
		t.Fatalf("non-deleting reclaim intent failed: %+v %v", intent, err)
	}
	if _, err := os.Lstat(filepath.Join(parent,
		dormantRuleRetiredPrefix+record.ArchiveSHA256)); !os.IsNotExist(err) {
		t.Fatalf("retired-looking entry still present: %v", err)
	}
	newScope := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
	data, err := os.ReadFile(filepath.Join(newScope, f.ruleHash+".json"))
	if err != nil || !bytes.Equal(data, f.ruleData) {
		t.Fatalf("intent removed or modified bytes: %v", err)
	}
	if entries := dormantStageEntries(t, parent); len(entries) != 1 ||
		entries[0].Name() != dormantRuleReclaimPrefix+record.ArchiveSHA256 {
		t.Fatalf("unexpected namespace after reclaim intent: %+v", entries)
	}
	if result, err := lease.InspectRetiredDormantRuleBundle(ctx, key); err == nil ||
		!reflect.DeepEqual(result, RetiredRuleInspection{}) {
		t.Fatalf("reclaiming scope was silently adopted: %+v %v", result, err)
	}
	if result, err := lease.BeginRetiredDormantRuleReclaim(ctx, key, report); err == nil ||
		!reflect.DeepEqual(result, RetiredRuleReclaimIntent{}) {
		t.Fatalf("duplicate intent silently replayed: %+v %v", result, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("reclaim intention changed live Applied/LKG: %+v -> %+v %v", before, after, err)
	}
	records, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(records) != 1 || records[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("reclaim changed journal: %+v %v", records, err)
	}
	if _, err := os.Stat(filepath.Join(f.stateRoot, "core", "rule-sets",
		"sha256", f.ruleHash+".json")); err != nil {
		t.Fatalf("reclaim touched active rule tree: %v", err)
	}
}

func TestRetiredReclaimRejectsBadExpectationsAndUnsafeEntries(t *testing.T) {
	for _, fault := range []string{
		"zero", "wrong_archive", "wrong_inventory", "wrong_scope", "wrong_bytes",
		"wrong_count", "forged_ready", "wrong_key", "canceled", "closed",
		"modified_rule", "same_byte_inode", "symlink", "hardlink",
		"extra_file", "public_scope", "public_root", "pending", "unknown",
	} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent := makeRetiredReclaimFixture(t)
			ctx := context.Background()
			expected, err := lease.InspectRetiredDormantRuleBundle(ctx, key)
			if err != nil { t.Fatal(err) }
			ruleDir := filepath.Join(parent, dormantRuleRetiredPrefix+record.ArchiveSHA256)
			leaf := filepath.Join(ruleDir, f.ruleHash+".json")
			useKey := key
			var mutation error
			switch fault {
			case "zero": expected = RetiredRuleInspection{}
			case "wrong_archive": expected.ArchiveSHA256 = strings.Repeat("0", 64)
			case "wrong_inventory": expected.InventorySHA256 = strings.Repeat("0", 64)
			case "wrong_scope": expected.RetiredScopeSHA256 = strings.Repeat("0", 64)
			case "wrong_bytes": expected.RuleBytes++
			case "wrong_count": expected.RuleCount++
			case "forged_ready": expected.RestoreReady = true
			case "wrong_key": useKey[0] ^= 0xaa
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed": mutation = lease.Close()
			case "modified_rule":
				mutation = os.Chmod(leaf, 0o600)
				if mutation == nil { mutation = os.WriteFile(leaf, bytes.Repeat([]byte("x"), len(f.ruleData)), 0o600) }
				if mutation == nil { mutation = os.Chmod(leaf, 0o400) }
			case "same_byte_inode":
				replacement := filepath.Join(ruleDir, "replacement")
				mutation = os.WriteFile(replacement, f.ruleData, 0o400)
				if mutation == nil { mutation = os.Rename(replacement, leaf) }
			case "symlink":
				mutation = os.Remove(leaf)
				if mutation == nil { mutation = os.Symlink("/etc/passwd", leaf) }
			case "hardlink": mutation = os.Link(leaf, filepath.Join(ruleDir, "extra"))
			case "extra_file": mutation = os.WriteFile(filepath.Join(ruleDir, "extra"), []byte("bad"), 0o600)
			case "public_scope": mutation = os.Chmod(ruleDir, 0o755)
			case "public_root": mutation = os.Chmod(parent, 0o755)
			case "pending": mutation = os.Mkdir(filepath.Join(parent, dormantRulePendingPrefix+"ABCDEF"), 0o700)
			case "unknown": mutation = os.WriteFile(filepath.Join(parent, "unknown"), []byte("bad"), 0o600)
			}
			if mutation != nil { t.Fatal(mutation) }
			res, err := lease.BeginRetiredDormantRuleReclaim(ctx, useKey, expected)
			if err == nil || !reflect.DeepEqual(res, RetiredRuleReclaimIntent{}) {
				t.Fatalf("accepted %s: %+v %v", fault, res, err)
			}
			if _, err := os.Lstat(filepath.Join(parent, dormantRuleReclaimPrefix+
				record.ArchiveSHA256)); !os.IsNotExist(err) {
				t.Fatalf("%s wrote reclaiming namespace: %v", fault, err)
			}
		})
	}
}

func TestRetiredReclaimDetectsLateDriftBeforeRename(t *testing.T) {
	for _, fault := range []string{
		"injected_error", "same_byte_inode", "changed_content", "new_scope",
		"journal_abandon", "selection", "root_replacement", "cancel",
	} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent := makeRetiredReclaimFixture(t)
			ctx := context.Background()
			expected, err := lease.InspectRetiredDormantRuleBundle(ctx, key)
			if err != nil { t.Fatal(err) }
			limited, cancel := context.WithCancel(ctx)
			defer cancel()
			ruleDir := filepath.Join(parent, dormantRuleRetiredPrefix+record.ArchiveSHA256)
			leaf := filepath.Join(ruleDir, f.ruleHash+".json")
			res, err := lease.beginRetiredDormantRuleReclaim(limited, key, expected, func() error {
				switch fault {
				case "injected_error": return errors.New("injected boundary")
				case "same_byte_inode":
					replacement := filepath.Join(ruleDir, "replacement")
					if err := os.WriteFile(replacement, f.ruleData, 0o400); err != nil { return err }
					return os.Rename(replacement, leaf)
				case "changed_content":
					if err := os.Chmod(leaf, 0o600); err != nil { return err }
					if err := os.WriteFile(leaf, bytes.Repeat([]byte("z"), len(f.ruleData)), 0o600); err != nil { return err }
					return os.Chmod(leaf, 0o400)
				case "new_scope": return os.Mkdir(filepath.Join(parent, dormantRulePendingPrefix+"ABCDEF"), 0o700)
				case "journal_abandon":
					return f.store.AbandonInertRestoreRecord(ctx, record.ID,
						record.CandidateScope, record.ArchiveSHA256)
				case "selection":
					_, err := f.store.SetCurrentSelectionIntent(ctx,
						[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`))
					return err
				case "root_replacement":
					if err := os.Rename(parent, parent+".moved"); err != nil { return err }
					return os.Mkdir(parent, 0o700)
				case "cancel": cancel()
				}
				return nil
			}, nil)
			if err == nil || !reflect.DeepEqual(res, RetiredRuleReclaimIntent{}) {
				t.Fatalf("late %s accepted: %+v %v", fault, res, err)
			}
			if _, err := os.Lstat(filepath.Join(parent, dormantRuleReclaimPrefix+
				record.ArchiveSHA256)); !os.IsNotExist(err) {
				t.Fatalf("late %s committed intent: %v", fault, err)
			}
		})
	}
}

func TestRetiredReclaimAfterRenameFailureIsNonDeletingAndUncertain(t *testing.T) {
	f, lease, record, key, parent := makeRetiredReclaimFixture(t)
	ctx := context.Background()
	expected, err := lease.InspectRetiredDormantRuleBundle(ctx, key)
	if err != nil { t.Fatal(err) }
	got, err := lease.beginRetiredDormantRuleReclaim(ctx, key, expected,
		nil, func() error { return errors.New("injected crash before root fsync") })
	if !errors.Is(err, ErrRetiredRuleReclaim) ||
		!reflect.DeepEqual(got, RetiredRuleReclaimIntent{}) {
		t.Fatalf("uncertain rename reported success: %+v %v", got, err)
	}
	reclaimPath := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
	data, err := os.ReadFile(filepath.Join(reclaimPath, f.ruleHash+".json"))
	if err != nil || !bytes.Equal(data, f.ruleData) {
		t.Fatalf("crash boundary physically deleted rules: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(parent, dormantRuleRetiredPrefix+
		record.ArchiveSHA256)); !os.IsNotExist(err) {
		t.Fatalf("ambiguous commit left original name: %v", err)
	}
	if result, err := lease.BeginRetiredDormantRuleReclaim(ctx, key, expected); err == nil ||
		!reflect.DeepEqual(result, RetiredRuleReclaimIntent{}) {
		t.Fatalf("uncertain commit silently re-adopted: %+v %v", result, err)
	}
}

func TestRetiredReclaimCrashHelper(t *testing.T) {
	if os.Getenv("KTUI_RETIRED_RECLAIM_HELPER") != "yes" { return }
	ctx := context.Background()
	store, err := storage.Open(ctx, os.Getenv("KTUI_RETIRED_RECLAIM_DB"))
	if err != nil { t.Fatal(err) }
	defer store.Close()
	id, err := strconv.ParseInt(os.Getenv("KTUI_RETIRED_RECLAIM_ID"), 10, 64)
	if err != nil { t.Fatal(err) }
	raw, err := hex.DecodeString(os.Getenv("KTUI_RETIRED_RECLAIM_KEY"))
	if err != nil || len(raw) != 32 { t.Fatal("bad key") }
	var key [32]byte
	copy(key[:], raw)
	lease, err := AcquireInertRestoreResourceLease(ctx, store,
		os.Getenv("KTUI_RETIRED_RECLAIM_PARENT"), id, key)
	if err != nil { t.Fatal(err) }
	defer lease.Close()
	report, err := lease.InspectRetiredDormantRuleBundle(ctx, key)
	if err != nil { t.Fatal(err) }
	_, _ = lease.beginRetiredDormantRuleReclaim(ctx, key, report, nil, func() error {
		if _, err := os.Stdout.Write([]byte("renamed\n")); err != nil { return err }
		time.Sleep(3 * time.Minute)
		return nil
	})
	t.Fatal("test subprocess not killed at rename fault")
}

func TestRetiredReclaimSIGKILLAfterAtomicIntent(t *testing.T) {
	f, lease, record, key, parent := makeRetiredReclaimFixture(t)
	ctx := context.Background()
	candidateParent := lease.candidate.parent
	if err := lease.Close(); err != nil { t.Fatal(err) }
	before, err := f.store.Snapshot(ctx)
	if err != nil { t.Fatal(err) }
	childCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestRetiredReclaimCrashHelper$")
	cmd.Env = append(os.Environ(),
		"KTUI_RETIRED_RECLAIM_HELPER=yes",
		"KTUI_RETIRED_RECLAIM_DB="+f.store.Path(),
		"KTUI_RETIRED_RECLAIM_PARENT="+candidateParent,
		"KTUI_RETIRED_RECLAIM_ID="+strconv.FormatInt(record.ID, 10),
		"KTUI_RETIRED_RECLAIM_KEY="+hex.EncodeToString(key[:]))
	reader, err := cmd.StdoutPipe()
	if err != nil { t.Fatal(err) }
	if err := cmd.Start(); err != nil { t.Fatal(err) }
	reaped := false
	t.Cleanup(func() {
		if !reaped { _ = cmd.Process.Kill(); _ = cmd.Wait() }
	})
	message := make([]byte, len("renamed\n"))
	if _, err := io.ReadFull(reader, message); err != nil || string(message) != "renamed\n" {
		t.Fatalf("subprocess did not atomically rename: %q %v", message, err)
	}
	if err := cmd.Process.Kill(); err != nil { t.Fatal(err) }
	_ = cmd.Wait()
	reaped = true
	newScope := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
	data, err := os.ReadFile(filepath.Join(newScope, f.ruleHash+".json"))
	if err != nil || !bytes.Equal(data, f.ruleData) {
		t.Fatalf("SIGKILL removed rules: %v", err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("SIGKILL changed daemon state: %+v -> %+v %v", before, after, err)
	}
	fresh, err := AcquireInertRestoreResourceLease(ctx, f.store, candidateParent, record.ID, key)
	if err != nil { t.Fatal(err) }
	defer fresh.Close()
	if _, err := fresh.InspectRetiredDormantRuleBundle(ctx, key); !errors.Is(err, ErrRetiredRuleReclaim) {
		t.Fatalf("reclaim intent was silently treated as a retired bundle: %v", err)
	}
}
