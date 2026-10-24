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

func makeDurableReclaimFixture(t *testing.T) (
	*fixture, *InertRestoreResourceLease, storage.InertRestorePreparation, [32]byte, string,
) {
	t.Helper()
	f, lease, record, key, parent := makeRetiredReclaimFixture(t)
	ctx := context.Background()
	retired, err := lease.InspectRetiredDormantRuleBundle(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := lease.BeginRetiredDormantRuleReclaim(ctx, key, retired)
	if err != nil || !intent.IntentPublished || intent.BytesDeleted {
		t.Fatalf("could not prepare complete reclaim scope: %+v %v", intent, err)
	}
	candidateParent := lease.candidate.parent
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := AcquireInertRestoreResourceLease(ctx, f.store, candidateParent, record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fresh.Close() })
	return f, fresh, record, key, parent
}

func TestDurableReclaimPlanAndOneFileUnlinkAreExplicitAndRecoverable(t *testing.T) {
	f, lease, record, key, parent := makeDurableReclaimFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := lease.PrepareDurableRuleReclaim(ctx, key)
	if err != nil || plan.UnlinkedRules != 0 || plan.UnlinkedBytes != 0 ||
		plan.PreparedIntents != 0 || plan.AllRulesUnlinked ||
		plan.ExpectedRules != 1 || !plan.RequiresRevalidation ||
		plan.RestoreReady || plan.RestoreSupported ||
		plan.ArchiveSHA256 != record.ArchiveSHA256 ||
		plan.InventorySHA256 != record.InventorySHA256 ||
		!validLowerSHA(plan.PlanSHA256) {
		t.Fatalf("unsafe durable plan: %+v %v", plan, err)
	}
	dir := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
	if data, err := os.ReadFile(filepath.Join(dir, f.ruleHash+".json")); err != nil ||
		!bytes.Equal(data, f.ruleData) {
		t.Fatalf("plan created an implicit deletion: %v", err)
	}
	checked, err := lease.InspectDurableRuleReclaim(ctx, key)
	if err != nil || !reflect.DeepEqual(plan, checked) {
		t.Fatalf("reopened plan mismatch: %+v %v", checked, err)
	}
	if report, err := lease.PrepareDurableRuleReclaim(ctx, key); err == nil ||
		!reflect.DeepEqual(report, DurableRuleReclaimProgress{}) {
		t.Fatalf("existing durable plan overwritten: %+v %v", report, err)
	}
	step, err := lease.UnlinkNextDurableReclaimRule(ctx, key, checked)
	if err != nil || !step.RuleUnlinked || step.RuleBytes != int64(len(f.ruleData)) ||
		step.RuleSHA256 != f.ruleHash || step.PlanSHA256 != checked.PlanSHA256 ||
		step.RestoreReady || step.RestoreSupported {
		t.Fatalf("one-leaf deletion not journalled: %+v %v", step, err)
	}
	if _, err := os.Lstat(filepath.Join(dir, f.ruleHash+".json")); !os.IsNotExist(err) {
		t.Fatalf("unlinked rule still appears: %v", err)
	}
	after, err := lease.InspectDurableRuleReclaim(ctx, key)
	if err != nil || after.UnlinkedRules != 1 ||
		after.UnlinkedBytes != int64(len(f.ruleData)) ||
		after.PreparedIntents != 1 || !after.AllRulesUnlinked ||
		after.PlanSHA256 != plan.PlanSHA256 {
		t.Fatalf("authenticated partially deleted state refused: %+v %v", after, err)
	}
	if result, err := lease.UnlinkNextDurableReclaimRule(ctx, key, after); err == nil ||
		!reflect.DeepEqual(result, DurableRuleUnlinkResult{}) {
		t.Fatalf("completed plan allowed second deletion: %+v %v", result, err)
	}
	for _, name := range []string{reclaimPlanFileName, reclaimIntentPrefix + "000"} {
		stat, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0o400 {
			t.Fatalf("durable log missing or public: %s %+v %v", name, stat, err)
		}
	}
	live, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, live) {
		t.Fatalf("inactive reclaim mutated Applied/LKG: %+v -> %+v %v", before, live, err)
	}
	records, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(records) != 1 || records[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("reclamation rewrote live journal: %+v %v", records, err)
	}
	if _, err := os.Stat(filepath.Join(f.stateRoot, "core", "rule-sets", "sha256",
		f.ruleHash+".json")); err != nil {
		t.Fatalf("reclamation touched active rule file: %v", err)
	}
}

func TestDurableReclaimRefusesAlteredPlanOrUnjournalledMissingLeaf(t *testing.T) {
	for _, fault := range []string{
		"wrong_key", "forged_digest", "missing_no_intent", "plan_symlink",
		"plan_tamper", "unknown_entry", "scope_public", "leaf_executable",
	} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent := makeDurableReclaimFixture(t)
			ctx := context.Background()
			expected, err := lease.PrepareDurableRuleReclaim(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
			leaf := filepath.Join(dir, f.ruleHash+".json")
			useKey := key
			var mutation error
			switch fault {
			case "wrong_key":
				useKey[0] ^= 0xaa
			case "forged_digest":
				expected.PlanSHA256 = strings.Repeat("0", 64)
			case "missing_no_intent":
				mutation = os.Remove(leaf)
			case "plan_symlink":
				mutation = os.Remove(filepath.Join(dir, reclaimPlanFileName))
				if mutation == nil {
					mutation = os.Symlink("/etc/passwd", filepath.Join(dir, reclaimPlanFileName))
				}
			case "plan_tamper":
				mutation = os.Chmod(filepath.Join(dir, reclaimPlanFileName), 0o600)
				if mutation == nil {
					data := bytes.Repeat([]byte("x"), 65)
					mutation = os.WriteFile(filepath.Join(dir, reclaimPlanFileName), data, 0o600)
				}
				if mutation == nil {
					mutation = os.Chmod(filepath.Join(dir, reclaimPlanFileName), 0o400)
				}
			case "unknown_entry":
				mutation = os.WriteFile(filepath.Join(dir, "unexpected"), []byte("bad"), 0o600)
			case "scope_public":
				mutation = os.Chmod(dir, 0o755)
			case "leaf_executable":
				mutation = os.Chmod(leaf, 0o500)
			}
			if mutation != nil {
				t.Fatal(mutation)
			}
			step, err := lease.UnlinkNextDurableReclaimRule(ctx, useKey, expected)
			if err == nil || !reflect.DeepEqual(step, DurableRuleUnlinkResult{}) {
				t.Fatalf("unsafe %s accepted: %+v %v", fault, step, err)
			}
			if _, err := os.Lstat(filepath.Join(dir, reclaimIntentPrefix+"000")); !os.IsNotExist(err) {
				t.Fatalf("%s authorized physical deletion: %v", fault, err)
			}
		})
	}
}

func TestDurableReclaimIntentBeforeUnlinkAndPostUnlinkFaults(t *testing.T) {
	t.Run("before_unlink", func(t *testing.T) {
		f, lease, record, key, parent := makeDurableReclaimFixture(t)
		ctx := context.Background()
		plan, err := lease.PrepareDurableRuleReclaim(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := lease.unlinkNextDurableReclaimRule(ctx, key, plan,
			func() error { return errors.New("crash after fsynced intent") }, nil)
		if !errors.Is(err, ErrDurableRuleReclaim) ||
			!reflect.DeepEqual(got, DurableRuleUnlinkResult{}) {
			t.Fatalf("before-unlink crash reported deletion: %+v %v", got, err)
		}
		dir := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
		if data, err := os.ReadFile(filepath.Join(dir, f.ruleHash+".json")); err != nil ||
			!bytes.Equal(data, f.ruleData) {
			t.Fatalf("pre-unlink crash lost bytes: %v", err)
		}
		checked, err := lease.InspectDurableRuleReclaim(ctx, key)
		if err != nil || checked.PreparedIntents != 1 ||
			checked.UnlinkedRules != 0 || checked.AllRulesUnlinked {
			t.Fatalf("durable prepared intent not resumable: %+v %v", checked, err)
		}
		result, err := lease.UnlinkNextDurableReclaimRule(ctx, key, checked)
		if err != nil || !result.RuleUnlinked {
			t.Fatalf("explicit resume after prepared intent failed: %+v %v", result, err)
		}
	})

	t.Run("after_unlink", func(t *testing.T) {
		f, lease, record, key, parent := makeDurableReclaimFixture(t)
		ctx := context.Background()
		before, err := f.store.Snapshot(ctx)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := lease.PrepareDurableRuleReclaim(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := lease.unlinkNextDurableReclaimRule(ctx, key, plan,
			nil, func() error { return errors.New("SIGKILL before directory fsync") })
		if !errors.Is(err, ErrDurableRuleReclaim) ||
			!reflect.DeepEqual(got, DurableRuleUnlinkResult{}) {
			t.Fatalf("after-unlink uncertain durability reported success: %+v %v", got, err)
		}
		checked, err := lease.InspectDurableRuleReclaim(ctx, key)
		if err != nil || checked.UnlinkedRules != 1 ||
			checked.PreparedIntents != 1 || !checked.AllRulesUnlinked ||
			checked.UnlinkedBytes != int64(len(f.ruleData)) {
			t.Fatalf("journal cannot authenticate crash subset: %+v %v", checked, err)
		}
		if _, err := os.Stat(filepath.Join(parent, dormantRuleReclaimPrefix+
			record.ArchiveSHA256, reclaimPlanFileName)); err != nil {
			t.Fatalf("crash removed original durable plan: %v", err)
		}
		after, err := f.store.Snapshot(ctx)
		if err != nil || !reflect.DeepEqual(before, after) {
			t.Fatalf("uncertain unlink changed live state: %+v %+v %v", before, after, err)
		}
	})
}

func TestDurableReclaimRefusesLateInodeAndLiveCASDrift(t *testing.T) {
	for _, fault := range []string{"inode_swap", "selection", "journal_abandon", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent := makeDurableReclaimFixture(t)
			ctx := context.Background()
			plan, err := lease.PrepareDurableRuleReclaim(ctx, key)
			if err != nil {
				t.Fatal(err)
			}
			scope := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
			leaf := filepath.Join(scope, f.ruleHash+".json")
			limited, cancel := context.WithCancel(ctx)
			defer cancel()
			got, err := lease.unlinkNextDurableReclaimRule(limited, key, plan,
				func() error {
					switch fault {
					case "inode_swap":
						copyPath := filepath.Join(scope, "replacement")
						if err := os.WriteFile(copyPath, f.ruleData, 0o400); err != nil {
							return err
						}
						return os.Rename(copyPath, leaf)
					case "selection":
						_, err := f.store.SetCurrentSelectionIntent(ctx,
							[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`))
						return err
					case "journal_abandon":
						return f.store.AbandonInertRestoreRecord(ctx, record.ID,
							record.CandidateScope, record.ArchiveSHA256)
					case "cancel":
						cancel()
					}
					return nil
				}, nil)
			if err == nil || !reflect.DeepEqual(got, DurableRuleUnlinkResult{}) {
				t.Fatalf("%s late mutation permitted unlink: %+v %v", fault, got, err)
			}
			if _, err := os.Lstat(leaf); err != nil {
				t.Fatalf("%s removed original rule: %v", fault, err)
			}
		})
	}
}

func TestDurableReclaimProcessHelper(t *testing.T) {
	if os.Getenv("KTUI_RECLAIM_UNLINK_HELPER") != "yes" {
		return
	}
	ctx := context.Background()
	s, err := storage.Open(ctx, os.Getenv("KTUI_RECLAIM_UNLINK_DB"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := strconv.ParseInt(os.Getenv("KTUI_RECLAIM_UNLINK_ID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(os.Getenv("KTUI_RECLAIM_UNLINK_KEY"))
	if err != nil || len(raw) != 32 {
		t.Fatal("bad test key")
	}
	var key [32]byte
	copy(key[:], raw)
	lease, err := AcquireInertRestoreResourceLease(ctx, s,
		os.Getenv("KTUI_RECLAIM_UNLINK_PARENT"), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	expected, err := lease.InspectDurableRuleReclaim(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = lease.unlinkNextDurableReclaimRule(ctx, key, expected, nil, func() error {
		if _, err := os.Stdout.Write([]byte("unlinked\n")); err != nil {
			return err
		}
		time.Sleep(3 * time.Minute)
		return nil
	})
	t.Fatal("SIGKILL fault helper unexpectedly survived")
}

func TestDurableReclaimSIGKILLAfterOneUnlinkCanReauthenticate(t *testing.T) {
	f, lease, record, key, parent := makeDurableReclaimFixture(t)
	ctx := context.Background()
	plan, err := lease.PrepareDurableRuleReclaim(ctx, key)
	if err != nil || plan.UnlinkedRules != 0 {
		t.Fatalf("durable plan: %+v %v", plan, err)
	}
	candidateParent := lease.candidate.parent
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	childCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestDurableReclaimProcessHelper$")
	cmd.Env = append(os.Environ(),
		"KTUI_RECLAIM_UNLINK_HELPER=yes",
		"KTUI_RECLAIM_UNLINK_DB="+f.store.Path(),
		"KTUI_RECLAIM_UNLINK_PARENT="+candidateParent,
		"KTUI_RECLAIM_UNLINK_ID="+strconv.FormatInt(record.ID, 10),
		"KTUI_RECLAIM_UNLINK_KEY="+hex.EncodeToString(key[:]))
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
	msg := make([]byte, len("unlinked\n"))
	if _, err := io.ReadFull(reader, msg); err != nil || string(msg) != "unlinked\n" {
		t.Fatalf("child did not reach fsync boundary: %q %v", msg, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	reaped = true
	reopened, err := AcquireInertRestoreResourceLease(ctx, f.store, candidateParent, record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.InspectDurableRuleReclaim(ctx, key)
	if err != nil || got.UnlinkedRules != 1 || got.PreparedIntents != 1 ||
		got.UnlinkedBytes != int64(len(f.ruleData)) || !got.AllRulesUnlinked {
		t.Fatalf("SIGKILL subset not authenticated: %+v %v", got, err)
	}
	dir := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
	if _, err := os.Stat(filepath.Join(dir, reclaimPlanFileName)); err != nil {
		t.Fatalf("durable manifest lost: %v", err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("SIGKILL changed live config: %+v %+v %v", before, after, err)
	}
}
