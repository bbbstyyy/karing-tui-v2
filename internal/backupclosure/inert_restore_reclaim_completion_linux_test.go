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

func makeFinishedRuleReclaimFixture(t *testing.T) (
	*fixture, *InertRestoreResourceLease,
	storage.InertRestorePreparation, [32]byte, string, DurableRuleReclaimProgress,
) {
	t.Helper()
	f, lease, record, key, parent := makeDurableReclaimFixture(t)
	ctx := context.Background()
	start, err := lease.PrepareDurableRuleReclaim(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	done, err := lease.UnlinkNextDurableReclaimRule(ctx, key, start)
	if err != nil || !done.RuleUnlinked {
		t.Fatalf("could not unlink private rule: %+v %v", done, err)
	}
	terminal, err := lease.InspectDurableRuleReclaim(ctx, key)
	if err != nil || !terminal.AllRulesUnlinked || terminal.PreparedIntents != terminal.ExpectedRules {
		t.Fatalf("fixture did not finish authenticated private leaf deletion: %+v %v", terminal, err)
	}
	return f, lease, record, key, parent, terminal
}

func TestSealedCompletionRequiresAllLeavesGoneAndRetainsEveryProof(t *testing.T) {
	f, lease, record, key, parent, expected := makeFinishedRuleReclaimFixture(t)
	ctx := context.Background()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result, err := lease.SealCompletedDurableReclaim(ctx, key, expected)
	if err != nil || !result.CompletionSealed || !result.MetadataRetained ||
		!result.RequiresRevalidation || result.RestoreSupported || result.RestoreReady ||
		result.ArchiveSHA256 != record.ArchiveSHA256 ||
		result.InventorySHA256 != record.InventorySHA256 ||
		result.PlanSHA256 != expected.PlanSHA256 ||
		result.RuleCount != 1 || result.UnlinkedBytes != int64(len(f.ruleData)) ||
		!validLowerSHA(result.CompletionSHA256) {
		t.Fatalf("terminal evidence not safely sealed: %+v %v", result, err)
	}
	dir := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("seal deleted provenance metadata or retained rules: %+v %v", entries, err)
	}
	for _, name := range []string{reclaimPlanFileName, reclaimIntentPrefix + "000", reclaimCompletionName} {
		info, err := os.Lstat(filepath.Join(dir, name))
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o400 {
			t.Fatalf("missing/private proof: %s %+v %v", name, info, err)
		}
	}
	check, err := lease.InspectSealedDurableReclaim(ctx, key)
	if err != nil || !reflect.DeepEqual(check, result) {
		t.Fatalf("terminal reader could not independently authenticate: %+v %v", check, err)
	}
	if prior, err := lease.InspectDurableRuleReclaim(ctx, key); !errors.Is(err, ErrDurableRuleReclaim) ||
		!reflect.DeepEqual(prior, DurableRuleReclaimProgress{}) {
		t.Fatalf("pre-completion reader adopted terminal proof: %+v %v", prior, err)
	}
	if repeat, err := lease.SealCompletedDurableReclaim(ctx, key, expected); err == nil ||
		!reflect.DeepEqual(repeat, CompletedRuleReclaimReceipt{}) {
		t.Fatalf("completion marker overwritten: %+v %v", repeat, err)
	}
	if result, err := lease.UnlinkNextDurableReclaimRule(ctx, key, expected); err == nil ||
		!reflect.DeepEqual(result, DurableRuleUnlinkResult{}) {
		t.Fatalf("sealed scope allowed further rule deletes: %+v %v", result, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("completion changed live state: %+v -> %+v %v", before, after, err)
	}
	journal, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(journal) != 1 || journal[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("terminal seal changed v18 journal: %+v %v", journal, err)
	}
	if _, err := os.Stat(filepath.Join(f.stateRoot, "core", "rule-sets", "sha256", f.ruleHash+".json")); err != nil {
		t.Fatalf("completion changed active rule: %v", err)
	}
}

func TestSealCompletionRejectsIncompleteOrForgedState(t *testing.T) {
	for _, fault := range []string{"incomplete", "wrong_archive", "wrong_plan", "wrong_bytes",
		"wrong_count", "not_all", "wrong_key", "canceled", "closed", "missing_intent",
		"unexpected_leaf", "public_scope"} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent, expected := makeFinishedRuleReclaimFixture(t)
			ctx := context.Background()
			dir := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
			var mutation error
			useKey := key
			switch fault {
			case "incomplete":
				expected.UnlinkedRules--
			case "wrong_archive":
				expected.ArchiveSHA256 = strings.Repeat("0", 64)
			case "wrong_plan":
				expected.PlanSHA256 = strings.Repeat("0", 64)
			case "wrong_bytes":
				expected.UnlinkedBytes++
			case "wrong_count":
				expected.PreparedIntents--
			case "not_all":
				expected.AllRulesUnlinked = false
			case "wrong_key":
				useKey[0] ^= 0xa7
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				mutation = lease.Close()
			case "missing_intent":
				mutation = os.Remove(filepath.Join(dir, reclaimIntentPrefix+"000"))
			case "unexpected_leaf":
				mutation = os.WriteFile(filepath.Join(dir, f.ruleHash+".json"), f.ruleData, 0o400)
			case "public_scope":
				mutation = os.Chmod(dir, 0o755)
			}
			if mutation != nil {
				t.Fatal(mutation)
			}
			receipt, err := lease.SealCompletedDurableReclaim(ctx, useKey, expected)
			if err == nil || !reflect.DeepEqual(receipt, CompletedRuleReclaimReceipt{}) {
				t.Fatalf("unsafe %s got sealed: %+v %v", fault, receipt, err)
			}
			if _, err := os.Lstat(filepath.Join(dir, reclaimCompletionName)); !os.IsNotExist(err) {
				t.Fatalf("refused completion %s wrote a marker: %v", fault, err)
			}
		})
	}
}

func TestSealedCompletionReaderRejectsTamperWithoutDeletingEvidence(t *testing.T) {
	for _, fault := range []string{"wrong_key", "marker_tamper", "marker_symlink",
		"plan_missing", "intent_missing", "extra_rule", "extra_unknown",
		"public_root", "selection", "journal_abandon", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent, expected := makeFinishedRuleReclaimFixture(t)
			ctx := context.Background()
			if _, err := lease.SealCompletedDurableReclaim(ctx, key, expected); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
			useKey := key
			var mutation error
			switch fault {
			case "wrong_key":
				useKey[0] ^= 0x71
			case "marker_tamper":
				name := filepath.Join(dir, reclaimCompletionName)
				mutation = os.Chmod(name, 0o600)
				if mutation == nil {
					mutation = os.WriteFile(name, []byte("not signed"), 0o600)
				}
				if mutation == nil {
					mutation = os.Chmod(name, 0o400)
				}
			case "marker_symlink":
				name := filepath.Join(dir, reclaimCompletionName)
				mutation = os.Remove(name)
				if mutation == nil {
					mutation = os.Symlink("/etc/passwd", name)
				}
			case "plan_missing":
				mutation = os.Remove(filepath.Join(dir, reclaimPlanFileName))
			case "intent_missing":
				mutation = os.Remove(filepath.Join(dir, reclaimIntentPrefix+"000"))
			case "extra_rule":
				mutation = os.WriteFile(filepath.Join(dir, f.ruleHash+".json"), f.ruleData, 0o400)
			case "extra_unknown":
				mutation = os.WriteFile(filepath.Join(dir, "unknown"), []byte("x"), 0o600)
			case "public_root":
				mutation = os.Chmod(parent, 0o755)
			case "selection":
				_, mutation = f.store.SetCurrentSelectionIntent(ctx, []byte(`{"kind":"specific_node","profile_id":"p","node_id":"changed"}`))
			case "journal_abandon":
				mutation = f.store.AbandonInertRestoreRecord(ctx, record.ID, record.CandidateScope, record.ArchiveSHA256)
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if mutation != nil {
				t.Fatal(mutation)
			}
			receipt, err := lease.InspectSealedDurableReclaim(ctx, useKey)
			if err == nil || !reflect.DeepEqual(receipt, CompletedRuleReclaimReceipt{}) {
				t.Fatalf("reader accepted %s: %+v %v", fault, receipt, err)
			}
		})
	}
}

func TestSealCompletionRejectsLateDriftAndReportsUncertainCommit(t *testing.T) {
	for _, fault := range []string{"unknown_entry", "late_selection", "late_abandon", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent, expected := makeFinishedRuleReclaimFixture(t)
			ctx := context.Background()
			scoped, cancel := context.WithCancel(ctx)
			defer cancel()
			receipt, err := lease.sealCompletedDurableReclaim(scoped, key, expected, func() error {
				switch fault {
				case "unknown_entry":
					return os.WriteFile(filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256,
						"late"), []byte("bad"), 0o600)
				case "late_selection":
					_, err := f.store.SetCurrentSelectionIntent(ctx, []byte(`{"kind":"specific_node","profile_id":"p","node_id":"other"}`))
					return err
				case "late_abandon":
					return f.store.AbandonInertRestoreRecord(ctx, record.ID, record.CandidateScope, record.ArchiveSHA256)
				case "cancel":
					cancel()
				}
				return nil
			}, nil)
			if err == nil || !reflect.DeepEqual(receipt, CompletedRuleReclaimReceipt{}) {
				t.Fatalf("late drift %s succeeded: %+v %v", fault, receipt, err)
			}
			if _, err := os.Lstat(filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256,
				reclaimCompletionName)); !os.IsNotExist(err) {
				t.Fatalf("%s committed completion despite changed state: %v", fault, err)
			}
		})
	}
	t.Run("after_file_fsync", func(t *testing.T) {
		_, lease, record, key, parent, expected := makeFinishedRuleReclaimFixture(t)
		ctx := context.Background()
		receipt, err := lease.sealCompletedDurableReclaim(ctx, key, expected, nil,
			func() error { return errors.New("SIGKILL before directory fsync") })
		if !errors.Is(err, ErrCompletedRuleReclaim) ||
			!reflect.DeepEqual(receipt, CompletedRuleReclaimReceipt{}) {
			t.Fatalf("uncertain completion reported success: %+v %v", receipt, err)
		}
		dir := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
		for _, name := range []string{reclaimPlanFileName, reclaimIntentPrefix + "000", reclaimCompletionName} {
			if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
				t.Fatalf("post-publication fault lost proof %s: %v", name, err)
			}
		}
		if observed, err := lease.InspectSealedDurableReclaim(ctx, key); err != nil ||
			!observed.CompletionSealed {
			t.Fatalf("revalidation of visible uncertain marker failed: %+v %v", observed, err)
		}
	})
}

func TestReclaimCompletionSubprocessHelper(t *testing.T) {
	if os.Getenv("KTUI_RECLAIM_COMPLETION_HELPER") != "yes" {
		return
	}
	ctx := context.Background()
	s, err := storage.Open(ctx, os.Getenv("KTUI_RECLAIM_COMPLETION_DB"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := strconv.ParseInt(os.Getenv("KTUI_RECLAIM_COMPLETION_ID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(os.Getenv("KTUI_RECLAIM_COMPLETION_KEY"))
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid test key")
	}
	var key [32]byte
	copy(key[:], raw)
	lease, err := AcquireInertRestoreResourceLease(ctx, s,
		os.Getenv("KTUI_RECLAIM_COMPLETION_PARENT"), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	expected, err := lease.InspectDurableRuleReclaim(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = lease.sealCompletedDurableReclaim(ctx, key, expected, nil, func() error {
		if _, err := os.Stdout.Write([]byte("sealed\n")); err != nil {
			return err
		}
		time.Sleep(3 * time.Minute)
		return nil
	})
	t.Fatal("subprocess was not SIGKILLed after marker publication")
}

func TestReclaimCompletionSIGKILLAndIndependentNewLease(t *testing.T) {
	f, lease, record, key, parent, expected := makeFinishedRuleReclaimFixture(t)
	ctx := context.Background()
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
	cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestReclaimCompletionSubprocessHelper$")
	cmd.Env = append(os.Environ(),
		"KTUI_RECLAIM_COMPLETION_HELPER=yes",
		"KTUI_RECLAIM_COMPLETION_DB="+f.store.Path(),
		"KTUI_RECLAIM_COMPLETION_PARENT="+candidateParent,
		"KTUI_RECLAIM_COMPLETION_ID="+strconv.FormatInt(record.ID, 10),
		"KTUI_RECLAIM_COMPLETION_KEY="+hex.EncodeToString(key[:]))
	out, err := cmd.StdoutPipe()
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
	message := make([]byte, len("sealed\n"))
	if _, err := io.ReadFull(out, message); err != nil || !bytes.Equal(message, []byte("sealed\n")) {
		t.Fatalf("child never reached marker fsync boundary: %q %v", message, err)
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
	result, err := reopened.InspectSealedDurableReclaim(ctx, key)
	if err != nil || !result.CompletionSealed || !result.MetadataRetained ||
		result.PlanSHA256 != expected.PlanSHA256 || result.RuleCount != 1 ||
		result.RestoreReady || result.RestoreSupported {
		t.Fatalf("post-SIGKILL separate lease refused evidence: %+v %v", result, err)
	}
	dir := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 3 {
		t.Fatalf("crash removed private terminal evidence: %+v %v", entries, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("SIGKILL terminal seal changed live config: %+v -> %+v %v", before, after, err)
	}
}
