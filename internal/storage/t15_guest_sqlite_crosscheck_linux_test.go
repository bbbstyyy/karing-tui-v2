//go:build linux

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	guestBridgeDomain = "ktui-t15t23-disposable-ci-only"
	guestBridgeUUID   = "01234567-89ab-cdef-0123-456789abcdef"
	guestBridgeNonce  = "0123456789abcdef0123456789abcdef"
	guestBridgeCase   = "T15-prepared-journal"
)

// Only synthetic CI test data is read by the Python guest auditor.
// This is a cross-language schema/phase contract test, NOT a VM reboot,
// electrical power interruption, or live Core / recovery authorization.
type guestBridge struct {
	stateHome string
	witness   string
	dbPath    string
	script    string
}

func newGuestBridge(t *testing.T) guestBridge {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the guest-only read-only audit refuses root")
	}
	if _, err := exec.LookPath("python3"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("CI Python recovery-lab dependency is missing: %v", err)
		}
		t.Skip("python3 is needed for cross-language guest SQLite regression")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "xdg")
	app := filepath.Join(home, "karing-tui-v2")
	lab := filepath.Join(app, "recovery-lab")
	leaf := filepath.Join(lab, "ktui-powercut-disposable-"+guestBridgeNonce)
	for _, dir := range []string{home, app, lab, leaf} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// The guest v11 pre-stop witness must contain the same phase marker the
	// real non-root host VM stop tool would inspect; entirely synthetic here.
	marker := []byte("KTUI_T15T23_LAB_READY_V1\ncase=" + guestBridgeCase +
		"\nnonce=" + guestBridgeNonce + "\n")
	if err := os.WriteFile(filepath.Join(leaf, "ready-"+guestBridgeNonce+".txt"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "recovery_lab", "guest_reboot_audit.py"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("ADR 0129 guest auditor missing: %v", err)
	}
	return guestBridge{
		stateHome: home,
		witness:   leaf,
		dbPath:    filepath.Join(app, "state.db"),
		script:    script,
	}
}

func (g guestBridge) run(t *testing.T, mode, pinnedSHA string, wantSuccess bool) map[string]any {
	t.Helper()
	args := []string{g.script, "--mode", mode, "--domain", guestBridgeDomain,
		"--uuid", guestBridgeUUID, "--case", guestBridgeCase,
		"--nonce", guestBridgeNonce, "--witness", g.witness}
	if mode != "capture" {
		args = append(args, "--baseline-sha256", pinnedSHA)
	}
	cmd := exec.Command("python3", args...)
	cmd.Env = append(os.Environ(),
		"XDG_STATE_HOME="+g.stateHome,
		"KTUI_LAB_GUEST_AUDIT_ACK=GUEST_AUDIT:"+guestBridgeDomain+":"+
			guestBridgeUUID+":"+guestBridgeCase+":"+guestBridgeNonce)
	stdout, err := cmd.Output()
	if !wantSuccess {
		if err == nil {
			t.Fatalf("Python guest auditor accepted intentionally invalid phase: %s", stdout)
		}
		failure, ok := err.(*exec.ExitError)
		if !ok || !strings.Contains(string(failure.Stderr),
			"REFUSED: disposable guest SQLite post-boot audit is not trustworthy") {
			t.Fatalf("guest refusal test passed only because Python crashed or the tool could not execute: %v", err)
		}
		return nil
	}
	if err != nil {
		if failure, ok := err.(*exec.ExitError); ok {
			t.Fatalf("real v18 SQLite rejected by Python auditor (%s): %s", mode, failure.Stderr)
		}
		t.Fatalf("unable to run guest auditor: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(stdout, &report); err != nil {
		t.Fatalf("invalid guest audit output: %v", err)
	}
	if report["physical_power_loss_verified"] != false ||
		report["restore_authorized"] != false ||
		report["metadata_deletion_authorized"] != false {
		t.Fatalf("guest auditor promoted synthetic evidence to real recovery permission: %+v", report)
	}
	return report
}

func (g guestBridge) seedRealV18(t *testing.T, prepared bool) int64 {
	t.Helper()
	ctx := context.Background()
	db, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	base, err := db.PrepareApply(ctx, 0, []byte(`{"inbounds":[],"lab":"cross-language-baseline"}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.BeginActivation(ctx, base.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.BeginVerification(ctx, base.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.CommitApplied(ctx, base.ID, true); err != nil {
		t.Fatal(err)
	}
	if !prepared {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
		return 0
	}
	next, err := db.PrepareApply(ctx, 1, []byte(`{"inbounds":[],"lab":"never-activated"}`))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := db.Snapshot(ctx)
	if err != nil || snapshot.ActiveAttemptID == nil ||
		*snapshot.ActiveAttemptID != next.ID || snapshot.RecoveryRequired {
		t.Fatalf("real Go Store did not reach prepared-only journal boundary: %+v %v", snapshot, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return next.ID
}

func (g guestBridge) syntheticStopObservation(t *testing.T) {
	t.Helper()
	// Deliberately synthetic! These host-shaped records do NOT prove VM stop,
	// reboot, electrical outage or real Core recovery.
	marker, err := os.ReadFile(filepath.Join(g.witness, "ready-"+guestBridgeNonce+".txt"))
	if err != nil {
		t.Fatal(err)
	}
	markerDigest := sha256.Sum256(marker)
	base := map[string]any{
		"schema_version":                   1,
		"case":                             guestBridgeCase,
		"nonce":                            guestBridgeNonce,
		"domain":                           guestBridgeDomain,
		"domain_uuid":                      guestBridgeUUID,
		"marker_sha256":                    hex.EncodeToString(markerDigest[:]),
		"guest_boot_verified":              false,
		"physical_power_loss_verified":     false,
		"post_reboot_consistency_verified": false,
		"restore_authorized":               false,
		"metadata_deletion_authorized":     false,
	}
	for _, entry := range []struct {
		name   string
		status string
		stamp  string
	}{
		{"intent", "intent_before_forced_virtual_stop", "2026-01-01T00:00:00+00:00"},
		{"observation", "virtual_guest_forced_off_observed", "2026-01-01T00:00:01+00:00"},
	} {
		record := make(map[string]any, len(base)+2)
		for key, value := range base {
			record[key] = value
		}
		record["status"] = entry.status
		record["time_utc"] = entry.stamp
		raw, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(g.witness, entry.name+"-"+guestBridgeNonce+".json")
		if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func (g guestBridge) capture(t *testing.T) string {
	t.Helper()
	report := g.run(t, "capture", "", true)
	if report["status"] != "baseline_captured_no_reboot_claim" {
		t.Fatalf("invalid real SQLite baseline state: %+v", report)
	}
	sha, ok := report["baseline_sha256"].(string)
	if !ok || len(sha) != 64 {
		t.Fatalf("missing independently pinned baseline digest: %+v", report)
	}
	// The digest is pinned in the Go test and is not derived from the
	// possibly replaced current witness during the verification call.
	raw, err := os.ReadFile(filepath.Join(g.witness, "baseline-"+guestBridgeNonce+".json"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if sha != hex.EncodeToString(digest[:]) {
		t.Fatal("cross-language baseline hash did not match durable witness")
	}
	return sha
}

func TestGuestAuditCrossLanguageUsesRealV18CommittedStore(t *testing.T) {
	g := newGuestBridge(t)
	g.seedRealV18(t, false)
	before, err := os.ReadFile(g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sha := g.capture(t)
	g.syntheticStopObservation(t)
	report := g.run(t, "verify", sha, true)
	if report["status"] != "sqlite_subset_consistent_manual_review_only" ||
		report["guest_reboot_verified"] != false ||
		report["core_health_verified"] != false ||
		report["archive_hmac_verified"] != false {
		t.Fatalf("real Go SQLite was given stronger proof than a subset check: %+v", report)
	}
	after, err := os.ReadFile(g.dbPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("Python WAL-aware read-only audit modified original Go SQLite file: %v", err)
	}
	ctx := context.Background()
	db, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetCurrentSelectionIntent(ctx, []byte(`{"kind":"specific_node","profile_id":"p","node_id":"new"}`)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", sha, false)
}

func TestGuestAuditRealV18UnreconciledPreparedJournalMustHold(t *testing.T) {
	g := newGuestBridge(t)
	pendingID := g.seedRealV18(t, true)
	sha := g.capture(t)
	g.syntheticStopObservation(t)
	// The SQLite state matches exactly, but active prepared journal means
	// a virtual stop witness CANNOT be treated as successful recovery.
	g.run(t, "verify", sha, false)
	ctx := context.Background()
	db, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := db.RecoverInterrupted(ctx)
	if err != nil || recovery.NeedsReconcile ||
		len(recovery.InterruptedAttemptIDs) != 1 ||
		recovery.InterruptedAttemptIDs[0] != pendingID {
		t.Fatalf("explicit disposable-only prepared recovery failed: %+v %v", recovery, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// The journal was intentionally changed by recovery; a pre-cut
	// snapshot SHA cannot authenticate that different logical state.
	g.run(t, "verify", sha, false)
}

func TestGuestAuditRejectsForgedVirtualStopWitnessOnRealV18(t *testing.T) {
	g := newGuestBridge(t)
	g.seedRealV18(t, false)
	sha := g.capture(t)
	g.syntheticStopObservation(t)
	path := filepath.Join(g.witness, "observation-"+guestBridgeNonce+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var proof map[string]any
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	proof["domain_uuid"] = strings.Repeat("f", 8) + guestBridgeUUID[8:]
	replaced, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(replaced, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", sha, false)
}

// TestGuestAuditRealV18PreparedReconciliation is only a disposable
// SQLite/Python contract.  A fabricated host witness is NOT reboot proof.
func TestGuestAuditRealV18PreparedReconciliation(t *testing.T) {
	g := newGuestBridge(t)
	pendingID := g.seedRealV18(t, true)
	sha := g.capture(t)
	g.syntheticStopObservation(t)
	g.run(t, "verify", sha, false)

	ctx := context.Background()
	db, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := db.RecoverInterrupted(ctx)
	if err != nil || recovery.NeedsReconcile ||
		len(recovery.InterruptedAttemptIDs) != 1 ||
		recovery.InterruptedAttemptIDs[0] != pendingID {
		t.Fatalf("real prepared journal recovery is not bounded: %+v %v", recovery, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	report := g.run(t, "reconcile-verify", sha, true)
	if report["status"] != "prepared_journal_sqlite_subset_manual_review_only" ||
		report["prepared_journal_transition_checked"] != true ||
		report["guest_reboot_verified"] != false ||
		report["core_health_verified"] != false ||
		report["archive_hmac_verified"] != false {
		t.Fatalf("cross-language recovery audit overstated evidence: %+v", report)
	}
	after, err := os.ReadFile(g.dbPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("read-only reconciliation modified the actual Go DB: %v", err)
	}
	// The legacy strict equality contract remains deliberately invalid.
	g.run(t, "verify", sha, false)

	db, err = Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.SetCurrentSelectionIntent(ctx,
		[]byte("{\"kind\":\"specific_node\",\"profile_id\":\"p\",\"node_id\":\"drift\"}"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "reconcile-verify", sha, false)
}

// The Go DB is real, but the stop observation is purely synthetic. Verify
// that an intact v18 database cannot compensate for a missing durable host
// intent: v11 requires the entire phase->intent->observed-stop chain.
func TestGuestAuditRealV18RequiresDurableHostStopIntent(t *testing.T) {
	g := newGuestBridge(t)
	g.seedRealV18(t, false)
	pinned := g.capture(t)
	g.syntheticStopObservation(t)
	ok := g.run(t, "verify", pinned, true)
	if ok["host_stop_chain_checked"] != true ||
		ok["guest_reboot_verified"] != false ||
		ok["restore_authorized"] != false {
		t.Fatalf("synthetic host witness claimed unsupported recovery: %+v", ok)
	}
	intent := filepath.Join(g.witness, "intent-"+guestBridgeNonce+".json")
	if err := os.Remove(intent); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", pinned, false)
}

