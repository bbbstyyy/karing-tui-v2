//go:build linux

package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Go DB is real v18 and the kernel ID is the REAL /proc Linux boot ID.
// No VM is stopped or restarted in CI, so a forged host running receipt must
// NOT be sufficient for a positive boot-epoch verdict.
func TestGuestKernelBootEpochRealV18RejectsUnchangedLinuxBoot(t *testing.T) {
	g := newGuestBridge(t)
	g.seedRealV18(t, false)
	pinned := g.capture(t)
	script := filepath.Join(filepath.Dir(g.script), "guest_kernel_boot_epoch.py")
	if _, err := os.Stat(script); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(),
		"XDG_STATE_HOME="+g.stateHome,
		"KTUI_LAB_GUEST_AUDIT_ACK=GUEST_AUDIT:"+guestBridgeDomain+":"+
			guestBridgeUUID+":"+guestBridgeCase+":"+guestBridgeNonce)
	run := func(mode, original string) ([]byte, error) {
		args := []string{script, "--mode", mode, "--case", guestBridgeCase,
			"--domain", guestBridgeDomain, "--uuid", guestBridgeUUID,
			"--nonce", guestBridgeNonce, "--witness", g.witness,
			"--baseline-sha256", pinned}
		if mode == "verify" {
			args = append(args, "--boot-epoch-sha256", original)
		}
		cmd := exec.Command("python3", args...)
		cmd.Env = env
		return cmd.Output()
	}
	before, err := os.ReadFile(g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	captured, err := run("capture", "")
	if err != nil {
		t.Fatalf("real Go v18 kernel-epoch capture failed: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(captured, &record); err != nil {
		t.Fatal(err)
	}
	original, ok := record["boot_epoch_sha256"].(string)
	if !ok || len(original) != 64 || record["kernel_boot_identity_changed_observed"] != false {
		t.Fatalf("invalid private kernel pre-stop witness response: %+v", record)
	}
	g.syntheticStopObservation(t) // explicitly SYNTHETIC, no virsh or VM action
	output, err := run("verify", original)
	if err == nil {
		t.Fatalf("unchanged real Linux /proc boot identity was accepted: %s", output)
	}
	exit, ok := err.(*exec.ExitError)
	if !ok || !strings.Contains(string(exit.Stderr),
		"REFUSED: disposable guest Linux boot identity check is not trustworthy") {
		t.Fatalf("unexpected non-protocol rejection: %v", err)
	}
	after, err := os.ReadFile(g.dbPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("kernel boot check modified real v18 SQLite main file: %v", err)
	}

	// Confirm a real Go Store can still open the identical state after the
	// negative read-only evidence check, with no migration or recovery.
	store, err := Open(context.Background(), g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}
