//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

// The helper deliberately suspends before the off-scope directory fsync.
// It must be killed, not allowed to return a successful durable receipt.
func TestRetainedReclaimAttestationCrashHelper(t *testing.T) {
	if os.Getenv("KTUI_OFFSCOPE_ATTEST_HELPER") != "yes" {
		return
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, os.Getenv("KTUI_OFFSCOPE_ATTEST_DB"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, err := strconv.ParseInt(os.Getenv("KTUI_OFFSCOPE_ATTEST_ID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(os.Getenv("KTUI_OFFSCOPE_ATTEST_KEY"))
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid test key")
	}
	var key [32]byte
	copy(key[:], raw)
	lease, err := AcquireInertRestoreResourceLease(ctx, store,
		os.Getenv("KTUI_OFFSCOPE_ATTEST_PARENT"), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	sealed, err := lease.InspectSealedDurableReclaim(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = lease.attestSealedDurableReclaim(ctx, key, sealed, nil, func() error {
		if _, err := os.Stdout.Write([]byte("attested\n")); err != nil {
			return err
		}
		time.Sleep(3 * time.Minute)
		return nil
	})
	t.Fatal("helper returned without SIGKILL at off-scope fsync boundary")
}

func TestRetainedReclaimAttestationSIGKILLAndIndependentAudit(t *testing.T) {
	f, lease, record, key, parent, expected := makeFinishedRuleReclaimFixture(t)
	ctx := context.Background()
	sealed, err := lease.SealCompletedDurableReclaim(ctx, key, expected)
	if err != nil {
		t.Fatal(err)
	}
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	candidateParent := lease.candidate.parent
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	childCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestRetainedReclaimAttestationCrashHelper$")
	cmd.Env = append(os.Environ(),
		"KTUI_OFFSCOPE_ATTEST_HELPER=yes",
		"KTUI_OFFSCOPE_ATTEST_DB="+f.store.Path(),
		"KTUI_OFFSCOPE_ATTEST_PARENT="+candidateParent,
		"KTUI_OFFSCOPE_ATTEST_ID="+strconv.FormatInt(record.ID, 10),
		"KTUI_OFFSCOPE_ATTEST_KEY="+hex.EncodeToString(key[:]))
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
	message := make([]byte, len("attested\n"))
	if _, err := io.ReadFull(out, message); err != nil || !bytes.Equal(message, []byte("attested\n")) {
		t.Fatalf("child never reached off-scope file fsync: %q %v", message, err)
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
	proof, err := reopened.InspectRetainedReclaimAttestation(ctx, key)
	if err != nil || !proof.AttestationRetained || !proof.OriginalEvidenceRetained ||
		proof.RestoreSupported || proof.RestoreReady ||
		proof.ArchiveSHA256 != record.ArchiveSHA256 ||
		proof.CompletionSHA256 != sealed.CompletionSHA256 {
		t.Fatalf("new process cannot reauthenticate visible off-scope evidence: %+v %v", proof, err)
	}
	scope := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
	if entries, err := os.ReadDir(scope); err != nil || len(entries) != 3 {
		t.Fatalf("SIGKILL destroyed signed source metadata: %+v %v", entries, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("SIGKILL and independent audit changed live state: %v", err)
	}
	records, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(records) != 1 || records[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("crash reauthentication changed restore journal: %+v %v", records, err)
	}
}
