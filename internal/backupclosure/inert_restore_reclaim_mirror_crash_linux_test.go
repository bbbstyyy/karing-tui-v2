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

// This subprocess fsyncs a complete mirrored proof inode, then remains alive
// before the parent directory fsync. A test SIGKILL deliberately interrupts
// the publication. Neither the child nor the caller may claim completion.
func TestReclaimEvidenceMirrorCrashHelper(t *testing.T) {
	if os.Getenv("KTUI_RECLAIM_MIRROR_HELPER") != "yes" {
		return
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, os.Getenv("KTUI_RECLAIM_MIRROR_DB"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, err := strconv.ParseInt(os.Getenv("KTUI_RECLAIM_MIRROR_ID"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(os.Getenv("KTUI_RECLAIM_MIRROR_KEY"))
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid test key")
	}
	var key [32]byte
	copy(key[:], raw)
	lease, err := AcquireInertRestoreResourceLease(ctx, store,
		os.Getenv("KTUI_RECLAIM_MIRROR_PARENT"), id, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	anchor, err := lease.InspectRetainedReclaimAttestation(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = lease.mirrorSealedReclaimEvidence(ctx, key, anchor, nil, func() error {
		if _, err := os.Stdout.Write([]byte("mirrored\n")); err != nil {
			return err
		}
		time.Sleep(3 * time.Minute)
		return nil
	})
	t.Fatal("mirror helper was not interrupted before directory fsync")
}

func TestReclaimEvidenceMirrorSIGKILLReacquireWithoutSourceDeletion(t *testing.T) {
	f, lease, record, key, parent, expected := makeMirroredReclaimFixture(t)
	ctx := context.Background()
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
	cmd := exec.CommandContext(childCtx, os.Args[0],
		"-test.run=^TestReclaimEvidenceMirrorCrashHelper$")
	cmd.Env = append(os.Environ(),
		"KTUI_RECLAIM_MIRROR_HELPER=yes",
		"KTUI_RECLAIM_MIRROR_DB="+f.store.Path(),
		"KTUI_RECLAIM_MIRROR_PARENT="+candidateParent,
		"KTUI_RECLAIM_MIRROR_ID="+strconv.FormatInt(record.ID, 10),
		"KTUI_RECLAIM_MIRROR_KEY="+hex.EncodeToString(key[:]))
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
	buf := make([]byte, len("mirrored\n"))
	if _, err := io.ReadFull(out, buf); err != nil || !bytes.Equal(buf, []byte("mirrored\n")) {
		t.Fatalf("child did not reach mirror file fsync: %q %v", buf, err)
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
	observed, err := reopened.InspectMirroredReclaimEvidence(ctx, key)
	if err != nil || !observed.MirrorRetained || !observed.OriginalProofsRetained ||
		observed.RestoreSupported || observed.RestoreReady ||
		observed.AttestationSHA256 != expected.AttestationSHA256 ||
		observed.RuleCount != expected.RuleCount {
		t.Fatalf("visible interrupted mirror cannot be independently verified: %+v %v", observed, err)
	}
	scope := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
	if entries, err := os.ReadDir(scope); err != nil || len(entries) != expected.RuleCount+2 {
		t.Fatalf("original signed proof files were lost after SIGKILL: %+v %v", entries, err)
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("interrupted mirror changed live state: %v", err)
	}
	journal, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(journal) != 1 || journal[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("interrupted mirror changed prepared journal: %+v %v", journal, err)
	}
}
