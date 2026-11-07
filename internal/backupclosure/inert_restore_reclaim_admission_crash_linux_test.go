//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetainedEvidenceAdmissionCrashHelper(t *testing.T) {
	if os.Getenv("KTUI_ADMISSION_CRASH_HELPER") != "yes" {
		return
	}
	root := os.Getenv("KTUI_ADMISSION_CRASH_PARENT")
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	name := reclaimAttestationPrefix + strings.Repeat("f", 64)
	held, err := beginRetainedEvidenceAdmission(context.Background(), dir, name, []byte("reserved"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.close()
	if _, err := os.Stdout.Write([]byte("locked\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Minute)
	t.Fatal("helper was not SIGKILLed during held state-directory advisory flock")
}

func TestRetainedEvidenceAdmissionSIGKILLReleasesOnlyKernelFlock(t *testing.T) {
	root := newPrivateAdmissionTestDir(t)
	childCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, os.Args[0],
		"-test.run=^TestRetainedEvidenceAdmissionCrashHelper$")
	cmd.Env = append(os.Environ(),
		"KTUI_ADMISSION_CRASH_HELPER=yes",
		"KTUI_ADMISSION_CRASH_PARENT="+root)
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
	ready := make([]byte, len("locked\n"))
	if _, err := io.ReadFull(out, ready); err != nil ||
		!bytes.Equal(ready, []byte("locked\n")) {
		t.Fatalf("subprocess did not hold cross-process directory flock: %q %v", ready, err)
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	name := reclaimMirrorPrefix + strings.Repeat("a", 64)
	if accepted, err := beginRetainedEvidenceAdmission(
		context.Background(), parent, name, []byte("new")); err == nil || accepted != nil {
		t.Fatalf("separate process bypassed existing held directory flock: %+v %v", accepted, err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	reaped = true
	guard, err := beginRetainedEvidenceAdmission(context.Background(), parent, name, []byte("new"))
	if err != nil {
		t.Fatalf("SIGKILL left stale cross-process state-directory lock: %v", err)
	}
	guard.close()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("admission created unexpected disk state or removed proofs: %+v %v", entries, err)
	}
	if _, err := os.Stat(filepath.Join(root, "reclaim-admission.lock")); !os.IsNotExist(err) {
		t.Fatalf("a forbidden PID/TTL lockfile was created: %v", err)
	}
}
