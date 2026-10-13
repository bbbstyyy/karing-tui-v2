//go:build linux

package backupclosure

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A real second process retains a file flock until SIGKILL, proving that
// process-exit recovery does not treat a live snapshot writer as an orphan.
func TestSealedArchiveCrashProcessHelper(t *testing.T) {
	if os.Getenv("KTUI_TEST_SEALED_CRASH_HELPER") != "yes" {
		return
	}
	parent := os.Getenv("KTUI_TEST_SEALED_PARENT")
	file, err := createLeasedSealedArchiveTemp(context.Background(), parent, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("partial encrypted archive")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stdout.Write([]byte("ready\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Minute)
	_ = file.Close()
}

func TestReclaimSealedArchiveKeepsActiveWriterAndSurvivesSIGKILL(t *testing.T) {
	f := newFixture(t)
	parent := testSealedDir(t, f)
	command := exec.Command(os.Args[0], "-test.run=^TestSealedArchiveCrashProcessHelper$")
	command.Env = append(os.Environ(), "KTUI_TEST_SEALED_CRASH_HELPER=yes", "KTUI_TEST_SEALED_PARENT="+parent)
	out, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	message, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || message != "ready\n" {
		t.Fatalf("child did not acquire leased staging file: %q %v", message, err)
	}
	ctx := context.Background()
	report, err := ReclaimAbandonedSealedArchives(ctx, parent)
	if err != nil || report.Active != 1 || report.Reclaimed != 0 || report.Temporary != 1 {
		t.Fatalf("active child was not protected: %+v %v", report, err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	killed = true
	report, err = ReclaimAbandonedSealedArchives(ctx, parent)
	if err != nil || report.Active != 0 || report.Reclaimed != 1 {
		t.Fatalf("SIGKILL orphan not reclaimed: %+v %v", report, err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("crashed child files persisted: %+v %v", entries, err)
	}
}

func TestSealedArchiveRetentionNeverRemovesPublishedArchives(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	parent := testSealedDir(t, f)
	key := testSealedKey(t)
	path := filepath.Join(parent, "important.ktbackup")
	receipt, err := closure.SealInertArchive(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoBackupScopes(t, f)
	temp, err := createLeasedSealedArchiveTemp(context.Background(), parent, 1234)
	if err != nil {
		t.Fatal(err)
	}
	name := temp.Name()
	if _, err := temp.Write([]byte("interrupted ciphertext")); err != nil {
		t.Fatal(err)
	}
	active, err := InspectSealedArchiveRetention(context.Background(), parent)
	if err != nil || active.Completed != 1 || active.Active != 1 ||
		active.CompletedBytes != receipt.Bytes {
		t.Fatalf("retention inventory omitted active or completed: %+v %v", active, err)
	}
	if err := temp.Close(); err != nil {
		t.Fatal(err)
	}
	result, err := ReclaimAbandonedSealedArchives(context.Background(), parent)
	if err != nil || result.Reclaimed != 1 || result.Completed != 1 {
		t.Fatalf("orphan recovery damaged inventory: %+v %v", result, err)
	}
	if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("orphan temporary file was not unlinked")
	}
	check, err := VerifyInertArchive(context.Background(), path, key)
	if err != nil || check != receipt {
		t.Fatalf("finished ciphertext was modified by cleanup: %+v %v", check, err)
	}
}

func TestSealedArchiveRetentionStopsAtCapacityWithoutPruning(t *testing.T) {
	f := newFixture(t)
	parent := testSealedDir(t, f)
	for index := 0; index < MaxRetainedSealedArchives; index++ {
		name := filepath.Join(parent, string(rune('a'+index))+".ktbackup")
		if err := os.WriteFile(name, bytes.Repeat([]byte{byte(index)}, 128), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	report, err := InspectSealedArchiveRetention(context.Background(), parent)
	if err != nil || report.Completed != MaxRetainedSealedArchives ||
		!report.AtCapacity || report.CompletedBytes != int64(MaxRetainedSealedArchives*128) {
		t.Fatalf("completed archive limit not enforced: %+v %v", report, err)
	}
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	if _, err := closure.SealInertArchive(context.Background(), filepath.Join(parent,
		"next.ktbackup"), testSealedKey(t)); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatalf("full retention inventory accepted a new archive: %v", err)
	}
	report, err = ReclaimAbandonedSealedArchives(context.Background(), parent)
	if err != nil || report.Completed != MaxRetainedSealedArchives || report.Reclaimed != 0 {
		t.Fatalf("completed archives were incorrectly pruned: %+v %v", report, err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != MaxRetainedSealedArchives {
		t.Fatalf("completed archives disappeared: %+v %v", entries, err)
	}
}

func TestSealedArchiveReclaimerFailsClosedForUnsafeEntries(t *testing.T) {
	for _, scenario := range []string{
		"legacy_unleased", "symlink", "foreign_mode", "hardlink", "oversized",
		"unknown_name", "published_hardlink", "too_many_temporary",
	} {
		t.Run(scenario, func(t *testing.T) {
			parent := t.TempDir()
			if err := os.Chmod(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			tempPath := filepath.Join(parent, sealedArchiveTemporaryPrefix+"abcdefgh9")
			switch scenario {
			case "legacy_unleased":
				tempPath = filepath.Join(parent, ".ktui-sealed-abcdefgh9")
				if err := os.WriteFile(tempPath, []byte("legacy"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("/etc/passwd", tempPath); err != nil {
					t.Fatal(err)
				}
			case "foreign_mode":
				if err := os.WriteFile(tempPath, []byte("partial"), 0o644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.WriteFile(tempPath, []byte("partial"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(tempPath, filepath.Join(parent, sealedArchiveTemporaryPrefix+"ijklmnop9")); err != nil {
					t.Fatal(err)
				}
			case "oversized":
				file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				err = file.Truncate(MaxSealedArchiveBytes + 1)
				_ = file.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "unknown_name":
				tempPath = filepath.Join(parent, "unknown.tmp")
				if err := os.WriteFile(tempPath, []byte("private"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "published_hardlink":
				if err := os.WriteFile(tempPath, bytes.Repeat([]byte("p"), 128), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(tempPath, filepath.Join(parent, "published.ktbackup")); err != nil {
					t.Fatal(err)
				}
			case "too_many_temporary":
				for index := 0; index <= MaxSealedArchiveTemporaryFiles; index++ {
					name := filepath.Join(parent, sealedArchiveTemporaryPrefix+
						fmt.Sprintf("%09d", index))
					if err := os.WriteFile(name, []byte("partial"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, err := os.ReadDir(parent)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReclaimAbandonedSealedArchives(context.Background(), parent); !errors.Is(err, ErrUnsafeSealedArchive) {
				t.Fatalf("unsafe scope accepted: %v", err)
			}
			after, err := os.ReadDir(parent)
			if err != nil || len(after) != len(before) {
				t.Fatalf("unsafe recovery deleted user files: %+v %v", after, err)
			}
		})
	}
}

func TestSealedArchiveParentLockHonorsCanceledContext(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Open(parent, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	guard := os.NewFile(uintptr(fd), parent)
	defer guard.Close()
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if _, err := ReclaimAbandonedSealedArchives(ctx, parent); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked parent lock ignored deadline: %v", err)
	}
}
