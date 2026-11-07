//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSealedRetentionInventoryUsesFreshLeasedDirectoryStream(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(parent, "published.ktbackup")
	if err := os.WriteFile(published, bytes.Repeat([]byte("p"), 128), 0o600); err != nil {
		t.Fatal(err)
	}
	temporary := filepath.Join(parent, sealedArchiveTemporaryPrefix+"abcDEF123")
	if err := os.WriteFile(temporary, []byte("unpublished encrypted temp"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	for attempt := 0; attempt < 3; attempt++ {
		report, candidates, inspectErr := inspectSealedArchiveDirectory(context.Background(), lock)
		if inspectErr != nil || report.Completed != 1 || report.Temporary != 1 ||
			len(candidates) != 1 || candidates[0].name != filepath.Base(temporary) {
			_ = closeAbandonedSealedArchives(candidates)
			t.Fatalf("pass %d silently skipped inventory: report=%+v count=%d err=%v",
				attempt, report, len(candidates), inspectErr)
		}
		if err := closeAbandonedSealedArchives(candidates); err != nil {
			t.Fatal(err)
		}
	}
	// An independent ReadDir must not advance the long-lived flock fd.
	stream, err := openLeasedSealedRetentionInventoryReader(lock)
	if err != nil {
		t.Fatal(err)
	}
	atLock, err := lock.Stat()
	if err != nil {
		t.Fatal(err)
	}
	atStream, err := stream.Stat()
	if err != nil || !os.SameFile(atLock, atStream) {
		t.Fatalf("directory stream left leased inode: %v", err)
	}
	entries, readErr := stream.ReadDir(-1)
	closeErr := stream.Close()
	if readErr != nil || closeErr != nil || len(entries) != 2 {
		t.Fatalf("fresh stream lost entries: entries=%d read=%v close=%v",
			len(entries), readErr, closeErr)
	}
	if _, err := openLeasedSealedRetentionInventoryReader(nil); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatalf("nil lease yielded a directory stream: %v", err)
	}
}

func TestSealedRetentionInventoryRejectsParentReplacementAfterReadDir(t *testing.T) {
	for _, kind := range []string{"temporary", "published"} {
		for _, replacement := range []string{"directory", "symlink"} {
			t.Run(kind+"_"+replacement, func(t *testing.T) {
				root := t.TempDir()
				if err := os.Chmod(root, 0o700); err != nil {
					t.Fatal(err)
				}
				parent := filepath.Join(root, "original-parent")
				moved := filepath.Join(root, "moved-parent")
				foreign := filepath.Join(root, "foreign-parent")
				if err := os.Mkdir(parent, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(foreign, 0o700); err != nil {
					t.Fatal(err)
				}
				name := sealedArchiveTemporaryPrefix + "abcDEF123"
				if kind == "published" {
					name = "published.ktbackup"
				}
				original := bytes.Repeat([]byte("o"), 128)
				forged := bytes.Repeat([]byte("f"), 128)
				if err := os.WriteFile(filepath.Join(parent, name), original, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(foreign, name), forged, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(foreign, "sentinel"), []byte("keep"), 0o600); err != nil {
					t.Fatal(err)
				}
				lock, err := lockSealedArchiveParent(context.Background(), parent)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				injected := false
				var mutationErr error
				report, candidates, inspectErr := inspectSealedArchiveDirectoryProbed(
					context.Background(), lock, func() {
						injected = true
						mutationErr = os.Rename(parent, moved)
						if mutationErr != nil {
							return
						}
						if replacement == "directory" {
							mutationErr = os.Rename(foreign, parent)
						} else {
							mutationErr = os.Symlink(foreign, parent)
						}
					},
				)
				if !injected || mutationErr != nil || len(candidates) != 0 ||
					!errors.Is(inspectErr, ErrUnsafeSealedArchive) {
					_ = closeAbandonedSealedArchives(candidates)
					t.Fatalf("swapped parent accepted: report=%+v candidates=%d err=%v injection=%v",
						report, len(candidates), inspectErr, mutationErr)
				}
				if originalBytes, err := os.ReadFile(filepath.Join(moved, name)); err != nil ||
					!bytes.Equal(originalBytes, original) {
					t.Fatalf("original file changed: %v", err)
				}
				foreignDir := foreign
				if replacement == "directory" {
					foreignDir = parent
				}
				if foreignBytes, err := os.ReadFile(filepath.Join(foreignDir, name)); err != nil ||
					!bytes.Equal(foreignBytes, forged) {
					t.Fatalf("foreign file changed: %v", err)
				}
				if sentinel, err := os.ReadFile(filepath.Join(foreignDir, "sentinel")); err != nil ||
					string(sentinel) != "keep" {
					t.Fatalf("foreign sentinel changed: %v", err)
				}
			})
		}
	}
}
