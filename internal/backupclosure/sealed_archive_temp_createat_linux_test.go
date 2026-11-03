//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The test checkpoint fires after the leased-parent inode check, just
// before openat. It must be impossible to create into a substituted 0700
// directory or a symlink target through the old canonical pathname.
func TestLeasedSealedTempOpenatUsesOriginalParentAfterPathSwap(t *testing.T) {
	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(root, "parent")
			moved := filepath.Join(root, "moved-original")
			foreign := filepath.Join(root, "foreign")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, "sentinel"), []byte("unchanged"), 0o600); err != nil {
				t.Fatal(err)
			}
			lock, err := lockSealedArchiveParent(context.Background(), parent)
			if err != nil {
				t.Fatal(err)
			}
			defer lock.Close()
			injected := false
			var mutationErr error
			file, createErr := openSealedArchiveTempAtLeasedParentProbed(
				parent, lock, func() {
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
			if file != nil {
				_ = file.Close()
			}
			if !injected || mutationErr != nil || file != nil ||
				!errors.Is(createErr, ErrUnsafeSealedArchive) {
				t.Fatalf("adopted swapped staging parent: injected=%t file=%t err=%v mutation=%v",
					injected, file != nil, createErr, mutationErr)
			}
			// The newly created empty file may remain under the moved
			// original inode; failing safely is better than deleting a
			// possibly unrelated replacement by pathname.
			entries, err := os.ReadDir(moved)
			if err != nil || len(entries) != 1 ||
				!recognizedSealedArchiveTemporary(entries[0].Name()) {
				t.Fatalf("openat targeted wrong parent: entries=%v err=%v", entries, err)
			}
			created, err := os.Lstat(filepath.Join(moved, entries[0].Name()))
			if err != nil || !created.Mode().IsRegular() || created.Mode().Perm() != 0o600 {
				t.Fatalf("unexpected original orphan mode: %v", err)
			}
			foreignPath := foreign
			if replacement == "directory" {
				foreignPath = parent
			}
			foreignEntries, err := os.ReadDir(foreignPath)
			if err != nil || len(foreignEntries) != 1 || foreignEntries[0].Name() != "sentinel" {
				t.Fatalf("foreign replacement modified: entries=%v err=%v", foreignEntries, err)
			}
			sentinel, err := os.ReadFile(filepath.Join(foreignPath, "sentinel"))
			if err != nil || string(sentinel) != "unchanged" {
				t.Fatalf("foreign sentinel modified: %v", err)
			}
		})
	}
}

func TestLeasedSealedTempStageRefusesParentReplacedAfterInventory(t *testing.T) {
	for _, replacement := range []string{"directory", "symlink"} {
		t.Run(replacement, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0o700); err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(root, "parent")
			moved := filepath.Join(root, "moved-original")
			foreign := filepath.Join(root, "foreign")
			if err := os.Mkdir(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(foreign, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(foreign, "sentinel"), []byte("keep"), 0o600); err != nil {
				t.Fatal(err)
			}
			injected := false
			var mutationErr error
			file, createErr := createLeasedSealedArchiveTempProbed(
				context.Background(), parent, 1024, func() {
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
			if file != nil {
				_ = file.Close()
			}
			if !injected || mutationErr != nil || file != nil ||
				!errors.Is(createErr, ErrUnsafeSealedArchive) {
				t.Fatalf("staging created file inside foreign parent: injected=%t file=%t err=%v mutation=%v",
					injected, file != nil, createErr, mutationErr)
			}
			if entries, err := os.ReadDir(moved); err != nil || len(entries) != 0 {
				t.Fatalf("failed inventory-stage admission created an orphan: %v %v", entries, err)
			}
			foreignPath := foreign
			if replacement == "directory" {
				foreignPath = parent
			}
			if entries, err := os.ReadDir(foreignPath); err != nil ||
				len(entries) != 1 || entries[0].Name() != "sentinel" {
				t.Fatalf("failed creation changed replacement: %v %v", entries, err)
			}
			if sentinel, err := os.ReadFile(filepath.Join(foreignPath, "sentinel")); err != nil || string(sentinel) != "keep" {
				t.Fatalf("foreign sentinel changed: %v", err)
			}
		})
	}
}

// Cleanup must use the parent fd and identity of the actual new file, not
// merely a recognized name whose directory entry could be substituted.
func TestLeasedSealedTempCleanupRejectsReplacedName(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	file, err := openSealedArchiveTempAtLeasedParent(parent, lock)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	original := file.Name()
	shifted := filepath.Join(parent, sealedArchiveTemporaryPrefix+"shifted123")
	if err := os.Rename(original, shifted); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(original, []byte("foreign-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unlinkJustCreatedSealedTemp(lock, file); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatalf("cleanup deleted replacement of newly created file: %v", err)
	}
	foreignBytes, err := os.ReadFile(original)
	if err != nil || string(foreignBytes) != "foreign-data" {
		t.Fatalf("replacement data removed: %v", err)
	}
	if _, err := os.Stat(shifted); err != nil {
		t.Fatalf("original created file lost: %v", err)
	}
}

func TestLeasedSealedTempCreateAndCleanupHealthy(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	lock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	file, err := openSealedArchiveTempAtLeasedParent(parent, lock)
	if err != nil {
		_ = lock.Close()
		t.Fatal(err)
	}
	if !recognizedSealedArchiveTemporary(filepath.Base(file.Name())) {
		t.Fatalf("unrecognized new staging name: %q", file.Name())
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		!singleOwnedSealedFile(info) {
		t.Fatalf("invalid created inode: %v", err)
	}
	path := file.Name()
	if err := unlinkJustCreatedSealedTemp(lock, file); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("known staging file survived safe cleanup: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	// Public writer admission still holds a file flock across the
	// reservation and makes the regular interrupted-write reclaimable.
	leased, err := createLeasedSealedArchiveTemp(context.Background(), parent, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := leased.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := ReclaimAbandonedSealedArchives(context.Background(), parent)
	if err != nil || report.Reclaimed != 1 {
		t.Fatalf("failed to reclaim closed v2 temp: %+v %v", report, err)
	}
}
