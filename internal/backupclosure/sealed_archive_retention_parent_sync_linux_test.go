//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The reclaimer has already unlinked the one known orphan before the
// durability barrier. An uncooperative same-UID actor can replace the
// canonical parent at that point, so the fsync must never reopen it by name.
func TestSealedReclaimPostUnlinkSyncRejectsParentSubstitution(t *testing.T) {
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
			orphanName := sealedArchiveTemporaryPrefix + "abcdef1234"
			orphan := filepath.Join(parent, orphanName)
			if err := os.WriteFile(orphan, []byte("abandoned encrypted staging"), 0o600); err != nil {
				t.Fatal(err)
			}

			var mutationErr error
			injected := false
			report, reclaimErr := reclaimAbandonedSealedArchivesProbed(
				context.Background(), parent, func() {
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
			if !injected || mutationErr != nil || report.Reclaimed != 1 ||
				!errors.Is(reclaimErr, ErrUnsafeSealedArchive) {
				t.Fatalf("reclaimer accepted swapped fsync: injected=%t report=%+v err=%v mutation=%v",
					injected, report, reclaimErr, mutationErr)
			}
			if entries, err := os.ReadDir(moved); err != nil || len(entries) != 0 {
				t.Fatalf("pinned original parent retained orphan: entries=%v err=%v", entries, err)
			}
			sentinelPath := filepath.Join(foreign, "sentinel")
			if replacement == "directory" {
				sentinelPath = filepath.Join(parent, "sentinel")
			}
			if data, err := os.ReadFile(sentinelPath); err != nil || string(data) != "unchanged" {
				t.Fatalf("foreign parent was modified: %v", err)
			}
			if replacement == "symlink" {
				if info, err := os.Lstat(parent); err != nil || info.Mode()&os.ModeSymlink == 0 {
					t.Fatalf("foreign symlink changed: %v", err)
				}
			}
		})
	}
}

// A healthy private parent remains usable, and the fixed hook runs only if
// one or more unlocked, single-linked v2 temporary files were unlinked.
func TestSealedReclaimLeasedParentSyncHealthyAndNoop(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	called := false
	report, err := reclaimAbandonedSealedArchivesProbed(
		context.Background(), parent, func() { called = true },
	)
	if err != nil || report.Reclaimed != 0 || called {
		t.Fatalf("empty inventory ran destructive sync checkpoint: report=%+v err=%v hook=%t",
			report, err, called)
	}
	orphan := filepath.Join(parent, sealedArchiveTemporaryPrefix+"abcDEF123")
	if err := os.WriteFile(orphan, []byte("incomplete encrypted archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = reclaimAbandonedSealedArchivesProbed(
		context.Background(), parent, func() { called = true },
	)
	if err != nil || report.Reclaimed != 1 || !called {
		t.Fatalf("valid orphan not reclaimed: report=%+v err=%v hook=%t", report, err, called)
	}
	if _, err := os.Lstat(orphan); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan still present after parent fd fsync: %v", err)
	}
}
