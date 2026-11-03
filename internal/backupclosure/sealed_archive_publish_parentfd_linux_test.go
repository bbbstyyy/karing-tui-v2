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

func newSealedPublishTestFile(t *testing.T) (string, *os.File, *os.File) {
	t.Helper()
	parentPath := t.TempDir()
	if err := os.Chmod(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := createLeasedSealedArchiveTemp(context.Background(), parentPath, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(bytes.Repeat([]byte("encrypted-payload"), 8)); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	parent, err := openSealedArchivePublicationParent(file)
	if err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = file.Close()
		_ = parent.Close()
	})
	return parentPath, parent, file
}

func TestSealedPublishPinnedParentNormalAndNoOverwrite(t *testing.T) {
	parentPath, parent, file := newSealedPublishTestFile(t)
	destination := filepath.Join(parentPath, "completed.ktbackup")
	tempPath := file.Name()
	linked, err := publishSealedArchiveAtPinnedParentProbed(parent, file, destination, nil, nil)
	if err != nil || !linked {
		t.Fatalf("valid fd-relative publication refused: linked=%t err=%v", linked, err)
	}
	if _, err := os.Lstat(tempPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("published temp name survived: %v", err)
	}
	got, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(got, bytes.Repeat([]byte("encrypted-payload"), 8)) {
		t.Fatalf("published data changed: %v", err)
	}
	info, err := os.Lstat(destination)
	if err != nil || !singleOwnedSealedFile(info) || info.Mode().Perm() != 0o600 {
		t.Fatalf("published inode not private and single-linked: %v", err)
	}

	// A second writer must never overwrite the completed archive.
	second, err := createLeasedSealedArchiveTemp(context.Background(), parentPath, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	secondParent, err := openSealedArchivePublicationParent(second)
	if err != nil {
		t.Fatal(err)
	}
	defer secondParent.Close()
	linked, err = publishSealedArchiveAtPinnedParentProbed(secondParent, second, destination, nil, nil)
	if linked || !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatalf("existing destination overwritten: linked=%t err=%v", linked, err)
	}
	if err := unlinkJustCreatedSealedTemp(secondParent, second); err != nil {
		t.Fatalf("known unpublished temp not safely cleaned: %v", err)
	}
	original, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(original, got) {
		t.Fatalf("existing destination contents replaced: %v", err)
	}
}

func TestSealedPublishRefusesReplacedTempName(t *testing.T) {
	parentPath, parent, file := newSealedPublishTestFile(t)
	tempPath := file.Name()
	other := filepath.Join(parentPath, sealedArchiveTemporaryPrefix+"moved-original")
	if err := os.Rename(tempPath, other); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tempPath, []byte("foreign-original-name"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked, err := publishSealedArchiveAtPinnedParentProbed(
		parent, file, filepath.Join(parentPath, "should-not-exist.ktbackup"), nil, nil)
	if linked || !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatalf("published swapped source inode: linked=%t err=%v", linked, err)
	}
	if err := unlinkJustCreatedSealedTemp(parent, file); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatalf("deleted foreign replacement during failed writer cleanup: %v", err)
	}
	foreign, err := os.ReadFile(tempPath)
	if err != nil || string(foreign) != "foreign-original-name" {
		t.Fatalf("foreign source entry removed or changed: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("original temp inode lost: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(parentPath, "should-not-exist.ktbackup")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong source was published: %v", err)
	}
}

func TestSealedPublishNeverUsesSubstitutedParentPath(t *testing.T) {
	for _, phase := range []string{"before-link", "after-link"} {
		for _, replacement := range []string{"directory", "symlink"} {
			t.Run(phase+"_"+replacement, func(t *testing.T) {
				root := t.TempDir()
				if err := os.Chmod(root, 0o700); err != nil {
					t.Fatal(err)
				}
				parentPath := filepath.Join(root, "parent")
				moved := filepath.Join(root, "moved-original")
				foreign := filepath.Join(root, "foreign")
				if err := os.Mkdir(parentPath, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(foreign, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(foreign, "sentinel"), []byte("untouched"), 0o600); err != nil {
					t.Fatal(err)
				}
				file, err := createLeasedSealedArchiveTemp(context.Background(), parentPath, 4096)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if _, err := file.Write([]byte("original encrypted content")); err != nil {
					t.Fatal(err)
				}
				if err := file.Sync(); err != nil {
					t.Fatal(err)
				}
				parent, err := openSealedArchivePublicationParent(file)
				if err != nil {
					t.Fatal(err)
				}
				defer parent.Close()
				tempName := filepath.Base(file.Name())
				destination := filepath.Join(parentPath, "published.ktbackup")
				injected := false
				var mutationErr error
				swap := func() {
					injected = true
					mutationErr = os.Rename(parentPath, moved)
					if mutationErr != nil {
						return
					}
					if replacement == "directory" {
						mutationErr = os.Rename(foreign, parentPath)
					} else {
						mutationErr = os.Symlink(foreign, parentPath)
					}
				}
				var beforeLink, afterLink func()
				if phase == "before-link" {
					beforeLink = swap
				} else {
					afterLink = swap
				}
				linked, publishErr := publishSealedArchiveAtPinnedParentProbed(
					parent, file, destination, beforeLink, afterLink)
				if !injected || mutationErr != nil || !linked ||
					!errors.Is(publishErr, ErrUnsafeSealedArchive) {
					t.Fatalf("swapped parent accepted: injected=%t linked=%t err=%v mutation=%v",
						injected, linked, publishErr, mutationErr)
				}
				// An already-linked, uncertain publication must not be
				// undone by guessed absolute-path cleanup. Both links
				// remain confined to the ORIGINAL pinned parent inode.
				for _, name := range []string{tempName, filepath.Base(destination)} {
					data, err := os.ReadFile(filepath.Join(moved, name))
					if err != nil || string(data) != "original encrypted content" {
						t.Fatalf("pinned original inode lost %s: %v", name, err)
					}
				}
				foreignPath := foreign
				if replacement == "directory" {
					foreignPath = parentPath
				}
				entries, err := os.ReadDir(foreignPath)
				if err != nil || len(entries) != 1 || entries[0].Name() != "sentinel" {
					t.Fatalf("foreign parent changed: entries=%v err=%v", entries, err)
				}
				sentinel, err := os.ReadFile(filepath.Join(foreignPath, "sentinel"))
				if err != nil || string(sentinel) != "untouched" {
					t.Fatalf("foreign sentinel modified: %v", err)
				}
			})
		}
	}
}
