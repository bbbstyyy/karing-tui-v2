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

// The source archive was authenticated before the candidate scope was
// reserved. A same-UID actor can rename its 0700 parent while the candidate
// writer is doing unrelated work, then substitute a foreign directory with
// the exact SAME valid ciphertext. Stage must keep reading the original
// parent and child fds, but fail closed rather than accept new custody.
func TestInertStageRefusesCopiedSourceInReplacedParent(t *testing.T) {
	for _, phase := range []string{"cipher_copy", "cipher_target_fd_opened"} {
		for _, replacement := range []string{"directory", "symlink"} {
			t.Run(phase+"_"+replacement, func(t *testing.T) {
				f := newFixture(t)
				f.commit(t, true)
				closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
				if err != nil {
					t.Fatal(err)
				}
				defer closure.Close()
				sourceParent := testSealedDir(t, f)
				source := filepath.Join(sourceParent, "original-source.ktbackup")
				key := testSealedKey(t)
				if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
					t.Fatal(err)
				}
				sourceBytes, err := os.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				candidateParent := newInertCandidateParent(t, f.stateRoot)
				moved := filepath.Join(f.stateRoot, "moved-source")
				foreign := filepath.Join(f.stateRoot, "foreign-source")
				if err := os.Mkdir(foreign, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(foreign, filepath.Base(source)), sourceBytes, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(foreign, "sentinel"), []byte("untouched"), 0o600); err != nil {
					t.Fatal(err)
				}
				injected := false
				var mutationErr error
				candidate, stageErr := stageInertRestoreCandidate(
					context.Background(), source, candidateParent, key,
					func(stage string) bool {
						if stage != phase {
							return true
						}
						injected = true
						mutationErr = os.Rename(sourceParent, moved)
						if mutationErr != nil {
							return true
						}
						if replacement == "directory" {
							mutationErr = os.Rename(foreign, sourceParent)
						} else {
							mutationErr = os.Symlink(foreign, sourceParent)
						}
						return true
					},
				)
				if candidate != nil {
					_ = candidate.Close()
				}
				if !injected || mutationErr != nil || candidate != nil ||
					!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
					t.Fatalf("source parent drift accepted: phase=%s injected=%t mutation=%v stage=%v",
						phase, injected, mutationErr, stageErr)
				}
				original, err := os.ReadFile(filepath.Join(moved, filepath.Base(source)))
				if err != nil || !bytes.Equal(original, sourceBytes) {
					t.Fatalf("original sealed source changed: %v", err)
				}
				foreignDir := foreign
				if replacement == "directory" {
					foreignDir = sourceParent
				}
				copyBytes, err := os.ReadFile(filepath.Join(foreignDir, filepath.Base(source)))
				if err != nil || !bytes.Equal(copyBytes, sourceBytes) {
					t.Fatalf("foreign authenticated source copy modified: %v", err)
				}
				sentinel, err := os.ReadFile(filepath.Join(foreignDir, "sentinel"))
				if err != nil || string(sentinel) != "untouched" {
					t.Fatalf("foreign sentinel modified: %v", err)
				}
				entries, err := os.ReadDir(candidateParent)
				if err != nil || len(entries) != 0 {
					t.Fatalf("failed Stage retained candidate or leaked ciphertext: entries=%v err=%v",
						entries, err)
				}
			})
		}
	}
}

// The original encrypted file inode may be moved beneath a newly created
// parent at the same pathname. File fstat and sha256 can still match; only
// the original parent inode lease can reject this change of custody.
func TestInertStageRejectsSameSourceInodeMovedUnderForeignParent(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sourceParent := testSealedDir(t, f)
	source := filepath.Join(sourceParent, "original-source.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		t.Fatal(err)
	}
	originalBytes, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	candidateParent := newInertCandidateParent(t, f.stateRoot)
	moved := filepath.Join(f.stateRoot, "moved-source")
	injected := false
	var mutationErr error
	candidate, stageErr := stageInertRestoreCandidate(
		context.Background(), source, candidateParent, key,
		func(stage string) bool {
			if stage != "cipher_copy" {
				return true
			}
			injected = true
			mutationErr = os.Rename(sourceParent, moved)
			if mutationErr != nil {
				return true
			}
			mutationErr = os.Mkdir(sourceParent, 0o700)
			if mutationErr != nil {
				return true
			}
			mutationErr = os.Rename(filepath.Join(moved, filepath.Base(source)), source)
			if mutationErr != nil {
				return true
			}
			mutationErr = os.WriteFile(filepath.Join(sourceParent, "sentinel"), []byte("keep"), 0o600)
			return true
		},
	)
	if candidate != nil {
		_ = candidate.Close()
	}
	if !injected || mutationErr != nil || candidate != nil ||
		!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("Stage accepted original inode in unrelated parent: injected=%t mutation=%v err=%v",
			injected, mutationErr, stageErr)
	}
	afterInfo, err := os.Lstat(source)
	if err != nil || !os.SameFile(sourceInfo, afterInfo) {
		t.Fatalf("source inode changed unexpectedly: %v", err)
	}
	afterBytes, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(afterBytes, originalBytes) {
		t.Fatalf("source bytes changed: %v", err)
	}
	sentinel, err := os.ReadFile(filepath.Join(sourceParent, "sentinel"))
	if err != nil || string(sentinel) != "keep" {
		t.Fatalf("substituted parent modified: %v", err)
	}
	entries, err := os.ReadDir(candidateParent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed Stage retained candidate: entries=%v err=%v", entries, err)
	}
}
