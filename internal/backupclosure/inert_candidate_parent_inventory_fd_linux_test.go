//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestInertParentInventoryUsesIndependentLeasedDirectoryStreams(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "candidates")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"AAAAAA01", "AAAAAA02"} {
		if err := os.Mkdir(filepath.Join(parent, inertRestoreCandidatePrefix+suffix), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	lock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()

	// Both calls must see the complete two-entry inventory. A ReadDir on
	// the long-lived flock fd would exhaust its shared directory offset.
	for attempt := 0; attempt < 3; attempt++ {
		count, err := inspectCandidateParent(context.Background(), lock)
		if err != nil || count != 2 {
			t.Fatalf("inventory %d returned count=%d err=%v", attempt, count, err)
		}
	}
	reader, err := openLockedInertCandidateParentInventoryReader(lock)
	if err != nil {
		t.Fatal(err)
	}
	onReader, err := reader.Stat()
	if err != nil {
		t.Fatal(err)
	}
	onLock, err := lock.Stat()
	if err != nil || !os.SameFile(onLock, onReader) {
		t.Fatalf("inventory stream left leased parent inode: %v", err)
	}
	entries, readErr := reader.ReadDir(-1)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(entries) != 2 {
		t.Fatalf("independent reader skipped entries: %d %v %v", len(entries), readErr, closeErr)
	}

	if err := os.Symlink(filepath.Join(parent, inertRestoreCandidatePrefix+"AAAAAA01"),
		filepath.Join(parent, inertRestoreCandidatePrefix+"AAAAAA03")); err != nil {
		t.Fatal(err)
	}
	if count, err := inspectCandidateParent(context.Background(), lock); count != 0 || !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("private-looking symlink accepted: count=%d err=%v", count, err)
	}
	if _, err := openLockedInertCandidateParentInventoryReader(nil); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("nil parent yielded inventory stream: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := openLockedInertCandidateParentInventoryReader(lock); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("closed parent yielded inventory stream: %v", err)
	}
}

// During the gap after ReadDir, a non-cooperating same-UID actor can
// substitute the private parent pathname. A new pathname-based directory
// scan or child check could see a different parent with an identical child
// name and mode. The stream and child open must still resolve via the flock
// fd, while the full admission refuses the changed canonical path.
func TestInertParentInventoryRejectsPostScanParentSubstitution(t *testing.T) {
	for _, replacement := range []string{"directory", "symlink"} {
		for _, empty := range []bool{false, true} {
			label := replacement + "_with_child"
			if empty {
				label = replacement + "_empty"
			}
			t.Run(label, func(t *testing.T) {
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
				name := inertRestoreCandidatePrefix + "ABCDEFGH"
				if !empty {
					if err := os.Mkdir(filepath.Join(parent, name), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(filepath.Join(foreign, name), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(foreign, name, "foreign-only"),
						[]byte("unchanged"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				lock, err := lockSealedArchiveParent(context.Background(), parent)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
				var injectedErr error
				injected := false
				count, err := inspectCandidateParentProbed(
					context.Background(), lock, func() {
						injected = true
						injectedErr = os.Rename(parent, moved)
						if injectedErr != nil {
							return
						}
						if replacement == "directory" {
							injectedErr = os.Rename(foreign, parent)
						} else {
							injectedErr = os.Symlink(foreign, parent)
						}
					},
				)
				if !injected || injectedErr != nil || count != 0 ||
					!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
					t.Fatalf("substituted parent accepted: injected=%t count=%d err=%v inject=%v",
						injected, count, err, injectedErr)
				}

				reader, err := openLockedInertCandidateParentInventoryReader(lock)
				if err != nil {
					t.Fatalf("cannot read original leased inode: %v", err)
				}
				entries, readErr := reader.ReadDir(-1)
				closeErr := reader.Close()
				expected := 1
				if empty {
					expected = 0
				}
				if readErr != nil || closeErr != nil || len(entries) != expected {
					t.Fatalf("reader escaped leased parent: count=%d err=%v close=%v",
						len(entries), readErr, closeErr)
				}
				if !empty {
					if entries[0].Name() != name {
						t.Fatalf("reader saw foreign child: %q", entries[0].Name())
					}
					fd, err := syscall.Openat(int(lock.Fd()), name,
						syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
					if err != nil {
						t.Fatal(err)
					}
					child := os.NewFile(uintptr(fd), filepath.Join(parent, name))
					onFD, statErr := child.Stat()
					closeErr := child.Close()
					original, origErr := os.Lstat(filepath.Join(moved, name))
					foreignDir, foreignErr := os.Lstat(filepath.Join(foreign, name))
					if replacement == "directory" {
						foreignDir, foreignErr = os.Lstat(filepath.Join(parent, name))
					}
					if statErr != nil || closeErr != nil || origErr != nil || foreignErr != nil ||
						!os.SameFile(onFD, original) || os.SameFile(onFD, foreignDir) {
						t.Fatalf("child fd escaped old parent: stat=%v close=%v original=%v foreign=%v",
							statErr, closeErr, origErr, foreignErr)
					}
					foreignCipher := filepath.Join(foreign, name, "foreign-only")
					if replacement == "directory" {
						foreignCipher = filepath.Join(parent, name, "foreign-only")
					}
					buf, err := os.ReadFile(foreignCipher)
					if err != nil || string(buf) != "unchanged" {
						t.Fatalf("foreign data touched: %v", err)
					}
				}
			})
		}
	}
}
