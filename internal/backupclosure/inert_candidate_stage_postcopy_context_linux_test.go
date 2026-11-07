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

// After the O_EXCL-owned ciphertext copy completes, a cancelled Stage must
// not continue fsync, the final HMAC/SQLite preflight or candidate publication.
// The exact O_EXCL-created cipher must be cleaned without orphaning flocks.
func TestStageCancellationAfterCipherCopyBeforeReceiptRemovesOnlyOwnScope(t *testing.T) {
	_, source, parent, key, sealed := stageTargetCustodyFixture(t)
	for _, phase := range []string{
		"scope_sync", "parent_sync", "candidate_revalidation",
		"candidate_authenticated", "candidate_receipt",
	} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			injected := false
			var visited []string
			candidate, stageErr := stageInertRestoreCandidate(
				ctx, source, parent, key, func(at string) bool {
					visited = append(visited, at)
					if at == phase {
						injected = true
						cancel()
					}
					return true
				})
			if candidate != nil {
				_ = candidate.Close()
			}
			if !injected || candidate != nil ||
				!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) ||
				lastOrEmptyStage(visited) != phase {
				t.Fatalf("cancelled post-copy Stage published a candidate: phase=%s injected=%t err=%v last=%s",
					phase, injected, stageErr, lastOrEmptyStage(visited))
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("post-copy cancellation retained candidate files: phase=%s entries=%v err=%v",
					phase, entries, err)
			}
			reacquired, err := lockSealedArchiveParent(context.Background(), parent)
			if err != nil {
				t.Fatalf("post-copy cancellation retained parent flock at %s: %v", phase, err)
			}
			if err := reacquired.Close(); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(got, sealed) {
				t.Fatalf("post-copy cancellation changed encrypted source at %s: %v", phase, err)
			}
		})
	}
	healthy, err := StageInertRestoreCandidate(context.Background(), source, parent, key)
	if err != nil || healthy == nil {
		t.Fatalf("healthy Stage after cancelled post-copy attempts refused: %v", err)
	}
	defer healthy.Close()
	verified, err := healthy.Verify(context.Background(), key)
	if err != nil || !verified.SQLiteLogicalVerified || !verified.SchemaCatalogVerified ||
		verified.RestoreReady || verified.RestoreSupported {
		t.Fatalf("healthy candidate after cancelled post-copy attempts degraded: %+v %v",
			verified, err)
	}
	if err := healthy.Discard(context.Background()); err != nil {
		t.Fatalf("healthy candidate explicit Discard failed: %v", err)
	}
}

// Cancellation at the last authenticated checkpoint combined with an
// uncooperative same-UID ciphertext swap must never authorize the failed
// Stage cleanup to delete a foreign but byte-identical encrypted inode.
func TestStagePostAuthCancellationPreservesForeignCiphertext(t *testing.T) {
	root, source, parent, key, sealed := stageTargetCustodyFixture(t)
	foreign := filepath.Join(root, "post-auth-foreign.ktbackup")
	moved := filepath.Join(root, "post-auth-original.ktbackup")
	sentinel := filepath.Join(root, "post-auth-foreign-sentinel")
	if err := os.WriteFile(foreign, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	foreignInfo, err := os.Lstat(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var originalInfo os.FileInfo
	var scope string
	var mutationErr error
	injected := false
	candidate, stageErr := stageInertRestoreCandidate(
		ctx, source, parent, key, func(at string) bool {
			if at != "candidate_authenticated" {
				return true
			}
			injected = true
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 1 || !entries[0].IsDir() {
				mutationErr = ErrUnsafeInertRestoreCandidate
				cancel()
				return true
			}
			scope = filepath.Join(parent, entries[0].Name())
			target := filepath.Join(scope, inertRestoreCipherName)
			originalInfo, mutationErr = os.Lstat(target)
			if mutationErr == nil {
				mutationErr = os.Rename(target, moved)
			}
			if mutationErr == nil {
				mutationErr = os.Rename(foreign, target)
			}
			cancel()
			return true
		})
	if candidate != nil {
		_ = candidate.Close()
	}
	if !injected || mutationErr != nil || candidate != nil ||
		!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) || scope == "" {
		t.Fatalf("post-auth cancelled Stage accepted or corrupted foreign scope: injected=%t mutation=%v err=%v",
			injected, mutationErr, stageErr)
	}
	atOriginal, err := os.Lstat(moved)
	if err != nil || !os.SameFile(originalInfo, atOriginal) {
		t.Fatalf("cancelled Stage removed its moved source inode: %v", err)
	}
	atForeign, err := os.Lstat(filepath.Join(scope, inertRestoreCipherName))
	if err != nil || !os.SameFile(foreignInfo, atForeign) {
		t.Fatalf("cancelled Stage unlinked foreign candidate cipher inode: %v", err)
	}
	for _, path := range []string{source, moved, filepath.Join(scope, inertRestoreCipherName)} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, sealed) {
			t.Fatalf("cancelled Stage modified ciphertext at %s: %v", filepath.Base(path), err)
		}
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep" {
		t.Fatalf("cancelled Stage removed foreign sentinel: %v", err)
	}
	reacquired, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatalf("cancelled Stage leaked parent flock: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
	contender, err := openLockedInertRestoreCandidate(scope)
	if err != nil {
		t.Fatalf("cancelled Stage leaked child flock: %v", err)
	}
	if err := contender.Close(); err != nil {
		t.Fatal(err)
	}
}
