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

// Cancelling at the five existing, read-only Stage admission probes must
// prevent the next operation (source open/HMAC, disk reserve, parent flock,
// or inventory) instead of waiting for the later create_scope gate.
// The probe returns true: only the real context check can refuse the call.
func TestStageEarlyAdmissionCancellationBeforeScopeAllocation(t *testing.T) {
	_, source, parent, key, original := stageTargetCustodyFixture(t)
	for _, phase := range []string{
		"source_preflight",
		"source_inode_pinned",
		"disk_reserve",
		"parent_lock",
		"parent_inventory",
	} {
		t.Run(phase, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var phases []string
			injected := false
			candidate, stageErr := stageInertRestoreCandidate(
				ctx, source, parent, key, func(at string) bool {
					phases = append(phases, at)
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
				lastOrEmptyStage(phases) != phase {
				t.Fatalf("cancelled Stage crossed early admission boundary: phase=%s injected=%t err=%v phases=%v",
					phase, injected, stageErr, phases)
			}
			entries, err := os.ReadDir(parent)
			if err != nil || len(entries) != 0 {
				t.Fatalf("cancelled early Stage created a scope: phase=%s entries=%v err=%v",
					phase, entries, err)
			}
			reacquired, err := lockSealedArchiveParent(context.Background(), parent)
			if err != nil {
				t.Fatalf("early cancellation retained parent flock at %s: %v", phase, err)
			}
			if err := reacquired.Close(); err != nil {
				t.Fatal(err)
			}
			if got, err := os.ReadFile(source); err != nil || !bytes.Equal(got, original) {
				t.Fatalf("early cancellation modified source ciphertext at %s: %v", phase, err)
			}
		})
	}
	healthy, err := StageInertRestoreCandidate(context.Background(), source, parent, key)
	if err != nil || healthy == nil {
		t.Fatalf("healthy Stage after early cancellations rejected: %v", err)
	}
	defer healthy.Close()
	report, err := healthy.Verify(context.Background(), key)
	if err != nil || !report.SQLiteLogicalVerified || !report.SchemaCatalogVerified ||
		report.RestoreReady || report.RestoreSupported {
		t.Fatalf("healthy Stage/Verify after cancellation degraded: %+v %v", report, err)
	}
	if err := healthy.Discard(context.Background()); err != nil {
		t.Fatalf("healthy candidate explicit Discard refused: %v", err)
	}
}

// The short parent flock was acquired on an inode before the private
// parent_inventory checkpoint. A same-UID actor can move that inode and
// replace its pathname. Cancellation must release the ORIGINAL lease,
// without inspecting, creating or cleaning anything under the replacement.
func TestStageCancelledEarlyInventoryWithForeignParentPreservesBoth(t *testing.T) {
	root, source, parent, key, ciphertext := stageTargetCustodyFixture(t)
	moved := filepath.Join(root, "early-cancel-original-parent")
	sentinel := filepath.Join(parent, "foreign-parent-sentinel")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mutationErr error
	injected := false
	candidate, stageErr := stageInertRestoreCandidate(
		ctx, source, parent, key, func(phase string) bool {
			if phase != "parent_inventory" {
				return true
			}
			injected = true
			mutationErr = os.Rename(parent, moved)
			if mutationErr == nil {
				mutationErr = os.Mkdir(parent, 0o700)
			}
			if mutationErr == nil {
				mutationErr = os.WriteFile(sentinel, []byte("foreign-keep"), 0o600)
			}
			cancel()
			return true
		})
	if candidate != nil {
		_ = candidate.Close()
	}
	if !injected || mutationErr != nil || candidate != nil ||
		!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("cancelled Stage adopted replaced parent: injected=%t mutation=%v err=%v",
			injected, mutationErr, stageErr)
	}
	if entries, err := os.ReadDir(moved); err != nil || len(entries) != 0 {
		t.Fatalf("original parent unexpectedly gained a scope: entries=%v err=%v",
			entries, err)
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "foreign-keep" {
		t.Fatalf("cancelled Stage modified replacement parent: %v", err)
	}
	if got, err := os.ReadFile(source); err != nil || !bytes.Equal(got, ciphertext) {
		t.Fatalf("cancelled Stage changed original ciphertext: %v", err)
	}
	// The old inode was locked while the name was exchanged; after Stage
	// refusal another observer must be able to acquire its exclusive flock.
	reacquired, err := lockSealedArchiveParent(context.Background(), moved)
	if err != nil {
		t.Fatalf("cancelled Stage retained original parent flock: %v", err)
	}
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}

// A bounded native Linux descriptor check covers repeated real Stage
// cancellation at the source-fd and parent-flock lifetimes. This is short
// CI regression evidence, not the 72-hour/7-day/30-day reliability gate.
func TestStageEarlyCancelledAdmissionCyclesDoNotLeakFDs(t *testing.T) {
	_, source, parent, key, _ := stageTargetCustodyFixture(t)
	baseline, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("Linux proc fd inventory unavailable: %v", err)
	}
	const cycles = 32
	for n := 0; n < cycles; n++ {
		phase := "source_inode_pinned"
		if n%2 == 1 {
			phase = "parent_inventory"
		}
		ctx, cancel := context.WithCancel(context.Background())
		var injected bool
		candidate, stageErr := stageInertRestoreCandidate(
			ctx, source, parent, key, func(at string) bool {
				if at == phase {
					injected = true
					cancel()
				}
				return true
			})
		cancel()
		if candidate != nil {
			_ = candidate.Close()
		}
		if !injected || candidate != nil ||
			!errors.Is(stageErr, ErrUnsafeInertRestoreCandidate) {
			t.Fatalf("cycle %d cancelled Stage admitted candidate: phase=%s injected=%t err=%v",
				n, phase, injected, stageErr)
		}
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("early cancelled Stage cycles retained scopes: entries=%v err=%v", entries, err)
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) > len(baseline)+4 {
		t.Fatalf("early cancelled Stage leaked file descriptors: before=%d after=%d err=%v",
			len(baseline), len(after), err)
	}
	lock, err := lockSealedArchiveParent(context.Background(), parent)
	if err != nil {
		t.Fatalf("early cancelled Stage cycles retained parent flock: %v", err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
}
