//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The probe is private and only selects fixed phases. Its injected failures
// never expose archive contents or key material and may not grant restore
// authority. All post-allocation refusals must discard only their own scope.
func TestInertRestoreStageProbeFailClosedAtEveryBoundary(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sealedParent := testSealedDir(t, f)
	source := filepath.Join(sealedParent, "phase-probe.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)

	for _, rejectedAt := range []string{
		"source_preflight",
		"disk_reserve",
		"parent_lock",
		"parent_inventory",
		"create_scope",
		"scope_created",
		"scope_child_open",
		"scope_child_fd_opened",
		"scope_child_flock",
		"scope_child_lock_held",
		"scope_child_identity",
		"scope_child_identity_verified",
		"scope_locked",
		"cipher_copy",
		"cipher_before_openat",
		"cipher_target_fd_opened",
		"scope_sync",
		"parent_sync",
		"candidate_revalidation",
	} {
		t.Run(rejectedAt, func(t *testing.T) {
			var lastPhase string
			candidate, err := stageInertRestoreCandidate(
				context.Background(), source, parent, key,
				func(phase string) bool {
					lastPhase = phase
					return phase != rejectedAt
				},
			)
			if candidate != nil || !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
				t.Fatalf("injected boundary granted candidate: candidate=%t err=%v",
					candidate != nil, err)
			}
			if lastPhase != rejectedAt {
				t.Fatalf("probe stopped at %q, want %q", lastPhase, rejectedAt)
			}
			entries, listErr := os.ReadDir(parent)
			if listErr != nil || len(entries) != 0 {
				t.Fatalf("refused stage retained unknown or partial scope: count=%d err=%v",
					len(entries), listErr)
			}
			if _, statErr := os.Stat(source); statErr != nil {
				t.Fatalf("refused stage removed the source ciphertext: %v", statErr)
			}
		})
	}
	seen := make([]string, 0, 12)
	candidate, err := stageInertRestoreCandidate(
		context.Background(), source, parent, key,
		func(phase string) bool {
			seen = append(seen, phase)
			return true
		},
	)
	if err != nil {
		t.Fatalf("unmodified admission failed at %q: %v", lastOrEmptyStage(seen), err)
	}
	if lastOrEmptyStage(seen) != "candidate_revalidation" {
		t.Fatalf("successful admission skipped final preflight: %q", lastOrEmptyStage(seen))
	}
	if _, err := candidate.Verify(context.Background(), key); err != nil {
		t.Fatalf("phase-observed candidate failed independent verify: %v", err)
	}
	if err := candidate.Discard(context.Background()); err != nil {
		t.Fatalf("phase-observed candidate could not be explicitly discarded: %v", err)
	}
}

func lastOrEmptyStage(stages []string) string {
	if len(stages) == 0 {
		return "not_started"
	}
	return stages[len(stages)-1]
}
