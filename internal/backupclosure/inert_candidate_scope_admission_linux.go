//go:build linux

package backupclosure

import (
	"context"
	"errors"
)

// inertScopeAdmissionCheckpoint distinguishes a refused test checkpoint from
// cancellation before the first mkdirat. This is STRICTLY diagnostic:
// production passes nil as the probe, retains its original public refusal,
// and neither retries a failed operation nor weakens an inode/lease guard.
func inertScopeAdmissionCheckpoint(
	ctx context.Context, phase string, probe func(string) bool,
) bool {
	if !inertScopeAdmissionContextActive(ctx, probe) {
		return false
	}
	if probe != nil && !probe(phase) {
		return false
	}
	return inertScopeAdmissionContextActive(ctx, probe)
}

func inertScopeAdmissionContextActive(ctx context.Context, probe func(string) bool) bool {
	if ctx != nil && ctx.Err() == nil {
		return true
	}
	if probe == nil {
		return false
	}
	// Only constant, non-sensitive labels enter a private test callback.
	// Never include an error string, archive path, file descriptor, or key.
	reason := "scope_admission_context_unavailable"
	if ctx != nil {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			reason = "scope_admission_context_deadline"
		case errors.Is(ctx.Err(), context.Canceled):
			reason = "scope_admission_context_cancelled"
		}
	}
	_ = probe(reason)
	return false
}
