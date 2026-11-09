//go:build linux

package backupclosure

import (
	"context"
	"testing"
	"time"
)

func TestInertScopeAdmissionDistinguishesDeadlineAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  func() (context.Context, context.CancelFunc)
		want string
	}{
		{
			name: "cancelled",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			want: "scope_admission_context_cancelled",
		},
		{
			name: "deadline",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
			},
			want: "scope_admission_context_deadline",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, stop := tc.ctx()
			defer stop()
			var stages []string
			ok := inertScopeAdmissionCheckpoint(ctx, "create_scope", func(stage string) bool {
				stages = append(stages, stage)
				return true
			})
			if ok || len(stages) != 1 || stages[0] != tc.want {
				t.Fatalf("refused scope did not preserve bounded context class: %v", stages)
			}
			// Neither production (nil probe) nor a context refusal may
			// proceed to create_scope or the first mkdirat.
			if inertScopeAdmissionCheckpoint(ctx, "scope_before_mkdirat", nil) {
				t.Fatal("expired context reached mkdirat admission")
			}
		})
	}
}

func TestInertScopeAdmissionDetectsCancellationAtPreMkdirCheckpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var phases []string
	ok := inertScopeAdmissionCheckpoint(ctx, "scope_before_mkdirat", func(stage string) bool {
		phases = append(phases, stage)
		if stage == "scope_before_mkdirat" {
			cancel()
		}
		return true
	})
	if ok || len(phases) != 2 ||
		phases[0] != "scope_before_mkdirat" ||
		phases[1] != "scope_admission_context_cancelled" {
		t.Fatalf("cancelled post-checkpoint scope was admitted: %v", phases)
	}
}

func TestInertScopeAdmissionRejectsProbeWithoutFakeContextCause(t *testing.T) {
	var phases []string
	ok := inertScopeAdmissionCheckpoint(context.Background(), "create_scope", func(stage string) bool {
		phases = append(phases, stage)
		return false
	})
	if ok || len(phases) != 1 || phases[0] != "create_scope" {
		t.Fatalf("probe rejection was incorrectly presented as a timeout: %v", phases)
	}
	if !inertScopeAdmissionCheckpoint(context.Background(), "create_scope", nil) {
		t.Fatal("ordinary production scope admission was refused")
	}
}
