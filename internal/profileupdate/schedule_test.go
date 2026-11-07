package profileupdate

import (
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestNextRefreshAtSkipsDisabledUnscheduledAndActiveSources(t *testing.T) {
	started := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	policy := DefaultSchedulePolicy()

	for _, mutate := range []func(*storage.ProfileSourceState){
		func(state *storage.ProfileSourceState) {
			state.Spec.Enabled = false
		},
		func(state *storage.ProfileSourceState) {
			state.Spec.UpdateInterval = 0
		},
		func(state *storage.ProfileSourceState) {
			state.ActiveUpdateID = "running-1"
		},
	} {
		state := scheduledSourceState("profile-a")
		mutate(&state)
		if _, scheduled, err := NextRefreshAt(state, started, policy); err != nil {
			t.Fatal(err)
		} else if scheduled {
			t.Fatalf("state unexpectedly scheduled: %+v", state)
		}
	}
}

func TestNextRefreshAtSpreadsNeverAttemptedProfilesDeterministically(t *testing.T) {
	started := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	policy := DefaultSchedulePolicy()
	state := scheduledSourceState("profile-a")

	first, scheduled, err := NextRefreshAt(state, started, policy)
	if err != nil {
		t.Fatal(err)
	}
	second, scheduledAgain, err := NextRefreshAt(state, started, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !scheduled || !scheduledAgain || !first.Equal(second) {
		t.Fatalf("stable startup schedule = %v/%v scheduled=%v/%v", first, second, scheduled, scheduledAgain)
	}
	if first.Before(started) || first.After(started.Add(policy.StartupSpread)) {
		t.Fatalf("startup spread = %v, want within [%v,%v]", first, started, started.Add(policy.StartupSpread))
	}

	other := scheduledSourceState("profile-b")
	otherAt, scheduled, err := NextRefreshAt(other, started, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !scheduled {
		t.Fatal("second source was not scheduled")
	}
	if first.Equal(otherAt) {
		t.Fatalf("distinct profile IDs received identical startup spread %v", first)
	}
}

func TestNextRefreshAtUsesSuccessIntervalAndSpreadsOverdueWork(t *testing.T) {
	started := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	policy := DefaultSchedulePolicy()
	state := scheduledSourceState("profile-a")

	success := started.Add(2 * time.Hour)
	state.LastSuccessAt = &success
	next, scheduled, err := NextRefreshAt(state, started, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !scheduled || !next.Equal(success.Add(state.Spec.UpdateInterval)) {
		t.Fatalf("success schedule = %v scheduled=%v", next, scheduled)
	}

	oldSuccess := started.Add(-24 * time.Hour)
	state.LastSuccessAt = &oldSuccess
	next, scheduled, err = NextRefreshAt(state, started, policy)
	if err != nil {
		t.Fatal(err)
	}
	if !scheduled || next.Before(started) || next.After(started.Add(policy.StartupSpread)) {
		t.Fatalf("overdue startup schedule = %v scheduled=%v", next, scheduled)
	}
}

func TestNextRefreshAtUsesBoundedStableFailureBackoff(t *testing.T) {
	started := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	policy := DefaultSchedulePolicy()
	state := scheduledSourceState("profile-a")
	attempt := started.Add(time.Hour)
	state.LastAttemptAt = &attempt

	for failures := uint32(1); failures <= 8; failures++ {
		state.ConsecutiveFailures = failures
		delay := failureBackoff(state.Spec.ProfileID, failures, policy)
		if delay < time.Duration(float64(policy.FailureBackoff)*0.8) {
			t.Fatalf("failure %d delay too small: %v", failures, delay)
		}
		if delay > policy.MaxBackoff {
			t.Fatalf("failure %d delay exceeds max: %v", failures, delay)
		}
		next, scheduled, err := NextRefreshAt(state, started, policy)
		if err != nil {
			t.Fatal(err)
		}
		if !scheduled || !next.Equal(attempt.Add(delay)) {
			t.Fatalf("failure %d next=%v delay=%v scheduled=%v", failures, next, delay, scheduled)
		}
		if again := failureBackoff(state.Spec.ProfileID, failures, policy); again != delay {
			t.Fatalf("failure %d jitter changed between evaluations: %v vs %v", failures, delay, again)
		}
	}

	if delay := failureBackoff("profile-a", 64, policy); delay > policy.MaxBackoff {
		t.Fatalf("large failure count delay = %v", delay)
	}
}

func TestNextRefreshAtRetryAfterDominatesLocalBackoff(t *testing.T) {
	started := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	state := scheduledSourceState("profile-a")
	attempt := started.Add(time.Hour)
	retryAfter := attempt.Add(4 * time.Hour)
	state.LastAttemptAt = &attempt
	state.ConsecutiveFailures = 1
	state.RetryAfterAt = &retryAfter

	next, scheduled, err := NextRefreshAt(state, started, DefaultSchedulePolicy())
	if err != nil {
		t.Fatal(err)
	}
	if !scheduled || !next.Equal(retryAfter) {
		t.Fatalf("Retry-After schedule = %v scheduled=%v, want %v", next, scheduled, retryAfter)
	}
}

func TestNextRefreshAtRejectsInvalidPolicyAndState(t *testing.T) {
	started := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	state := scheduledSourceState("profile-a")

	policy := DefaultSchedulePolicy()
	policy.FailureBackoff = 0
	if _, _, err := NextRefreshAt(state, started, policy); err == nil {
		t.Fatal("zero failure backoff was accepted")
	}
	if _, _, err := NextRefreshAt(state, time.Time{}, DefaultSchedulePolicy()); err == nil {
		t.Fatal("zero scheduler start time was accepted")
	}

	state.Spec.UpdateInterval = profile.MinUpdateInterval - time.Second
	if _, _, err := NextRefreshAt(state, started, DefaultSchedulePolicy()); err == nil {
		t.Fatal("invalid persisted source interval was accepted")
	}
}

func scheduledSourceState(profileID string) storage.ProfileSourceState {
	return storage.ProfileSourceState{
		Revision: 1,
		Spec: profile.SourceSpec{
			ProfileID:      profileID,
			Format:         profile.SourceFormatSingBox,
			LocationKind:   profile.SourceLocationURL,
			Location:       "https://example.com/subscription",
			Fetch:          profile.FetchPolicy{Mode: profile.FetchDirect},
			UpdateInterval: profile.DefaultUpdateInterval,
			Enabled:        true,
		},
	}
}
