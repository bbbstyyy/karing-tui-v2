package profileupdate

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

const (
	DefaultFailureBackoff = time.Minute
	DefaultMaxBackoff     = time.Hour
	DefaultStartupSpread  = 2 * time.Minute
)

type SchedulePolicy struct {
	FailureBackoff time.Duration
	MaxBackoff     time.Duration
	StartupSpread  time.Duration
}

func DefaultSchedulePolicy() SchedulePolicy {
	return SchedulePolicy{
		FailureBackoff: DefaultFailureBackoff,
		MaxBackoff:     DefaultMaxBackoff,
		StartupSpread:  DefaultStartupSpread,
	}
}

func (p SchedulePolicy) Validate() error {
	if p.FailureBackoff <= 0 {
		return errors.New("profile schedule failure backoff must be positive")
	}
	if p.MaxBackoff < p.FailureBackoff {
		return errors.New("profile schedule max backoff must not be smaller than base backoff")
	}
	if p.StartupSpread < 0 {
		return errors.New("profile schedule startup spread must not be negative")
	}
	return nil
}

func NextRefreshAt(
	state storage.ProfileSourceState,
	schedulerStartedAt time.Time,
	policy SchedulePolicy,
) (time.Time, bool, error) {
	if err := policy.Validate(); err != nil {
		return time.Time{}, false, err
	}
	if schedulerStartedAt.IsZero() {
		return time.Time{}, false, errors.New("profile scheduler start time is required")
	}
	if err := state.Spec.Validate(); err != nil {
		return time.Time{}, false, err
	}
	if !state.Spec.Enabled || state.Spec.UpdateInterval == 0 || state.ActiveUpdateID != "" {
		return time.Time{}, false, nil
	}

	var candidate time.Time
	switch {
	case state.ConsecutiveFailures > 0 && state.LastAttemptAt != nil:
		candidate = state.LastAttemptAt.Add(
			failureBackoff(
				state.Spec.ProfileID,
				state.ConsecutiveFailures,
				policy,
			),
		)
	case state.LastSuccessAt != nil:
		candidate = state.LastSuccessAt.Add(state.Spec.UpdateInterval)
	case state.LastAttemptAt != nil:
		candidate = state.LastAttemptAt.Add(state.Spec.UpdateInterval)
	default:
		candidate = schedulerStartedAt.Add(
			stableSpread(
				state.Spec.ProfileID,
				0,
				policy.StartupSpread,
			),
		)
	}

	if state.RetryAfterAt != nil && state.RetryAfterAt.After(candidate) {
		candidate = *state.RetryAfterAt
	}

	if candidate.Before(schedulerStartedAt) {
		candidate = schedulerStartedAt.Add(
			stableSpread(
				state.Spec.ProfileID,
				state.ConsecutiveFailures,
				policy.StartupSpread,
			),
		)
	}
	return candidate.UTC(), true, nil
}

func failureBackoff(
	profileID string,
	failures uint32,
	policy SchedulePolicy,
) time.Duration {
	delay := policy.FailureBackoff
	for i := uint32(1); i < failures && delay < policy.MaxBackoff; i++ {
		if delay > policy.MaxBackoff/2 {
			delay = policy.MaxBackoff
			break
		}
		delay *= 2
	}
	if delay > policy.MaxBackoff {
		delay = policy.MaxBackoff
	}

	// Stable 80%-120% jitter de-correlates many profiles while keeping the
	// next eligible time deterministic across scheduler scans and restarts.
	jitterPercent := int64(80 + stableHash(profileID, failures)%41)
	jittered := time.Duration(int64(delay) * jitterPercent / 100)
	if jittered > policy.MaxBackoff {
		return policy.MaxBackoff
	}
	return jittered
}

func stableSpread(
	profileID string,
	salt uint32,
	window time.Duration,
) time.Duration {
	if window <= 0 {
		return 0
	}
	return time.Duration(
		stableHash(profileID, salt) % uint64(window),
	)
}

func stableHash(profileID string, salt uint32) uint64 {
	var suffix [4]byte
	binary.BigEndian.PutUint32(suffix[:], salt)
	sum := sha256.Sum256(append(append([]byte(nil), profileID...), suffix[:]...))
	return binary.BigEndian.Uint64(sum[:8])
}
