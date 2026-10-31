package profileupdate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

const (
	DefaultSchedulerScanInterval = 30 * time.Second
	DefaultRefreshConcurrency    = 2
	MaxRefreshConcurrency        = 16
)

type ScheduledRefreshFunc func(
	context.Context,
	string,
	uint64,
	string,
) error

type SchedulerOptions struct {
	ScanInterval  time.Duration
	MaxConcurrent int
	Policy        SchedulePolicy
}

func DefaultSchedulerOptions() SchedulerOptions {
	return SchedulerOptions{
		ScanInterval:  DefaultSchedulerScanInterval,
		MaxConcurrent: DefaultRefreshConcurrency,
		Policy:        DefaultSchedulePolicy(),
	}
}

func (o SchedulerOptions) Validate() error {
	if o.ScanInterval <= 0 {
		return errors.New("profile scheduler scan interval must be positive")
	}
	if o.MaxConcurrent <= 0 || o.MaxConcurrent > MaxRefreshConcurrency {
		return fmt.Errorf(
			"profile scheduler concurrency must be between 1 and %d",
			MaxRefreshConcurrency,
		)
	}
	return o.Policy.Validate()
}

type RefreshScheduler struct {
	store     *storage.Store
	refresh   ScheduledRefreshFunc
	options   SchedulerOptions
	startedAt time.Time
	slots     chan struct{}

	mu      sync.Mutex
	running map[string]struct{}
	wg      sync.WaitGroup
	seq     atomic.Uint64
}

func NewRefreshScheduler(
	store *storage.Store,
	refresh ScheduledRefreshFunc,
	options SchedulerOptions,
) (*RefreshScheduler, error) {
	if store == nil {
		return nil, errors.New("profile scheduler store is nil")
	}
	if refresh == nil {
		return nil, errors.New("profile scheduler refresh callback is nil")
	}
	if err := options.Validate(); err != nil {
		return nil, err
	}
	return &RefreshScheduler{
		store:     store,
		refresh:   refresh,
		options:   options,
		startedAt: time.Now().UTC(),
		slots:     make(chan struct{}, options.MaxConcurrent),
		running:   make(map[string]struct{}),
	}, nil
}

func (s *RefreshScheduler) Run(ctx context.Context) error {
	if s == nil {
		return errors.New("profile scheduler is nil")
	}
	ticker := time.NewTicker(s.options.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			s.wait()
			return nil
		default:
		}
		if err := s.dispatchDue(ctx, time.Now().UTC()); err != nil {
			if ctx.Err() != nil {
				s.wait()
				return nil
			}
			s.wait()
			return err
		}
		select {
		case <-ctx.Done():
			s.wait()
			return nil
		case <-ticker.C:
		}
	}
}

func (s *RefreshScheduler) dispatchDue(ctx context.Context, now time.Time) error {
	sources, err := s.store.ListProfileSources(ctx)
	if err != nil {
		return err
	}
	for _, source := range sources {
		next, scheduled, err := NextRefreshAt(
			source,
			s.startedAt,
			s.options.Policy,
		)
		if err != nil {
			return err
		}
		if !scheduled || next.After(now) {
			continue
		}
		if !s.markRunning(source.Spec.ProfileID) {
			continue
		}
		select {
		case s.slots <- struct{}{}:
		default:
			s.unmarkRunning(source.Spec.ProfileID)
			continue
		}

		updateID := fmt.Sprintf(
			"scheduled-%d-%d",
			now.UnixNano(),
			s.seq.Add(1),
		)
		s.wg.Add(1)
		go s.runOne(ctx, source, updateID)
	}
	return nil
}

func (s *RefreshScheduler) runOne(
	ctx context.Context,
	source storage.ProfileSourceState,
	updateID string,
) {
	defer s.wg.Done()
	defer func() { <-s.slots }()
	defer s.unmarkRunning(source.Spec.ProfileID)

	_ = s.refresh(
		ctx,
		source.Spec.ProfileID,
		source.Revision,
		updateID,
	)
}

func (s *RefreshScheduler) markRunning(profileID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.running[profileID]; exists {
		return false
	}
	s.running[profileID] = struct{}{}
	return true
}

func (s *RefreshScheduler) unmarkRunning(profileID string) {
	s.mu.Lock()
	delete(s.running, profileID)
	s.mu.Unlock()
}

func (s *RefreshScheduler) wait() {
	s.wg.Wait()
}
