package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

type State string

const (
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateBackoff  State = "backoff"
	StateStopping State = "stopping"
	StateFailed   State = "failed"
)

var (
	ErrNotRunning    = errors.New("core supervisor is not running")
	ErrStopTimeout   = errors.New("core did not stop before timeout")
	ErrCircuitOpen   = errors.New("core restart circuit is open")
	ErrInvalidPolicy = errors.New("invalid core supervisor policy")
)

type Process interface {
	PID() int
	Wait() error
	Terminate() error
	Kill() error
}

type Runner interface {
	Start(context.Context) (Process, error)
}

type Probe interface {
	Ready(context.Context, Process) error
}

type ProbeFunc func(context.Context, Process) error

func (f ProbeFunc) Ready(ctx context.Context, process Process) error {
	return f(ctx, process)
}

var readyImmediately Probe = ProbeFunc(func(context.Context, Process) error { return nil })

type Policy struct {
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	FailureWindow  time.Duration
	MaxFailures    int
	ReadyTimeout   time.Duration
	StopTimeout    time.Duration
}

func DefaultPolicy() Policy {
	return Policy{
		InitialBackoff: time.Second,
		MaxBackoff:     60 * time.Second,
		FailureWindow:  10 * time.Minute,
		MaxFailures:    5,
		ReadyTimeout:   10 * time.Second,
		StopTimeout:    10 * time.Second,
	}
}

func (p Policy) Validate() error {
	if p.InitialBackoff <= 0 {
		return fmt.Errorf("%w: initial backoff must be positive", ErrInvalidPolicy)
	}
	if p.MaxBackoff < p.InitialBackoff {
		return fmt.Errorf("%w: max backoff must be >= initial backoff", ErrInvalidPolicy)
	}
	if p.FailureWindow <= 0 {
		return fmt.Errorf("%w: failure window must be positive", ErrInvalidPolicy)
	}
	if p.MaxFailures < 1 {
		return fmt.Errorf("%w: max failures must be positive", ErrInvalidPolicy)
	}
	if p.ReadyTimeout <= 0 {
		return fmt.Errorf("%w: readiness timeout must be positive", ErrInvalidPolicy)
	}
	if p.StopTimeout <= 0 {
		return fmt.Errorf("%w: stop timeout must be positive", ErrInvalidPolicy)
	}
	return nil
}

type Snapshot struct {
	State            State
	DesiredRunning   bool
	PID              int
	ConsecutiveFails int
	CircuitOpen      bool
	LastError        string
	NextRetryAt      time.Time
}

type commandKind uint8

const (
	commandStart commandKind = iota + 1
	commandStop
	commandReset
)

type command struct {
	kind commandKind
	ack  chan error
}

type processExit struct {
	process Process
	err     error
}

type Supervisor struct {
	runner Runner
	probe  Probe
	policy Policy

	mu       sync.RWMutex
	snapshot Snapshot
	running  bool
	readyCh  chan struct{}
	commands chan command
}

func NewSupervisor(runner Runner, policy Policy) (*Supervisor, error) {
	return NewSupervisorWithProbe(runner, readyImmediately, policy)
}

func NewSupervisorWithProbe(runner Runner, probe Probe, policy Policy) (*Supervisor, error) {
	if runner == nil {
		return nil, errors.New("core runner is nil")
	}
	if probe == nil {
		return nil, errors.New("core readiness probe is nil")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &Supervisor{
		runner:   runner,
		probe:    probe,
		policy:   policy,
		commands: make(chan command),
		readyCh:  make(chan struct{}),
		snapshot: Snapshot{State: StateStopped},
	}, nil
}

func (s *Supervisor) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot
}

func (s *Supervisor) WaitReady(ctx context.Context) error {
	s.mu.RLock()
	if s.running {
		s.mu.RUnlock()
		return nil
	}
	readyCh := s.readyCh
	s.mu.RUnlock()

	select {
	case <-readyCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Supervisor) Start(ctx context.Context) error {
	return s.command(ctx, commandStart)
}

func (s *Supervisor) Stop(ctx context.Context) error {
	return s.command(ctx, commandStop)
}

// ResetCircuit clears the failure window after an operator has diagnosed a
// deterministic startup failure. It does not start the core by itself.
func (s *Supervisor) ResetCircuit(ctx context.Context) error {
	return s.command(ctx, commandReset)
}

func (s *Supervisor) command(ctx context.Context, kind commandKind) error {
	ack := make(chan error, 1)
	cmd := command{kind: kind, ack: ack}

	s.mu.RLock()
	running := s.running
	s.mu.RUnlock()
	if !running {
		return ErrNotRunning
	}

	select {
	case s.commands <- cmd:
	case <-ctx.Done():
		return ctx.Err()
	}

	select {
	case err := <-ack:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run owns the lifecycle of the Process returned by Runner. Only this loop
// waits for the process, so callers cannot accidentally reap or restart a
// process that the supervisor does not own.
func (s *Supervisor) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("core supervisor already running")
	}
	s.running = true
	close(s.readyCh)
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.running = false
		s.readyCh = make(chan struct{})
		s.mu.Unlock()
	}()

	var (
		current    Process
		exitCh     = make(chan processExit, 1)
		retryTimer *time.Timer
		retryC     <-chan time.Time
		failures   []time.Time
		attempt    int
		stopAck    chan error
		stopTimer  *time.Timer
		stopC      <-chan time.Time
	)

	clearRetry := func() {
		if retryTimer != nil {
			if !retryTimer.Stop() {
				select {
				case <-retryTimer.C:
				default:
				}
			}
			retryTimer = nil
			retryC = nil
		}
	}

	clearStopTimer := func() {
		if stopTimer != nil {
			if !stopTimer.Stop() {
				select {
				case <-stopTimer.C:
				default:
				}
			}
			stopTimer = nil
			stopC = nil
		}
	}

	setSnapshot := func(update func(*Snapshot)) {
		s.mu.Lock()
		update(&s.snapshot)
		s.mu.Unlock()
	}

	pruneFailures := func(now time.Time) {
		cutoff := now.Add(-s.policy.FailureWindow)
		first := 0
		for first < len(failures) && failures[first].Before(cutoff) {
			first++
		}
		if first > 0 {
			failures = append(failures[:0], failures[first:]...)
		}
	}

	recordFailure := func(err error) bool {
		now := time.Now()
		pruneFailures(now)
		if len(failures) == 0 {
			attempt = 0
		}
		failures = append(failures, now)
		lastError := "core process exited unexpectedly"
		if err != nil {
			lastError = err.Error()
		}
		open := len(failures) >= s.policy.MaxFailures
		setSnapshot(func(snapshot *Snapshot) {
			snapshot.ConsecutiveFails = len(failures)
			snapshot.CircuitOpen = open
			snapshot.LastError = lastError
		})
		return open
	}

	scheduleRetry := func() {
		delay := Backoff(s.policy, attempt)
		attempt++
		retryTimer = time.NewTimer(delay)
		retryC = retryTimer.C
		next := time.Now().Add(delay)
		setSnapshot(func(snapshot *Snapshot) {
			snapshot.State = StateBackoff
			snapshot.PID = 0
			snapshot.NextRetryAt = next
		})
	}

	startProcess := func() {
		setSnapshot(func(snapshot *Snapshot) {
			snapshot.State = StateStarting
			snapshot.PID = 0
			snapshot.NextRetryAt = time.Time{}
		})
		process, err := s.runner.Start(ctx)
		if err != nil {
			if recordFailure(err) {
				setSnapshot(func(snapshot *Snapshot) {
					snapshot.State = StateFailed
					snapshot.PID = 0
					snapshot.NextRetryAt = time.Time{}
				})
				return
			}
			scheduleRetry()
			return
		}

		readyCtx, cancel := context.WithTimeout(ctx, s.policy.ReadyTimeout)
		readyErr := s.probe.Ready(readyCtx, process)
		cancel()
		if readyErr != nil {
			readyErr = fmt.Errorf("core readiness check failed: %w", readyErr)
			if stopErr := stopBeforeRunning(process, s.policy.StopTimeout); stopErr != nil {
				readyErr = errors.Join(readyErr, stopErr)
			}
			if recordFailure(readyErr) {
				setSnapshot(func(snapshot *Snapshot) {
					snapshot.State = StateFailed
					snapshot.PID = 0
					snapshot.NextRetryAt = time.Time{}
				})
				return
			}
			scheduleRetry()
			return
		}

		current = process
		setSnapshot(func(snapshot *Snapshot) {
			snapshot.State = StateRunning
			snapshot.PID = process.PID()
			snapshot.NextRetryAt = time.Time{}
		})
		go func(process Process) {
			exitCh <- processExit{process: process, err: process.Wait()}
		}(process)
	}

	stopProcess := func(ack chan error) {
		clearRetry()
		setSnapshot(func(snapshot *Snapshot) {
			snapshot.DesiredRunning = false
			snapshot.NextRetryAt = time.Time{}
		})
		if current == nil {
			setSnapshot(func(snapshot *Snapshot) {
				snapshot.State = StateStopped
				snapshot.PID = 0
			})
			ack <- nil
			return
		}
		setSnapshot(func(snapshot *Snapshot) { snapshot.State = StateStopping })
		if err := current.Terminate(); err != nil {
			setSnapshot(func(snapshot *Snapshot) { snapshot.LastError = err.Error() })
			if killErr := current.Kill(); killErr != nil {
				ack <- errors.Join(err, killErr)
				return
			}
			ack <- err
			return
		}
		stopAck = ack
		stopTimer = time.NewTimer(s.policy.StopTimeout)
		stopC = stopTimer.C
	}

	shutdown := func() error {
		clearRetry()
		clearStopTimer()
		setSnapshot(func(snapshot *Snapshot) { snapshot.DesiredRunning = false })
		if current == nil {
			setSnapshot(func(snapshot *Snapshot) {
				snapshot.State = StateStopped
				snapshot.PID = 0
			})
			return nil
		}
		setSnapshot(func(snapshot *Snapshot) { snapshot.State = StateStopping })
		if err := current.Terminate(); err != nil {
			_ = current.Kill()
			return fmt.Errorf("terminate core during supervisor shutdown: %w", err)
		}
		timer := time.NewTimer(s.policy.StopTimeout)
		defer timer.Stop()
		select {
		case exited := <-exitCh:
			if exited.process != current {
				return errors.New("received exit for unowned core process")
			}
			current = nil
			setSnapshot(func(snapshot *Snapshot) {
				snapshot.State = StateStopped
				snapshot.PID = 0
			})
			return nil
		case <-timer.C:
			if err := current.Kill(); err != nil {
				return errors.Join(ErrStopTimeout, err)
			}
			select {
			case exited := <-exitCh:
				if exited.process != current {
					return errors.New("received exit for unowned core process")
				}
				current = nil
				setSnapshot(func(snapshot *Snapshot) {
					snapshot.State = StateStopped
					snapshot.PID = 0
					snapshot.LastError = ErrStopTimeout.Error()
				})
				return ErrStopTimeout
			case <-time.After(s.policy.StopTimeout):
				return ErrStopTimeout
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return shutdown()

		case cmd := <-s.commands:
			switch cmd.kind {
			case commandStart:
				snapshot := s.Snapshot()
				if snapshot.CircuitOpen {
					cmd.ack <- ErrCircuitOpen
					continue
				}
				if snapshot.DesiredRunning {
					cmd.ack <- nil
					continue
				}
				setSnapshot(func(snapshot *Snapshot) { snapshot.DesiredRunning = true })
				cmd.ack <- nil
				startProcess()

			case commandStop:
				stopProcess(cmd.ack)

			case commandReset:
				failures = nil
				attempt = 0
				clearRetry()
				setSnapshot(func(snapshot *Snapshot) {
					snapshot.CircuitOpen = false
					snapshot.ConsecutiveFails = 0
					snapshot.LastError = ""
					snapshot.NextRetryAt = time.Time{}
					if snapshot.State == StateFailed {
						snapshot.State = StateStopped
						snapshot.DesiredRunning = false
					}
				})
				cmd.ack <- nil
			}

		case <-retryC:
			retryTimer = nil
			retryC = nil
			snapshot := s.Snapshot()
			if snapshot.DesiredRunning && !snapshot.CircuitOpen {
				startProcess()
			}

		case <-stopC:
			stopTimer = nil
			stopC = nil
			if current == nil {
				continue
			}
			killErr := current.Kill()
			setSnapshot(func(snapshot *Snapshot) {
				snapshot.LastError = ErrStopTimeout.Error()
			})
			if stopAck != nil {
				if killErr != nil {
					stopAck <- errors.Join(ErrStopTimeout, killErr)
				} else {
					stopAck <- ErrStopTimeout
				}
				stopAck = nil
			}

		case exited := <-exitCh:
			clearStopTimer()
			if current == nil || exited.process != current {
				return errors.New("received exit for unowned core process")
			}
			current = nil
			snapshot := s.Snapshot()
			if snapshot.State == StateStopping || !snapshot.DesiredRunning {
				setSnapshot(func(snapshot *Snapshot) {
					snapshot.State = StateStopped
					snapshot.PID = 0
					snapshot.NextRetryAt = time.Time{}
				})
				if stopAck != nil {
					stopAck <- nil
					stopAck = nil
				}
				continue
			}
			if recordFailure(exited.err) {
				clearRetry()
				setSnapshot(func(snapshot *Snapshot) {
					snapshot.State = StateFailed
					snapshot.PID = 0
					snapshot.NextRetryAt = time.Time{}
				})
				continue
			}
			scheduleRetry()
		}
	}
}

func Backoff(policy Policy, attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	delay := policy.InitialBackoff
	for i := 0; i < attempt; i++ {
		if delay >= policy.MaxBackoff/2 {
			return policy.MaxBackoff
		}
		delay *= 2
	}
	if delay > policy.MaxBackoff {
		return policy.MaxBackoff
	}
	return delay
}

func stopBeforeRunning(process Process, timeout time.Duration) error {
	if err := process.Terminate(); err != nil {
		if killErr := process.Kill(); killErr != nil {
			return errors.Join(err, killErr)
		}
	}

	waitCh := make(chan error, 1)
	go func() { waitCh <- process.Wait() }()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-waitCh:
		return nil
	case <-timer.C:
		if err := process.Kill(); err != nil {
			return errors.Join(ErrStopTimeout, err)
		}
		timer.Reset(timeout)
		select {
		case <-waitCh:
			return ErrStopTimeout
		case <-timer.C:
			return ErrStopTimeout
		}
	}
}
