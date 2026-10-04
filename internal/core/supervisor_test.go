package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeRunner struct {
	mu        sync.Mutex
	starts    int
	processes []*fakeProcess
	startErrs []error
}

func (r *fakeRunner) Start(context.Context) (Process, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index := r.starts
	r.starts++
	if index < len(r.startErrs) && r.startErrs[index] != nil {
		return nil, r.startErrs[index]
	}
	process := newFakeProcess(1000 + index)
	r.processes = append(r.processes, process)
	return process, nil
}

func (r *fakeRunner) Starts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.starts
}

func (r *fakeRunner) LastProcess() *fakeProcess {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.processes) == 0 {
		return nil
	}
	return r.processes[len(r.processes)-1]
}

type fakeProcess struct {
	pid             int
	done            chan error
	stopOnce        sync.Once
	ignoreTerminate bool
	mu              sync.Mutex
	killed          bool
}

func newFakeProcess(pid int) *fakeProcess {
	return &fakeProcess{pid: pid, done: make(chan error, 1)}
}

func (p *fakeProcess) PID() int { return p.pid }

func (p *fakeProcess) Wait() error { return <-p.done }

func (p *fakeProcess) Terminate() error {
	if p.ignoreTerminate {
		return nil
	}
	p.stopOnce.Do(func() { p.done <- nil })
	return nil
}

func (p *fakeProcess) Kill() error {
	p.mu.Lock()
	p.killed = true
	p.mu.Unlock()
	p.stopOnce.Do(func() { p.done <- errors.New("killed") })
	return nil
}

func (p *fakeProcess) Killed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.killed
}

func (p *fakeProcess) Crash(err error) {
	p.stopOnce.Do(func() { p.done <- err })
}

func TestBackoffUsesBoundedExponentialSchedule(t *testing.T) {
	policy := DefaultPolicy()
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 60 * time.Second, 60 * time.Second}
	for attempt, expected := range want {
		if got := Backoff(policy, attempt); got != expected {
			t.Fatalf("Backoff(%d) = %s, want %s", attempt, got, expected)
		}
	}
}

func TestSupervisorStopIntentPreventsRestart(t *testing.T) {
	runner := &fakeRunner{}
	supervisor := newTestSupervisor(t, runner, 5)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitSupervisorRunning(t, supervisor)

	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitState(t, supervisor, StateRunning)
	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitState(t, supervisor, StateStopped)

	time.Sleep(40 * time.Millisecond)
	if got := runner.Starts(); got != 1 {
		t.Fatalf("core starts after explicit stop = %d, want 1", got)
	}
	if supervisor.Snapshot().DesiredRunning {
		t.Fatal("desired-running remained true after stop")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorOpensCircuitAfterFailureBudget(t *testing.T) {
	runner := &fakeRunner{startErrs: []error{errors.New("bad config"), errors.New("bad config"), errors.New("bad config")}}
	supervisor := newTestSupervisor(t, runner, 3)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitSupervisorRunning(t, supervisor)

	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitState(t, supervisor, StateFailed)
	if got := runner.Starts(); got != 3 {
		t.Fatalf("start attempts = %d, want 3", got)
	}
	snapshot := supervisor.Snapshot()
	if !snapshot.CircuitOpen || snapshot.ConsecutiveFails != 3 {
		t.Fatalf("unexpected failed snapshot: %+v", snapshot)
	}
	if err := supervisor.Start(context.Background()); !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("start with open circuit error = %v, want ErrCircuitOpen", err)
	}

	if err := supervisor.ResetCircuit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if supervisor.Snapshot().CircuitOpen {
		t.Fatal("circuit remained open after explicit reset")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorRestartsUnexpectedExitButNotHealthSignals(t *testing.T) {
	runner := &fakeRunner{}
	supervisor := newTestSupervisor(t, runner, 5)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitSupervisorRunning(t, supervisor)

	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitState(t, supervisor, StateRunning)
	first := runner.LastProcess()
	first.Crash(errors.New("exit 2"))

	waitStarts(t, runner, 2)
	waitState(t, supervisor, StateRunning)
	if !supervisor.Snapshot().DesiredRunning {
		t.Fatal("desired-running cleared after unexpected exit")
	}

	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorForcesOwnedProcessAfterStopTimeout(t *testing.T) {
	runner := &fakeRunner{}
	supervisor := newTestSupervisor(t, runner, 5)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitSupervisorRunning(t, supervisor)

	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitState(t, supervisor, StateRunning)
	process := runner.LastProcess()
	process.ignoreTerminate = true
	if err := supervisor.Stop(context.Background()); !errors.Is(err, ErrStopTimeout) {
		t.Fatalf("stop error = %v, want ErrStopTimeout", err)
	}
	waitState(t, supervisor, StateStopped)
	if !process.Killed() {
		t.Fatal("process was not force-killed after stop timeout")
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorShutdownStopsOwnedProcess(t *testing.T) {
	runner := &fakeRunner{}
	supervisor := newTestSupervisor(t, runner, 5)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitSupervisorRunning(t, supervisor)

	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitState(t, supervisor, StateRunning)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := supervisor.Snapshot().State; got != StateStopped {
		t.Fatalf("state after shutdown = %s, want stopped", got)
	}
}

func newTestSupervisor(t *testing.T, runner Runner, maxFailures int) *Supervisor {
	t.Helper()
	policy := Policy{
		InitialBackoff: 5 * time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		FailureWindow:  time.Second,
		MaxFailures:    maxFailures,
		ReadyTimeout:   100 * time.Millisecond,
		StopTimeout:    200 * time.Millisecond,
	}
	supervisor, err := NewSupervisor(runner, policy)
	if err != nil {
		t.Fatal(err)
	}
	return supervisor
}

func waitSupervisorRunning(t *testing.T, supervisor *Supervisor) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := supervisor.WaitReady(ctx); err != nil {
		t.Fatalf("supervisor run loop did not start: %v", err)
	}
}

func waitState(t *testing.T, supervisor *Supervisor, want State) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if supervisor.Snapshot().State == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("state = %s, want %s; snapshot=%+v", supervisor.Snapshot().State, want, supervisor.Snapshot())
}

func waitStarts(t *testing.T, runner *fakeRunner, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if runner.Starts() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("runner starts = %d, want >= %d", runner.Starts(), want)
}

func TestSupervisorWaitsForReadinessBeforeRunning(t *testing.T) {
	runner := &fakeRunner{}
	gate := make(chan struct{})
	probe := ProbeFunc(func(ctx context.Context, _ Process) error {
		select {
		case <-gate:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	policy := Policy{
		InitialBackoff: 5 * time.Millisecond,
		MaxBackoff:     20 * time.Millisecond,
		FailureWindow:  time.Second,
		MaxFailures:    3,
		ReadyTimeout:   200 * time.Millisecond,
		StopTimeout:    200 * time.Millisecond,
	}
	supervisor, err := NewSupervisorWithProbe(runner, probe, policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitSupervisorRunning(t, supervisor)

	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitStarts(t, runner, 1)
	if got := supervisor.Snapshot().State; got != StateStarting {
		t.Fatalf("state before readiness = %s, want starting", got)
	}
	close(gate)
	waitState(t, supervisor, StateRunning)

	if err := supervisor.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupervisorCountsReadinessFailureTowardCircuitBreaker(t *testing.T) {
	runner := &fakeRunner{}
	probe := ProbeFunc(func(context.Context, Process) error {
		return errors.New("local control API unavailable")
	})
	policy := Policy{
		InitialBackoff: time.Millisecond,
		MaxBackoff:     2 * time.Millisecond,
		FailureWindow:  time.Second,
		MaxFailures:    2,
		ReadyTimeout:   50 * time.Millisecond,
		StopTimeout:    50 * time.Millisecond,
	}
	supervisor, err := NewSupervisorWithProbe(runner, probe, policy)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- supervisor.Run(ctx) }()
	waitSupervisorRunning(t, supervisor)

	if err := supervisor.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitState(t, supervisor, StateFailed)
	snapshot := supervisor.Snapshot()
	if !snapshot.CircuitOpen || snapshot.ConsecutiveFails != 2 {
		t.Fatalf("unexpected readiness-failure snapshot: %+v", snapshot)
	}
	if got := runner.Starts(); got != 2 {
		t.Fatalf("start attempts = %d, want 2", got)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}


func TestSupervisorWaitReadyHonorsContextBeforeRun(t *testing.T) {
	supervisor := newTestSupervisor(t, &fakeRunner{}, 3)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if err := supervisor.WaitReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitReady error = %v, want deadline exceeded", err)
	}
}
