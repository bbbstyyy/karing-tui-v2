//go:build linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreapi"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrNoAppliedGeneration = errors.New("no applied generation is available")

type managedCoreState interface {
	Snapshot(context.Context) (storage.Snapshot, error)
	GenerationConfig(context.Context, int64) ([]byte, string, error)
}

type generationFiles interface {
	Stage(context.Context, int64, []byte, string) (string, error)
}

type generationBinder interface {
	BindConfig(string, string) error
}

type supervisorEngine interface {
	Run(context.Context) error
	Start(context.Context) error
	Stop(context.Context) error
	ResetCircuit(context.Context) error
	Snapshot() core.Snapshot
}

type generationCheckFunc func(context.Context, string, string, io.Writer, io.Writer) error

type ManagedCoreOptions struct {
	Executable      string
	StateRoot       string
	ControlEndpoint string
	ControlSecret   string
	Inbounds        domain.InboundSet
	Policy          core.Policy
	LogCapacity     int
}

type ManagedCore struct {
	state      managedCoreState
	files      generationFiles
	binder     generationBinder
	supervisor supervisorEngine
	probe      core.Probe
	check      generationCheckFunc
	stdout     *core.RingBuffer
	stderr     *core.RingBuffer

	transitionMu        sync.Mutex
	pollInterval        time.Duration
	applyKeepRunning    bool
}

func NewManagedCore(state managedCoreState, options ManagedCoreOptions) (*ManagedCore, error) {
	if state == nil {
		return nil, errors.New("managed core state source is nil")
	}
	if err := coreartifact.Verify(options.Executable); err != nil {
		return nil, fmt.Errorf("verify configured core artifact: %w", err)
	}
	files, err := coreartifact.NewStore(options.StateRoot)
	if err != nil {
		return nil, err
	}
	if options.Policy == (core.Policy{}) {
		options.Policy = core.DefaultPolicy()
	}
	if options.LogCapacity <= 0 {
		options.LogCapacity = 256 << 10
	}
	stdout := core.NewRingBuffer(options.LogCapacity)
	stderr := core.NewRingBuffer(options.LogCapacity)
	runner, err := core.NewGenerationRunner(options.Executable, coreartifact.Verify, stdout, stderr)
	if err != nil {
		return nil, err
	}
	probe, err := coreapi.NewLocalHealthProbe(options.ControlEndpoint, options.ControlSecret, options.Inbounds)
	if err != nil {
		return nil, err
	}
	supervisor, err := core.NewSupervisorWithProbe(runner, probe, options.Policy)
	if err != nil {
		return nil, err
	}
	check := func(ctx context.Context, path, sha string, out, errOut io.Writer) error {
		return core.CheckGenerationConfig(ctx, options.Executable, coreartifact.Verify, path, sha, out, errOut)
	}
	return newManagedCore(state, files, runner, supervisor, probe, check, stdout, stderr), nil
}

func newManagedCore(
	state managedCoreState,
	files generationFiles,
	binder generationBinder,
	supervisor supervisorEngine,
	probe core.Probe,
	check generationCheckFunc,
	stdout *core.RingBuffer,
	stderr *core.RingBuffer,
) *ManagedCore {
	return &ManagedCore{
		state:        state,
		files:        files,
		binder:       binder,
		supervisor:   supervisor,
		probe:        probe,
		check:        check,
		stdout:       stdout,
		stderr:       stderr,
		pollInterval: 10 * time.Millisecond,
	}
}

func (m *ManagedCore) Run(ctx context.Context) error {
	return m.supervisor.Run(ctx)
}

func (m *ManagedCore) Snapshot() core.Snapshot {
	return m.supervisor.Snapshot()
}

func (m *ManagedCore) StdoutTail() []byte {
	if m.stdout == nil {
		return nil
	}
	return m.stdout.Bytes()
}

func (m *ManagedCore) StderrTail() []byte {
	if m.stderr == nil {
		return nil
	}
	return m.stderr.Bytes()
}

func (m *ManagedCore) Start(ctx context.Context) error {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()

	snapshot, err := m.state.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("read applied generation before core start: %w", err)
	}
	if snapshot.RecoveryRequired {
		return storage.ErrRecoveryRequired
	}
	if snapshot.AppliedGenerationID == nil {
		return ErrNoAppliedGeneration
	}
	generation, err := m.loadGeneration(ctx, *snapshot.AppliedGenerationID)
	if err != nil {
		return err
	}
	if err := m.stageAndBind(ctx, generation); err != nil {
		return err
	}
	if err := m.supervisor.Start(ctx); err != nil {
		return err
	}
	return m.waitRunning(ctx)
}

func (m *ManagedCore) Stop(ctx context.Context) error {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	return m.supervisor.Stop(ctx)
}

func (m *ManagedCore) Check(ctx context.Context, generation Generation) error {
	path, err := m.files.Stage(ctx, generation.ID, generation.Config, generation.SHA256)
	if err != nil {
		return fmt.Errorf("stage generation for check: %w", err)
	}
	if err := m.check(ctx, path, generation.SHA256, m.stdout, m.stderr); err != nil {
		return err
	}
	return nil
}

func (m *ManagedCore) Activate(ctx context.Context, generation Generation) error {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()

	snapshot, err := m.state.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("read core intent before activation: %w", err)
	}
	switch snapshot.CoreDesiredState {
	case storage.CoreDesiredRunning:
		m.applyKeepRunning = true
	case storage.CoreDesiredStopped:
		m.applyKeepRunning = false
	default:
		return fmt.Errorf("%w: %q", storage.ErrInvalidCoreDesiredState, snapshot.CoreDesiredState)
	}

	if err := m.stageAndBind(ctx, generation); err != nil {
		return err
	}
	return m.restartLocked(ctx, true)
}

func (m *ManagedCore) Verify(ctx context.Context, _ Generation) error {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()

	if err := m.waitRunning(ctx); err != nil {
		return err
	}
	if err := m.probe.Ready(ctx, nil); err != nil {
		return fmt.Errorf("verify local core health: %w", err)
	}
	if !m.applyKeepRunning {
		if err := m.supervisor.Stop(ctx); err != nil && !errors.Is(err, core.ErrNotRunning) {
			return fmt.Errorf("restore stopped intent after verification: %w", err)
		}
	}
	return nil
}

func (m *ManagedCore) Rollback(ctx context.Context, previous *Generation) error {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()

	if previous == nil {
		if err := m.supervisor.Stop(ctx); err != nil && !errors.Is(err, core.ErrNotRunning) {
			return err
		}
		return nil
	}
	if err := m.stageAndBind(ctx, *previous); err != nil {
		return err
	}
	if !m.applyKeepRunning {
		if err := m.supervisor.Stop(ctx); err != nil && !errors.Is(err, core.ErrNotRunning) {
			return fmt.Errorf("restore stopped intent during rollback: %w", err)
		}
		return nil
	}
	if err := m.restartLocked(ctx, true); err != nil {
		return err
	}
	if err := m.probe.Ready(ctx, nil); err != nil {
		return fmt.Errorf("verify rolled back core health: %w", err)
	}
	return nil
}

func (m *ManagedCore) loadGeneration(ctx context.Context, generationID int64) (Generation, error) {
	config, sha, err := m.state.GenerationConfig(ctx, generationID)
	if err != nil {
		return Generation{}, fmt.Errorf("load generation %d: %w", generationID, err)
	}
	return Generation{ID: generationID, Config: config, SHA256: sha}, nil
}

func (m *ManagedCore) stageAndBind(ctx context.Context, generation Generation) error {
	path, err := m.files.Stage(ctx, generation.ID, generation.Config, generation.SHA256)
	if err != nil {
		return fmt.Errorf("stage generation %d: %w", generation.ID, err)
	}
	if err := m.binder.BindConfig(path, generation.SHA256); err != nil {
		return fmt.Errorf("bind generation %d: %w", generation.ID, err)
	}
	return nil
}

func (m *ManagedCore) restartLocked(ctx context.Context, resetCircuit bool) error {
	if err := m.supervisor.Stop(ctx); err != nil && !errors.Is(err, core.ErrNotRunning) {
		return fmt.Errorf("stop core before generation switch: %w", err)
	}
	if resetCircuit {
		if err := m.supervisor.ResetCircuit(ctx); err != nil && !errors.Is(err, core.ErrNotRunning) {
			return fmt.Errorf("reset core circuit before generation switch: %w", err)
		}
	}
	if err := m.supervisor.Start(ctx); err != nil {
		return fmt.Errorf("start core after generation switch: %w", err)
	}
	return m.waitRunning(ctx)
}

func (m *ManagedCore) waitRunning(ctx context.Context) error {
	ticker := time.NewTicker(m.pollInterval)
	defer ticker.Stop()

	for {
		snapshot := m.supervisor.Snapshot()
		switch snapshot.State {
		case core.StateRunning:
			return nil
		case core.StateFailed:
			if snapshot.LastError != "" {
				return fmt.Errorf("core supervisor failed: %s", snapshot.LastError)
			}
			return errors.New("core supervisor failed")
		case core.StateStopped:
			if !snapshot.DesiredRunning {
				return errors.New("core stopped before becoming ready")
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
