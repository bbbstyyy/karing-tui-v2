//go:build linux

package daemon

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type fakeManagedState struct {
	snapshot storage.Snapshot
	config   []byte
	hash     string
	err      error
}

func (s *fakeManagedState) Snapshot(context.Context) (storage.Snapshot, error) {
	return s.snapshot, s.err
}

func (s *fakeManagedState) GenerationConfig(context.Context, int64) ([]byte, string, error) {
	if s.err != nil {
		return nil, "", s.err
	}
	return append([]byte(nil), s.config...), s.hash, nil
}

type fakeGenerationFiles struct {
	path       string
	stageCount int
	lastID     int64
	lastHash   string
}

func (f *fakeGenerationFiles) Stage(_ context.Context, id int64, _ []byte, hash string) (string, error) {
	f.stageCount++
	f.lastID = id
	f.lastHash = hash
	return f.path, nil
}

type fakeBinder struct {
	path string
	hash string
}

func (b *fakeBinder) BindConfig(path, hash string) error {
	b.path = path
	b.hash = hash
	return nil
}

type fakeSupervisor struct {
	snapshot core.Snapshot
	starts   int
	stops    int
	resets   int
}

func (s *fakeSupervisor) Run(context.Context) error {
	return nil
}

func (s *fakeSupervisor) Start(context.Context) error {
	s.starts++
	s.snapshot = core.Snapshot{State: core.StateRunning, DesiredRunning: true, PID: 123}
	return nil
}

func (s *fakeSupervisor) Stop(context.Context) error {
	s.stops++
	s.snapshot = core.Snapshot{State: core.StateStopped}
	return nil
}

func (s *fakeSupervisor) ResetCircuit(context.Context) error {
	s.resets++
	s.snapshot.CircuitOpen = false
	return nil
}

func (s *fakeSupervisor) Snapshot() core.Snapshot {
	return s.snapshot
}

type fakeProbe struct {
	calls int
	err   error
}

func (p *fakeProbe) Ready(context.Context, core.Process) error {
	p.calls++
	return p.err
}

func TestManagedCoreStartBindsAppliedGeneration(t *testing.T) {
	id := int64(7)
	state := &fakeManagedState{
		snapshot: storage.Snapshot{AppliedGenerationID: &id},
		config:   []byte("{}"),
		hash:     "abc",
	}
	files := &fakeGenerationFiles{path: "/state/generations/7/config.json"}
	binder := &fakeBinder{}
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateStopped}}
	managed := newManagedCore(state, files, binder, supervisor, &fakeProbe{}, nil, nil, nil)

	if err := managed.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if files.stageCount != 1 || files.lastID != id {
		t.Fatalf("unexpected stage calls: %+v", files)
	}
	if binder.path != files.path || binder.hash != "abc" {
		t.Fatalf("unexpected binding: %+v", binder)
	}
	if supervisor.starts != 1 {
		t.Fatalf("start calls = %d, want 1", supervisor.starts)
	}
}

func TestManagedCoreStartRejectsRecoveryAndMissingGeneration(t *testing.T) {
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateStopped}}
	files := &fakeGenerationFiles{path: "/state/config.json"}
	binder := &fakeBinder{}

	recovery := newManagedCore(
		&fakeManagedState{snapshot: storage.Snapshot{RecoveryRequired: true}},
		files,
		binder,
		supervisor,
		&fakeProbe{},
		nil,
		nil,
		nil,
	)
	if err := recovery.Start(context.Background()); !errors.Is(err, storage.ErrRecoveryRequired) {
		t.Fatalf("recovery start error = %v", err)
	}

	missing := newManagedCore(
		&fakeManagedState{snapshot: storage.Snapshot{}},
		files,
		binder,
		supervisor,
		&fakeProbe{},
		nil,
		nil,
		nil,
	)
	if err := missing.Start(context.Background()); !errors.Is(err, ErrNoAppliedGeneration) {
		t.Fatalf("missing generation start error = %v", err)
	}
}

func TestManagedCoreCheckStagesExactGeneration(t *testing.T) {
	files := &fakeGenerationFiles{path: "/state/generations/9/config.json"}
	var checkedPath, checkedHash string
	check := func(_ context.Context, path, hash string, _, _ io.Writer) error {
		checkedPath = path
		checkedHash = hash
		return nil
	}
	managed := newManagedCore(
		&fakeManagedState{},
		files,
		&fakeBinder{},
		&fakeSupervisor{},
		&fakeProbe{},
		check,
		nil,
		nil,
	)
	generation := Generation{ID: 9, Config: []byte("{}"), SHA256: "def"}
	if err := managed.Check(context.Background(), generation); err != nil {
		t.Fatal(err)
	}
	if files.lastID != 9 || files.lastHash != "def" || checkedPath != files.path || checkedHash != "def" {
		t.Fatalf("check did not preserve generation identity: files=%+v path=%q hash=%q", files, checkedPath, checkedHash)
	}
}

func TestManagedCoreActivateVerifyAndRollback(t *testing.T) {
	files := &fakeGenerationFiles{path: "/state/config.json"}
	binder := &fakeBinder{}
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateRunning, DesiredRunning: true}}
	probe := &fakeProbe{}
	managed := newManagedCore(
		&fakeManagedState{snapshot: storage.Snapshot{CoreDesiredState: storage.CoreDesiredRunning}},
		files,
		binder,
		supervisor,
		probe,
		nil,
		nil,
		nil,
	)

	candidate := Generation{ID: 10, Config: []byte("{}"), SHA256: "candidate"}
	if err := managed.Activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if supervisor.stops != 1 || supervisor.starts != 1 || supervisor.resets != 1 {
		t.Fatalf("candidate restart counts: stops=%d starts=%d resets=%d", supervisor.stops, supervisor.starts, supervisor.resets)
	}
	if err := managed.Verify(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if probe.calls != 1 {
		t.Fatalf("verify probe calls = %d, want 1", probe.calls)
	}

	previous := Generation{ID: 8, Config: []byte("{}"), SHA256: "previous"}
	if err := managed.Rollback(context.Background(), &previous); err != nil {
		t.Fatal(err)
	}
	if supervisor.stops != 2 || supervisor.starts != 2 || supervisor.resets != 2 {
		t.Fatalf("rollback restart counts: stops=%d starts=%d resets=%d", supervisor.stops, supervisor.starts, supervisor.resets)
	}
	if probe.calls != 2 {
		t.Fatalf("rollback probe calls = %d, want 2", probe.calls)
	}

	if err := managed.Rollback(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if supervisor.stops != 3 {
		t.Fatalf("nil rollback stop count = %d, want 3", supervisor.stops)
	}
}

func TestManagedCoreApplyPreservesStoppedIntent(t *testing.T) {
	files := &fakeGenerationFiles{path: "/state/config.json"}
	binder := &fakeBinder{}
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateStopped}}
	probe := &fakeProbe{}
	managed := newManagedCore(
		&fakeManagedState{snapshot: storage.Snapshot{CoreDesiredState: storage.CoreDesiredStopped}},
		files,
		binder,
		supervisor,
		probe,
		nil,
		nil,
		nil,
	)

	candidate := Generation{ID: 11, Config: []byte("{}"), SHA256: "candidate"}
	if err := managed.Activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if supervisor.starts != 1 || supervisor.resets != 1 {
		t.Fatalf("temporary activation counts: starts=%d resets=%d", supervisor.starts, supervisor.resets)
	}
	if err := managed.Verify(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if probe.calls != 1 {
		t.Fatalf("verify probe calls = %d, want 1", probe.calls)
	}
	if supervisor.snapshot.State != core.StateStopped || supervisor.snapshot.DesiredRunning {
		t.Fatalf("stopped intent not restored: %+v", supervisor.snapshot)
	}

	previous := Generation{ID: 8, Config: []byte("{}"), SHA256: "previous"}
	startsBefore := supervisor.starts
	if err := managed.Rollback(context.Background(), &previous); err != nil {
		t.Fatal(err)
	}
	if supervisor.starts != startsBefore {
		t.Fatalf("stopped rollback restarted core: starts=%d before=%d", supervisor.starts, startsBefore)
	}
	if binder.hash != "previous" {
		t.Fatalf("rollback did not rebind previous generation: %+v", binder)
	}
}
