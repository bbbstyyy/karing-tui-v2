//go:build linux

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreapi"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
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

type fakeManagedArtifactState struct {
	*fakeManagedState
	artifacts storage.GenerationArtifacts
}

func (s *fakeManagedArtifactState) GenerationArtifacts(context.Context, int64) (storage.GenerationArtifacts, error) {
	if s.err != nil {
		return storage.GenerationArtifacts{}, s.err
	}
	out := s.artifacts
	out.ConfigJSON = append([]byte(nil), s.artifacts.ConfigJSON...)
	out.ManifestJSON = append([]byte(nil), s.artifacts.ManifestJSON...)
	out.SourceMapJSON = append([]byte(nil), s.artifacts.SourceMapJSON...)
	return out, nil
}

type fakeManagedSelectionState struct {
	*fakeManagedArtifactState
	declaration storage.DeclarationRevision
	intent      storage.SelectionIntent
	hasIntent   bool
}

func (s *fakeManagedSelectionState) Declaration(_ context.Context, revision uint64) (storage.DeclarationRevision, error) {
	if s.err != nil {
		return storage.DeclarationRevision{}, s.err
	}
	if s.declaration.Revision != revision {
		return storage.DeclarationRevision{}, storage.ErrDeclarationNotFound
	}
	out := s.declaration
	out.DocumentJSON = append([]byte(nil), out.DocumentJSON...)
	return out, nil
}

func (s *fakeManagedSelectionState) CurrentSelectionIntent(context.Context) (storage.SelectionIntent, bool, error) {
	if s.err != nil {
		return storage.SelectionIntent{}, false, s.err
	}
	out := s.intent
	out.TargetJSON = append([]byte(nil), out.TargetJSON...)
	return out, s.hasIntent, nil
}

type fakeConnectionsControl struct {
	snapshot coreapi.ConnectionsSnapshot
	calls    int
	err      error
}

func (c *fakeConnectionsControl) Snapshot(context.Context) (coreapi.ConnectionsSnapshot, error) {
	c.calls++
	if c.err != nil {
		return coreapi.ConnectionsSnapshot{}, c.err
	}
	return c.snapshot, nil
}

type fakeSelectorControl struct {
	selected string
	calls    []string
	err      error
}

func (s *fakeSelectorControl) Select(_ context.Context, selectorTag, outboundTag string) error {
	s.calls = append(s.calls, selectorTag+"=>"+outboundTag)
	if s.err != nil {
		return s.err
	}
	s.selected = outboundTag
	return nil
}

func (s *fakeSelectorControl) Current(context.Context, string) (coreapi.SelectorSnapshot, error) {
	if s.err != nil {
		return coreapi.SelectorSnapshot{}, s.err
	}
	return coreapi.SelectorSnapshot{Now: s.selected, All: []string{s.selected}}, nil
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

type fakePruningGenerationFiles struct {
	fakeGenerationFiles
	pruneCount int
	protected  []int64
	keepRecent int
	pruneErr   error
}

func (f *fakePruningGenerationFiles) PruneStagedGenerations(_ context.Context, protected []int64, keepRecent int) ([]int64, error) {
	f.pruneCount++
	f.protected = append([]int64(nil), protected...)
	f.keepRecent = keepRecent
	return nil, f.pruneErr
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

func (s *fakeSupervisor) WaitReady(context.Context) error {
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

func TestManagedCoreCheckPrunesStagedGenerationsWithProtectedState(t *testing.T) {
	applied := int64(5)
	lastKnownGood := int64(4)
	files := &fakePruningGenerationFiles{
		fakeGenerationFiles: fakeGenerationFiles{path: "/state/generations/9/config.json"},
	}
	managed := newManagedCore(
		&fakeManagedState{snapshot: storage.Snapshot{
			AppliedGenerationID:       &applied,
			LastKnownGoodGenerationID: &lastKnownGood,
		}},
		files,
		&fakeBinder{},
		&fakeSupervisor{},
		&fakeProbe{},
		func(context.Context, string, string, io.Writer, io.Writer) error { return nil },
		nil,
		nil,
	)

	if err := managed.Check(context.Background(), Generation{ID: 9, Config: []byte("{}"), SHA256: "def"}); err != nil {
		t.Fatal(err)
	}
	if files.pruneCount != 1 || files.keepRecent != stagedGenerationRetention {
		t.Fatalf("unexpected prune call: count=%d keep=%d", files.pruneCount, files.keepRecent)
	}
	want := map[int64]bool{9: true, 5: true, 4: true}
	if len(files.protected) != len(want) {
		t.Fatalf("protected generations = %#v", files.protected)
	}
	for _, id := range files.protected {
		if !want[id] {
			t.Fatalf("unexpected protected generation %d in %#v", id, files.protected)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("missing protected generations: %#v", want)
	}
	if files.stageCount != 1 || files.lastID != 9 {
		t.Fatalf("candidate was not staged after cleanup: %+v", files.fakeGenerationFiles)
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

func TestManagedCoreVerifiesPersistedGenerationMetadataBeforeCheck(t *testing.T) {
	config := []byte("{}")
	configHash := testSHA256(config)
	ruleContent := []byte("rule-set-fixture")
	ruleHash := testSHA256(ruleContent)
	ruleDir := t.TempDir()
	rulePath := filepath.Join(ruleDir, ruleHash+".srs")
	if err := os.WriteFile(rulePath, ruleContent, 0o600); err != nil {
		t.Fatal(err)
	}

	manifest := compiler.NativeManifest{
		SchemaID:     compiler.NativeSchemaID,
		ConfigSHA256: configHash,
		RuleSets: []compiler.NativeRuleSetManifest{{
			Ref:         "acl:test",
			RuntimeTag:  "rs-test",
			RuntimePath: rulePath,
			SHA256:      ruleHash,
			Format:      compiler.RuleSetFormatBinary,
		}},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sourceMapJSON := []byte("[]")
	state := &fakeManagedArtifactState{
		fakeManagedState: &fakeManagedState{config: config, hash: configHash},
		artifacts: storage.GenerationArtifacts{
			ConfigJSON:      config,
			ConfigSHA256:    configHash,
			ManifestJSON:    manifestJSON,
			ManifestSHA256:  testSHA256(manifestJSON),
			SourceMapJSON:   sourceMapJSON,
			SourceMapSHA256: testSHA256(sourceMapJSON),
		},
	}
	files := &fakeGenerationFiles{path: "/state/generations/9/config.json"}
	checkCalls := 0
	check := func(_ context.Context, _, _ string, _, _ io.Writer) error {
		checkCalls++
		return nil
	}
	managed := newManagedCore(state, files, &fakeBinder{}, &fakeSupervisor{}, &fakeProbe{}, check, nil, nil)

	generation := Generation{ID: 9, Config: config, SHA256: configHash}
	if err := managed.Check(context.Background(), generation); err != nil {
		t.Fatal(err)
	}
	if files.stageCount != 1 || checkCalls != 1 {
		t.Fatalf("valid metadata did not reach core check: stages=%d checks=%d", files.stageCount, checkCalls)
	}

	if err := os.WriteFile(rulePath, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := managed.Check(context.Background(), generation); err == nil {
		t.Fatal("tampered rule-set unexpectedly passed generation verification")
	}
	if files.stageCount != 1 || checkCalls != 1 {
		t.Fatalf("tampered metadata reached staging/check: stages=%d checks=%d", files.stageCount, checkCalls)
	}
}

func TestManagedCoreRejectsPersistedMetadataHashMismatchBeforeStart(t *testing.T) {
	id := int64(7)
	config := []byte("{}")
	configHash := testSHA256(config)
	manifest := compiler.NativeManifest{
		SchemaID:     compiler.NativeSchemaID,
		ConfigSHA256: configHash,
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sourceMapJSON := []byte("[]")
	state := &fakeManagedArtifactState{
		fakeManagedState: &fakeManagedState{
			snapshot: storage.Snapshot{AppliedGenerationID: &id},
			config:   config,
			hash:     configHash,
		},
		artifacts: storage.GenerationArtifacts{
			ConfigJSON:      config,
			ConfigSHA256:    configHash,
			ManifestJSON:    manifestJSON,
			ManifestSHA256:  testSHA256([]byte("different manifest")),
			SourceMapJSON:   sourceMapJSON,
			SourceMapSHA256: testSHA256(sourceMapJSON),
		},
	}
	files := &fakeGenerationFiles{path: "/state/generations/7/config.json"}
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateStopped}}
	managed := newManagedCore(state, files, &fakeBinder{}, supervisor, &fakeProbe{}, nil, nil, nil)

	if err := managed.Start(context.Background()); err == nil {
		t.Fatal("manifest hash mismatch unexpectedly started core")
	}
	if files.stageCount != 0 || supervisor.starts != 0 {
		t.Fatalf("invalid metadata reached staging/start: stages=%d starts=%d", files.stageCount, supervisor.starts)
	}
}

func TestManagedCoreAllowsLegacyGenerationWithoutMetadata(t *testing.T) {
	config := []byte("{}")
	hash := testSHA256(config)
	state := &fakeManagedArtifactState{
		fakeManagedState: &fakeManagedState{config: config, hash: hash},
		artifacts: storage.GenerationArtifacts{
			ConfigJSON:   config,
			ConfigSHA256: hash,
		},
	}
	files := &fakeGenerationFiles{path: "/state/generations/3/config.json"}
	checkCalls := 0
	managed := newManagedCore(
		state,
		files,
		&fakeBinder{},
		&fakeSupervisor{},
		&fakeProbe{},
		func(_ context.Context, _, _ string, _, _ io.Writer) error {
			checkCalls++
			return nil
		},
		nil,
		nil,
	)
	if err := managed.Check(context.Background(), Generation{ID: 3, Config: config, SHA256: hash}); err != nil {
		t.Fatal(err)
	}
	if files.stageCount != 1 || checkCalls != 1 {
		t.Fatalf("legacy generation was not preserved: stages=%d checks=%d", files.stageCount, checkCalls)
	}
}

func testSHA256(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func TestManagedCoreReconcileRecoveryRestoresAppliedGeneration(t *testing.T) {
	id := int64(7)
	state := &fakeManagedState{
		snapshot: storage.Snapshot{
			AppliedGenerationID: &id,
			RecoveryRequired:    true,
			CoreDesiredState:    storage.CoreDesiredRunning,
		},
		config: []byte("{}"),
		hash:   "applied",
	}
	files := &fakeGenerationFiles{path: "/state/generations/7/config.json"}
	binder := &fakeBinder{}
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateStopped}}
	probe := &fakeProbe{}
	managed := newManagedCore(state, files, binder, supervisor, probe, nil, nil, nil)

	if err := managed.ReconcileRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if files.stageCount != 1 || files.lastID != id || binder.hash != "applied" {
		t.Fatalf("applied generation was not restored: files=%+v binder=%+v", files, binder)
	}
	if supervisor.stops != 1 || supervisor.starts != 1 || supervisor.resets != 1 {
		t.Fatalf("unexpected recovery restart counts: stops=%d starts=%d resets=%d", supervisor.stops, supervisor.starts, supervisor.resets)
	}
	if probe.calls != 1 {
		t.Fatalf("recovery probe calls = %d, want 1", probe.calls)
	}
}

func TestManagedCoreReconcileRecoveryHonorsStoppedIntent(t *testing.T) {
	id := int64(7)
	files := &fakeGenerationFiles{path: "/state/generations/7/config.json"}
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateStopped}}
	managed := newManagedCore(
		&fakeManagedState{
			snapshot: storage.Snapshot{
				AppliedGenerationID: &id,
				RecoveryRequired:    true,
				CoreDesiredState:    storage.CoreDesiredStopped,
			},
			config: []byte("{}"),
			hash:   "applied",
		},
		files,
		&fakeBinder{},
		supervisor,
		&fakeProbe{},
		nil,
		nil,
		nil,
	)

	if err := managed.ReconcileRecovery(context.Background()); err != nil {
		t.Fatal(err)
	}
	if supervisor.stops != 1 || supervisor.starts != 0 || supervisor.resets != 0 {
		t.Fatalf("stopped recovery changed runtime intent: stops=%d starts=%d resets=%d", supervisor.stops, supervisor.starts, supervisor.resets)
	}
	if files.stageCount != 0 {
		t.Fatalf("stopped recovery unnecessarily staged a generation: %+v", files)
	}
}

func TestManagedCoreReconcileRecoveryRequiresAppliedGenerationForRunningIntent(t *testing.T) {
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateStopped}}
	managed := newManagedCore(
		&fakeManagedState{snapshot: storage.Snapshot{
			RecoveryRequired: true,
			CoreDesiredState: storage.CoreDesiredRunning,
		}},
		&fakeGenerationFiles{},
		&fakeBinder{},
		supervisor,
		&fakeProbe{},
		nil,
		nil,
		nil,
	)

	if err := managed.ReconcileRecovery(context.Background()); !errors.Is(err, ErrNoAppliedGeneration) {
		t.Fatalf("recovery error = %v, want ErrNoAppliedGeneration", err)
	}
	if supervisor.starts != 0 {
		t.Fatalf("recovery started core without an applied generation: %d", supervisor.starts)
	}
}

func TestManagedCoreStartRestoresSelectionFromAppliedGenerationProvenance(t *testing.T) {
	ctx := context.Background()
	id := int64(7)
	document := currentSelectionTestDeclaration()
	target := []byte(`{"kind":"specific_node","profile_id":"profile-a","node_id":"node-b"}`)
	sum := sha256.Sum256(document)
	declarationHash := hex.EncodeToString(sum[:])
	manifestJSON, err := json.Marshal(compiler.NativeManifest{
		SchemaID:            compiler.NativeSchemaID,
		ConfigSHA256:        testSHA256([]byte("{}")),
		DeclarationRevision: 3,
		DeclarationSHA256:   declarationHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	state := &fakeManagedSelectionState{
		fakeManagedArtifactState: &fakeManagedArtifactState{
			fakeManagedState: &fakeManagedState{
				snapshot: storage.Snapshot{AppliedGenerationID: &id},
				config:   []byte("{}"),
				hash:     testSHA256([]byte("{}")),
			},
			artifacts: storage.GenerationArtifacts{
				ConfigJSON:      []byte("{}"),
				ConfigSHA256:    testSHA256([]byte("{}")),
				ManifestJSON:    manifestJSON,
				ManifestSHA256:  testSHA256(manifestJSON),
				SourceMapJSON:   []byte("[]"),
				SourceMapSHA256: testSHA256([]byte("[]")),
			},
		},
		declaration: storage.DeclarationRevision{
			Revision:     3,
			DocumentJSON: document,
			SHA256:       declarationHash,
		},
		intent:    storage.SelectionIntent{TargetJSON: target},
		hasIntent: true,
	}
	files := &fakeGenerationFiles{path: "/state/generations/7/config.json"}
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateStopped}}
	selector := &fakeSelectorControl{}
	managed := newManagedCore(state, files, &fakeBinder{}, supervisor, &fakeProbe{}, nil, nil, nil)
	managed.selector = selector

	if err := managed.Start(ctx); err != nil {
		t.Fatal(err)
	}
	wantTag, err := declaration.CurrentSelectionRuntimeTag(document, domain.TargetRef{
		Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-b",
	})
	if err != nil {
		t.Fatal(err)
	}
	if selector.selected != wantTag || len(selector.calls) != 1 {
		t.Fatalf("restored selector = %q calls=%v, want %q", selector.selected, selector.calls, wantTag)
	}
}

func TestManagedCoreVerifyRestoresSelectionForCandidateGeneration(t *testing.T) {
	ctx := context.Background()
	document := currentSelectionTestDeclaration()
	target := []byte(`{"kind":"specific_node","profile_id":"profile-a","node_id":"node-b"}`)
	sum := sha256.Sum256(document)
	declarationHash := hex.EncodeToString(sum[:])
	manifestJSON, err := json.Marshal(compiler.NativeManifest{
		SchemaID:            compiler.NativeSchemaID,
		ConfigSHA256:        testSHA256([]byte("{}")),
		DeclarationRevision: 4,
		DeclarationSHA256:   declarationHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	state := &fakeManagedSelectionState{
		fakeManagedArtifactState: &fakeManagedArtifactState{
			fakeManagedState: &fakeManagedState{
				snapshot: storage.Snapshot{CoreDesiredState: storage.CoreDesiredRunning},
			},
			artifacts: storage.GenerationArtifacts{ManifestJSON: manifestJSON},
		},
		declaration: storage.DeclarationRevision{
			Revision:     4,
			DocumentJSON: document,
			SHA256:       declarationHash,
		},
		intent:    storage.SelectionIntent{TargetJSON: target},
		hasIntent: true,
	}
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateRunning, DesiredRunning: true, PID: 123}}
	selector := &fakeSelectorControl{}
	managed := newManagedCore(state, &fakeGenerationFiles{}, &fakeBinder{}, supervisor, &fakeProbe{}, nil, nil, nil)
	managed.selector = selector

	if err := managed.Verify(ctx, Generation{ID: 10, Config: []byte("{}"), SHA256: testSHA256([]byte("{}"))}); err != nil {
		t.Fatal(err)
	}
	if len(selector.calls) != 1 {
		t.Fatalf("candidate selection restore calls=%v", selector.calls)
	}
}

func TestManagedCoreStartFailsClosedWhenSelectionProvenanceMissing(t *testing.T) {
	id := int64(7)
	state := &fakeManagedSelectionState{
		fakeManagedArtifactState: &fakeManagedArtifactState{
			fakeManagedState: &fakeManagedState{
				snapshot: storage.Snapshot{AppliedGenerationID: &id},
				config:   []byte("{}"),
				hash:     testSHA256([]byte("{}")),
			},
			artifacts: storage.GenerationArtifacts{},
		},
		intent:    storage.SelectionIntent{TargetJSON: []byte(`{"kind":"specific_node","profile_id":"profile-a","node_id":"node-b"}`)},
		hasIntent: true,
	}
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateStopped}}
	managed := newManagedCore(state, &fakeGenerationFiles{path: "/state/generations/7/config.json"}, &fakeBinder{}, supervisor, &fakeProbe{}, nil, nil, nil)
	managed.selector = &fakeSelectorControl{}

	if err := managed.Start(context.Background()); err == nil {
		t.Fatal("core start unexpectedly ignored persisted selection without provenance")
	}
	if supervisor.starts != 1 || supervisor.stops != 1 {
		t.Fatalf("failed selection restore did not stop mismatched core: starts=%d stops=%d", supervisor.starts, supervisor.stops)
	}
}


func TestManagedCoreConnectionsRequiresRunningCoreAndReturnsSnapshot(t *testing.T) {
	supervisor := &fakeSupervisor{snapshot: core.Snapshot{State: core.StateStopped}}
	connections := &fakeConnectionsControl{snapshot: coreapi.ConnectionsSnapshot{
		Connections: []coreapi.ConnectionInfo{{
			ID:       "connection-1",
			Metadata: coreapi.ConnectionMetadata{Network: "tcp"},
		}},
	}}
	managed := newManagedCore(
		&fakeManagedState{},
		&fakeGenerationFiles{},
		&fakeBinder{},
		supervisor,
		&fakeProbe{},
		nil,
		nil,
		nil,
	)
	managed.connections = connections

	if _, err := managed.Connections(context.Background()); !errors.Is(err, core.ErrNotRunning) {
		t.Fatalf("stopped connections error = %v, want ErrNotRunning", err)
	}
	if connections.calls != 0 {
		t.Fatalf("stopped core queried connections API: %d", connections.calls)
	}

	supervisor.snapshot = core.Snapshot{State: core.StateRunning, DesiredRunning: true, PID: 123}
	snapshot, err := managed.Connections(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if connections.calls != 1 || len(snapshot.Connections) != 1 || snapshot.Connections[0].ID != "connection-1" {
		t.Fatalf("connections snapshot = calls:%d %+v", connections.calls, snapshot)
	}
}
