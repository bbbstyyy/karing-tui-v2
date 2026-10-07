//go:build linux

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sync"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreapi"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrNoAppliedGeneration = errors.New("no applied generation is available")

const stagedGenerationRetention = 8

type managedCoreState interface {
	Snapshot(context.Context) (storage.Snapshot, error)
	GenerationConfig(context.Context, int64) ([]byte, string, error)
}

type managedCoreArtifactState interface {
	GenerationArtifacts(context.Context, int64) (storage.GenerationArtifacts, error)
}

type managedCoreSelectionState interface {
	GenerationArtifacts(context.Context, int64) (storage.GenerationArtifacts, error)
	Declaration(context.Context, uint64) (storage.DeclarationRevision, error)
	CurrentSelectionIntent(context.Context) (storage.SelectionIntent, bool, error)
}

type generationFiles interface {
	Stage(context.Context, int64, []byte, string) (string, error)
}

type generationPruner interface {
	PruneStagedGenerations(context.Context, []int64, int) ([]int64, error)
}

type generationBinder interface {
	BindConfig(string, string) error
}

type supervisorEngine interface {
	Run(context.Context) error
	WaitReady(context.Context) error
	Start(context.Context) error
	Stop(context.Context) error
	ResetCircuit(context.Context) error
	Snapshot() core.Snapshot
}

type generationCheckFunc func(context.Context, string, string, io.Writer, io.Writer) error

type selectorControl interface {
	Select(context.Context, string, string) error
	Current(context.Context, string) (coreapi.SelectorSnapshot, error)
}

type connectionsControl interface {
	Snapshot(context.Context) (coreapi.ConnectionsSnapshot, error)
}

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
	selector    selectorControl
	connections connectionsControl
	stdout      *core.RingBuffer
	stderr     *core.RingBuffer

	transitionMu     sync.Mutex
	pollInterval     time.Duration
	applyKeepRunning bool
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
	selector, err := coreapi.NewSelectorClient(options.ControlEndpoint, options.ControlSecret)
	if err != nil {
		return nil, err
	}
	connections, err := coreapi.NewConnectionsClient(options.ControlEndpoint, options.ControlSecret)
	if err != nil {
		return nil, err
	}
	managed := newManagedCore(state, files, runner, supervisor, probe, check, stdout, stderr)
	managed.selector = selector
	managed.connections = connections
	return managed, nil
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

func (m *ManagedCore) WaitReady(ctx context.Context) error {
	return m.supervisor.WaitReady(ctx)
}

func (m *ManagedCore) Snapshot() core.Snapshot {
	return m.supervisor.Snapshot()
}

func (m *ManagedCore) Connections(ctx context.Context) (coreapi.ConnectionsSnapshot, error) {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	if m.connections == nil {
		return coreapi.ConnectionsSnapshot{}, errors.New("core connections control is not configured")
	}
	if m.supervisor.Snapshot().State != core.StateRunning {
		return coreapi.ConnectionsSnapshot{}, core.ErrNotRunning
	}
	return m.connections.Snapshot(ctx)
}

func (m *ManagedCore) SelectCurrent(ctx context.Context, outboundTag string) error {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	if m.selector == nil {
		return errors.New("core selector control is not configured")
	}
	if m.supervisor.Snapshot().State != core.StateRunning {
		return core.ErrNotRunning
	}
	return m.selector.Select(ctx, compiler.CurrentSelectedOutboundTag, outboundTag)
}

func (m *ManagedCore) CurrentSelection(ctx context.Context) (string, error) {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	if m.selector == nil {
		return "", errors.New("core selector control is not configured")
	}
	if m.supervisor.Snapshot().State != core.StateRunning {
		return "", core.ErrNotRunning
	}
	snapshot, err := m.selector.Current(ctx, compiler.CurrentSelectedOutboundTag)
	if err != nil {
		return "", err
	}
	return snapshot.Now, nil
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
	if err := m.waitRunning(ctx); err != nil {
		return err
	}
	if err := m.restoreSelectionForGeneration(ctx, generation.ID); err != nil {
		stopErr := m.supervisor.Stop(ctx)
		return errors.Join(fmt.Errorf("restore current selection after core start: %w", err), stopErr)
	}
	return nil
}

func (m *ManagedCore) Stop(ctx context.Context) error {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()
	return m.supervisor.Stop(ctx)
}

func (m *ManagedCore) ReconcileRecovery(ctx context.Context) error {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()

	snapshot, err := m.state.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("read persisted state before recovery reconcile: %w", err)
	}
	if !snapshot.RecoveryRequired {
		return nil
	}

	switch snapshot.CoreDesiredState {
	case storage.CoreDesiredStopped:
		if err := m.supervisor.Stop(ctx); err != nil && !errors.Is(err, core.ErrNotRunning) {
			return fmt.Errorf("enforce stopped core during recovery reconcile: %w", err)
		}
		return nil
	case storage.CoreDesiredRunning:
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
		if err := m.restartLocked(ctx, true); err != nil {
			return fmt.Errorf("restore applied generation during recovery reconcile: %w", err)
		}
		if err := m.restoreSelectionForGeneration(ctx, generation.ID); err != nil {
			return fmt.Errorf("restore current selection during recovery reconcile: %w", err)
		}
		if err := m.probe.Ready(ctx, nil); err != nil {
			return fmt.Errorf("verify recovered applied generation: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("%w: %q", storage.ErrInvalidCoreDesiredState, snapshot.CoreDesiredState)
	}
}

func (m *ManagedCore) Check(ctx context.Context, generation Generation) error {
	if err := m.verifyGenerationArtifacts(ctx, generation); err != nil {
		return err
	}
	if err := m.pruneStagedGenerations(ctx, generation.ID); err != nil {
		return err
	}
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

func (m *ManagedCore) Verify(ctx context.Context, generation Generation) error {
	m.transitionMu.Lock()
	defer m.transitionMu.Unlock()

	if err := m.waitRunning(ctx); err != nil {
		return err
	}
	if err := m.restoreSelectionForGeneration(ctx, generation.ID); err != nil {
		return fmt.Errorf("restore current selection for candidate generation: %w", err)
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
	if err := m.restoreSelectionForGeneration(ctx, previous.ID); err != nil {
		return fmt.Errorf("restore current selection after rollback: %w", err)
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
	if err := m.verifyGenerationArtifacts(ctx, generation); err != nil {
		return err
	}
	if err := m.pruneStagedGenerations(ctx, generation.ID); err != nil {
		return err
	}
	path, err := m.files.Stage(ctx, generation.ID, generation.Config, generation.SHA256)
	if err != nil {
		return fmt.Errorf("stage generation %d: %w", generation.ID, err)
	}
	if err := m.binder.BindConfig(path, generation.SHA256); err != nil {
		return fmt.Errorf("bind generation %d: %w", generation.ID, err)
	}
	return nil
}

func (m *ManagedCore) pruneStagedGenerations(ctx context.Context, generationID int64) error {
	pruner, ok := m.files.(generationPruner)
	if !ok {
		return nil
	}
	snapshot, err := m.state.Snapshot(ctx)
	if err != nil {
		return fmt.Errorf("read state before staged generation cleanup: %w", err)
	}

	protected := make([]int64, 0, 3)
	seen := make(map[int64]struct{}, 3)
	addProtected := func(id int64) {
		if id <= 0 {
			return
		}
		if _, exists := seen[id]; exists {
			return
		}
		seen[id] = struct{}{}
		protected = append(protected, id)
	}
	addProtected(generationID)
	if snapshot.AppliedGenerationID != nil {
		addProtected(*snapshot.AppliedGenerationID)
	}
	if snapshot.LastKnownGoodGenerationID != nil {
		addProtected(*snapshot.LastKnownGoodGenerationID)
	}

	if _, err := pruner.PruneStagedGenerations(ctx, protected, stagedGenerationRetention); err != nil {
		return fmt.Errorf("prune staged generations: %w", err)
	}
	return nil
}

func (m *ManagedCore) restoreSelectionForGeneration(ctx context.Context, generationID int64) error {
	if m.selector == nil {
		return nil
	}
	state, ok := m.state.(managedCoreSelectionState)
	if !ok {
		return nil
	}
	intent, exists, err := state.CurrentSelectionIntent(ctx)
	if err != nil {
		return fmt.Errorf("read persisted current selection: %w", err)
	}
	if !exists {
		return nil
	}
	target, err := decodeSelectionTarget(intent.TargetJSON)
	if err != nil {
		return err
	}
	artifacts, err := state.GenerationArtifacts(ctx, generationID)
	if err != nil {
		return fmt.Errorf("load generation %d metadata for current selection: %w", generationID, err)
	}
	if len(artifacts.ManifestJSON) == 0 {
		return fmt.Errorf("generation %d has no declaration provenance for persisted current selection", generationID)
	}
	var manifest compiler.NativeManifest
	if err := json.Unmarshal(artifacts.ManifestJSON, &manifest); err != nil {
		return fmt.Errorf("decode generation %d manifest for current selection: %w", generationID, err)
	}
	if manifest.DeclarationRevision == 0 || manifest.DeclarationSHA256 == "" {
		return fmt.Errorf("generation %d has no declaration binding for persisted current selection", generationID)
	}
	stored, err := state.Declaration(ctx, manifest.DeclarationRevision)
	if err != nil {
		return fmt.Errorf("load declaration revision %d for current selection: %w", manifest.DeclarationRevision, err)
	}
	if stored.SHA256 != manifest.DeclarationSHA256 {
		return fmt.Errorf(
			"generation %d declaration hash mismatch for current selection: state=%s manifest=%s",
			generationID,
			stored.SHA256,
			manifest.DeclarationSHA256,
		)
	}
	runtimeTag, err := declaration.CurrentSelectionRuntimeTag(stored.DocumentJSON, target)
	if err != nil {
		return fmt.Errorf("resolve persisted current selection against declaration revision %d: %w", stored.Revision, err)
	}
	if err := m.selector.Select(ctx, compiler.CurrentSelectedOutboundTag, runtimeTag); err != nil {
		return fmt.Errorf("apply persisted current selection %q: %w", runtimeTag, err)
	}
	return nil
}

func (m *ManagedCore) verifyGenerationArtifacts(ctx context.Context, generation Generation) error {
	state, ok := m.state.(managedCoreArtifactState)
	if !ok {
		return nil
	}
	artifacts, err := state.GenerationArtifacts(ctx, generation.ID)
	if err != nil {
		return fmt.Errorf("load generation %d metadata: %w", generation.ID, err)
	}
	if len(artifacts.ManifestJSON) == 0 && len(artifacts.SourceMapJSON) == 0 &&
		artifacts.ManifestSHA256 == "" && artifacts.SourceMapSHA256 == "" {
		return nil
	}
	if len(artifacts.ManifestJSON) == 0 || len(artifacts.SourceMapJSON) == 0 ||
		artifacts.ManifestSHA256 == "" || artifacts.SourceMapSHA256 == "" {
		return fmt.Errorf("generation %d metadata is incomplete", generation.ID)
	}
	if artifacts.ConfigSHA256 != generation.SHA256 {
		return fmt.Errorf("generation %d config hash mismatch: state=%s candidate=%s", generation.ID, artifacts.ConfigSHA256, generation.SHA256)
	}
	configSum := sha256.Sum256(generation.Config)
	if hex.EncodeToString(configSum[:]) != generation.SHA256 {
		return fmt.Errorf("generation %d candidate config bytes do not match SHA-256", generation.ID)
	}
	if !bytes.Equal(artifacts.ConfigJSON, generation.Config) {
		return fmt.Errorf("generation %d candidate config bytes differ from persisted generation", generation.ID)
	}
	if err := verifyMetadataHash("manifest", artifacts.ManifestJSON, artifacts.ManifestSHA256); err != nil {
		return fmt.Errorf("generation %d: %w", generation.ID, err)
	}
	if err := verifyMetadataHash("source map", artifacts.SourceMapJSON, artifacts.SourceMapSHA256); err != nil {
		return fmt.Errorf("generation %d: %w", generation.ID, err)
	}
	if !json.Valid(artifacts.SourceMapJSON) {
		return fmt.Errorf("generation %d source map is not valid JSON", generation.ID)
	}

	var manifest compiler.NativeManifest
	if err := json.Unmarshal(artifacts.ManifestJSON, &manifest); err != nil {
		return fmt.Errorf("generation %d decode native manifest: %w", generation.ID, err)
	}
	if manifest.SchemaID != compiler.NativeSchemaID {
		return fmt.Errorf("generation %d manifest schema %q is unsupported", generation.ID, manifest.SchemaID)
	}
	if manifest.ConfigSHA256 != generation.SHA256 {
		return fmt.Errorf("generation %d manifest config hash mismatch: %s", generation.ID, manifest.ConfigSHA256)
	}
	if err := manifest.ValidateDeclarationBinding(false); err != nil {
		return fmt.Errorf("generation %d declaration provenance: %w", generation.ID, err)
	}
	for _, ruleSet := range manifest.RuleSets {
		extension := ""
		switch ruleSet.Format {
		case compiler.RuleSetFormatSource:
			extension = ".json"
		case compiler.RuleSetFormatBinary:
			extension = ".srs"
		default:
			return fmt.Errorf("generation %d rule-set %q has unsupported format %q", generation.ID, ruleSet.Ref, ruleSet.Format)
		}
		if filepath.Base(ruleSet.RuntimePath) != ruleSet.SHA256+extension {
			return fmt.Errorf("generation %d rule-set %q runtime path is not content-addressed", generation.ID, ruleSet.Ref)
		}
		if err := coreartifact.VerifyRuleSet(ruleSet.RuntimePath, ruleSet.SHA256); err != nil {
			return fmt.Errorf("generation %d verify rule-set %q: %w", generation.ID, ruleSet.Ref, err)
		}
	}
	return nil
}

func verifyMetadataHash(name string, content []byte, expected string) error {
	sum := sha256.Sum256(content)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("%s SHA-256 mismatch: got %s want %s", name, actual, expected)
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
