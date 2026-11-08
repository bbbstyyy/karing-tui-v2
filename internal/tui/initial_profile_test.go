package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

type initialTUIFake struct {
	*fakeAPI
	preview        apiv1.InitialProfileDeclarationPreviewResponse
	stage          apiv1.InitialProfileDeclarationStageResponse
	previewErr     error
	stageErr       error
	previewCalls   int
	stageCalls     int
	previewRequest apiv1.InitialProfileDeclarationPreviewRequest
	stageRequest   apiv1.InitialProfileDeclarationStageRequest
}

func (f *initialTUIFake) PreviewInitialProfileDeclaration(
	_ context.Context, _ string, request apiv1.InitialProfileDeclarationPreviewRequest,
) (apiv1.InitialProfileDeclarationPreviewResponse, error) {
	f.previewCalls++
	f.previewRequest = request
	return f.preview, f.previewErr
}

func (f *initialTUIFake) StageInitialProfileDeclaration(
	_ context.Context, _ string, request apiv1.InitialProfileDeclarationStageRequest,
) (apiv1.InitialProfileDeclarationStageResponse, error) {
	f.stageCalls++
	f.stageRequest = request
	if f.stageErr == nil {
		f.status.DeclarationRevision = 1
	}
	return f.stage, f.stageErr
}

func newInitialTUIFake() *initialTUIFake {
	const id = "work"
	const node = "node-selected"
	snapshot := int64(42)
	return &initialTUIFake{
		fakeAPI: &fakeAPI{
			status: apiv1.StatusResponse{
				APIVersion:     apiv1.Version,
				ConfigRevision: 0, DeclarationRevision: 0,
			},
			profiles: []apiv1.ProfileSourceResponse{{
				ProfileID: id, Revision: 3,
				Source:            apiv1.ProfileSourceSpec{Enabled: true},
				CurrentSnapshotID: &snapshot,
			}},
			nodes: map[string]apiv1.ProfileNodeListResponse{
				id: {
					ProfileID: id, SnapshotID: &snapshot, Total: 1,
					Nodes: []apiv1.ProfileNodeSummary{{
						NodeID: node, DisplayName: "safe-node", Disabled: false,
					}},
				},
			},
		},
		preview: apiv1.InitialProfileDeclarationPreviewResponse{
			ProfileID: id, SnapshotID: snapshot, SourceRevision: 3,
			BaseDeclarationRevision: 0, EffectiveNodeCount: 1,
			SelectedNodeID: node, ResolverAddress: "127.0.0.1:5300",
			CandidateSHA256:      strings.Repeat("a", 64),
			RuntimeOverlaySHA256: strings.Repeat("b", 64),
			RoutingMode:          initialRoutingMode,
		},
		stage: apiv1.InitialProfileDeclarationStageResponse{
			ProfileID: id, SnapshotID: snapshot, SourceRevision: 3,
			DeclarationRevision: 1,
			DeclarationSHA256:   strings.Repeat("a", 64),
			RoutingMode:         initialRoutingMode,
		},
	}
}

func initialKey(key string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
}

func initNodesPage(t *testing.T, api *initialTUIFake) Model {
	t.Helper()
	m := NewModel(context.Background(), api)
	m.width, m.height = 90, 25
	m, _ = updated(t, m, statusLoaded{request: 1, value: api.status})
	m, _ = updated(t, m, profilesLoaded{
		request: 1, value: apiv1.ProfileSourceListResponse{Profiles: api.profiles},
	})
	m, cmd := updated(t, m, initialKey("3"))
	if cmd == nil || m.page != nodesPage {
		t.Fatal("failed to enter nodes page")
	}
	m, _ = updated(t, m, cmd())
	if !m.nodesReady {
		t.Fatal("accepted nodes not loaded")
	}
	return m
}

func previewInitialTUI(t *testing.T, m Model) (Model, tea.Cmd) {
	t.Helper()
	m, _ = updated(t, m, initialKey("i"))
	if !m.initial.editing {
		t.Fatalf("no resolver prompt: %s", m.View())
	}
	m, _ = updated(t, m, initialKey("127.0.0.1:5300"))
	if m.initial.resolver != "127.0.0.1:5300" {
		t.Fatal("resolver editor did not capture a local address")
	}
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil || !m.initial.previewing || m.initial.pending != nil {
		t.Fatal("resolver entry did not start read-only preview")
	}
	return m, cmd
}

func TestFirstRunTUIExplicitResolverPreviewConfirmAndReadback(t *testing.T) {
	api := newInitialTUIFake()
	m := initNodesPage(t, api)
	m, previewCmd := previewInitialTUI(t, m)
	if api.previewCalls != 0 || api.stageCalls != 0 {
		t.Fatal("network write occurred before read-only command execution")
	}
	previewMsg := previewCmd()
	m, _ = updated(t, m, previewMsg)
	if api.previewCalls != 1 || api.previewRequest.SnapshotID != 42 ||
		api.previewRequest.SelectedNodeID != "node-selected" ||
		api.previewRequest.ResolverAddress != "127.0.0.1:5300" ||
		!m.initial.active() || m.initial.pending == nil || api.stageCalls != 0 {
		t.Fatalf("invalid preview state: %+v", m.initial)
	}
	view := m.View()
	for _, required := range []string{"CN 28-GROUP RULES NOT PRESENT", "CN not available",
		"Candidate declaration SHA256", "y: CONFIRM"} {
		if !strings.Contains(view, required) {
			t.Fatalf("initial stage review omitted %q: %q", required, view)
		}
	}
	m, cmd := updated(t, m, initialKey("y"))
	if cmd == nil || !m.initial.writing || api.stageCalls != 0 {
		t.Fatal("confirmation did not create a single asynchronous stage command")
	}
	stageMsg := cmd()
	if api.stageCalls != 1 || api.stageRequest.SnapshotID != 42 ||
		api.stageRequest.ExpectedSourceRevision != 3 ||
		api.stageRequest.SelectedNodeID != "node-selected" ||
		api.stageRequest.ResolverAddress != "127.0.0.1:5300" ||
		api.stageRequest.CandidateSHA256 != strings.Repeat("a", 64) ||
		api.stageRequest.RuntimeOverlaySHA256 != strings.Repeat("b", 64) ||
		!api.stageRequest.AcknowledgeProxyOnlyNoCN {
		t.Fatal("stage request was not bound to exact preview digest and explicit acknowledgement")
	}
	m, statusCmd := updated(t, m, stageMsg)
	if statusCmd == nil || m.initial.active() || m.statusReady ||
		!m.initial.awaitingReadback ||
		!strings.Contains(m.initial.notice, "verifying durable declaration") {
		t.Fatalf("stage response prematurely claimed durable success: %+v", m.initial)
	}
	m, _ = updated(t, m, statusCmd())
	if !m.statusReady || m.status.DeclarationRevision != 1 || m.status.ConfigRevision != 0 ||
		m.initial.awaitingReadback || api.stageCalls != 1 || !strings.Contains(m.View(), "CN NOT ready") {
		t.Fatalf("first-run stage changed Core or lost readback: %+v", m.status)
	}
	m, _ = updated(t, m, initialKey("i"))
	if m.initial.editing || api.stageCalls != 1 {
		t.Fatal("nonempty declaration allowed a second initial stage")
	}
}

func TestFirstRunTUIBailsOutWithoutNetworkWrites(t *testing.T) {
	for _, change := range []struct {
		name   string
		mutate func(*Model)
	}{
		{"old declaration", func(m *Model) { m.status.DeclarationRevision = 2 }},
		{"applied revision", func(m *Model) { m.status.ConfigRevision = 1 }},
		{"recovery required", func(m *Model) { m.status.RecoveryRequired = true }},
		{"active operation", func(m *Model) { m.status.ActiveOperation = "apply" }},
		{"source disabled", func(m *Model) { m.profiles[0].Enabled = false }},
		{"snapshot changed", func(m *Model) { *m.nodes.SnapshotID = 999 }},
		{"disabled node", func(m *Model) { m.nodes.Nodes[0].Disabled = true }},
		{"narrow terminal", func(m *Model) { m.width, m.height = 60, 12 }},
		{"missing status", func(m *Model) { m.statusReady = false }},
		{"source truncated", func(m *Model) { m.profilesTruncated = true }},
	} {
		t.Run(change.name, func(t *testing.T) {
			api := newInitialTUIFake()
			m := initNodesPage(t, api)
			change.mutate(&m)
			m, cmd := updated(t, m, initialKey("i"))
			if cmd != nil || m.initial.active() || api.previewCalls != 0 || api.stageCalls != 0 {
				t.Fatal("unsafe first-run setup started")
			}
		})
	}
}

func TestFirstRunTUIInvalidResolverAndCancelledPreviewCannotStage(t *testing.T) {
	api := newInitialTUIFake()
	m := initNodesPage(t, api)
	m, _ = updated(t, m, initialKey("i"))
	m, _ = updated(t, m, initialKey("127.0.0.1:0"))
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil || !m.initial.editing || api.previewCalls != 0 {
		t.Fatal("zero-port resolver preview was allowed")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyCtrlU})
	m, _ = updated(t, m, initialKey("127.0.0.1:5300"))
	m, cmd = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil || !m.initial.previewing {
		t.Fatal("valid DNS address could not be previewed")
	}
	stale := cmd()
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.initial.active() {
		t.Fatal("escape did not discard preview")
	}
	m, _ = updated(t, m, stale)
	m, _ = updated(t, m, initialKey("y"))
	if m.initial.active() || api.stageCalls != 0 {
		t.Fatal("late preview message authorized a stage")
	}
}

func TestFirstRunTUIRejectsForgedOrStalePreviewAndResize(t *testing.T) {
	for _, condition := range []string{"cn-ready", "applied", "wrong-node", "wrong-source-rev", "wrong-digest"} {
		t.Run(condition, func(t *testing.T) {
			api := newInitialTUIFake()
			m := initNodesPage(t, api)
			m, cmd := previewInitialTUI(t, m)
			switch condition {
			case "cn-ready":
				api.preview.CNRulesReady = true
			case "applied":
				api.preview.Applied = true
			case "wrong-node":
				api.preview.SelectedNodeID = "other-node"
			case "wrong-source-rev":
				api.preview.SourceRevision = 4
			case "wrong-digest":
				api.preview.CandidateSHA256 = "TOP_SECRET"
			}
			m, _ = updated(t, m, cmd())
			if m.initial.active() || api.stageCalls != 0 {
				t.Fatal("forged or changed first-run preview reached confirmation")
			}
			if strings.Contains(m.View(), "TOP_SECRET") {
				t.Fatal("untrusted preview detail leaked to TUI")
			}
		})
	}
	api := newInitialTUIFake()
	m := initNodesPage(t, api)
	m, cmd := previewInitialTUI(t, m)
	m, _ = updated(t, m, cmd())
	if m.initial.pending == nil {
		t.Fatal("missing review")
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 60, Height: 12})
	m, _ = updated(t, m, initialKey("y"))
	if m.initial.active() || api.stageCalls != 0 {
		t.Fatal("resized terminal kept executable confirmation")
	}
}

func TestFirstRunTUIUncertainStageDoesNotLeakOrAutoRetry(t *testing.T) {
	api := newInitialTUIFake()
	api.stageErr = errors.New("https://subscription.example?token=TOP_SECRET\x1b[31m")
	m := initNodesPage(t, api)
	m, cmd := previewInitialTUI(t, m)
	m, _ = updated(t, m, cmd())
	m, writeCmd := updated(t, m, initialKey("y"))
	if writeCmd == nil {
		t.Fatal("no stage command")
	}
	m, refreshCmd := updated(t, m, writeCmd())
	if refreshCmd == nil || m.initial.active() ||
		!strings.Contains(m.initial.notice, "NEVER auto-retry") ||
		strings.Contains(m.View(), "TOP_SECRET") ||
		api.stageCalls != 1 {
		t.Fatalf("uncertain stage was claimed successful or exposed secret: %q", m.View())
	}
	m, _ = updated(t, m, initialKey("y"))
	if api.stageCalls != 1 {
		t.Fatal("uncertain first-run stage retried on y without new preview")
	}
}

func TestFirstRunTUICancelOnNavigationAndQuitNeverStages(t *testing.T) {
	api := newInitialTUIFake()
	m := initNodesPage(t, api)
	m, cmd := previewInitialTUI(t, m)
	m, _ = updated(t, m, cmd())
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.initial.active() || api.stageCalls != 0 {
		t.Fatal("escape staged a declaration")
	}
	m, cmd = previewInitialTUI(t, m)
	m, _ = updated(t, m, cmd())
	m, _ = updated(t, m, initialKey("q"))
	if !m.quitting || api.stageCalls != 0 {
		t.Fatal("quitting confirmation triggered unexpected stage")
	}
}

func TestFirstRunTUIForgedAsyncPreviewCannotPanicOrConfirm(t *testing.T) {
	api := newInitialTUIFake()
	m := initNodesPage(t, api)
	m, _ = previewInitialTUI(t, m)
	sequence := m.initial.sequence
	forged := api.preview
	forged.CandidateSHA256 = "short"
	m, _ = updated(t, m, initialProfilePreviewLoaded{
		sequence: sequence, ok: true, value: forged,
	})
	if m.initial.active() || api.stageCalls != 0 {
		t.Fatal("forged asynchronous preview entered confirmation")
	}
	if strings.Contains(m.View(), "short") {
		t.Fatal("malformed digest leaked into terminal preview")
	}
}

func TestFirstRunTUIDurableReadbackMismatchNeverReportsStageSuccess(t *testing.T) {
	api := newInitialTUIFake()
	m := initNodesPage(t, api)
	m, cmd := previewInitialTUI(t, m)
	m, _ = updated(t, m, cmd())
	m, writeCmd := updated(t, m, initialKey("y"))
	if writeCmd == nil {
		t.Fatal("stage command missing")
	}
	m, readbackCmd := updated(t, m, writeCmd())
	if readbackCmd == nil || !m.initial.awaitingReadback {
		t.Fatal("stage response was not held pending readback")
	}
	// Simulate delayed/stale daemon state after a successful-looking stage
	// receipt. An incorrect readback must never be reported as success.
	api.status.DeclarationRevision = 0
	m, _ = updated(t, m, readbackCmd())
	if m.initial.awaitingReadback || !strings.Contains(m.initial.notice, "uncertain") ||
		strings.Contains(m.View(), "Verified proxy-only") || api.stageCalls != 1 {
		t.Fatalf("stale durable status was accepted: %s", m.View())
	}
}

func TestFirstRunTUIRefusesStaleStateBetweenPreviewAndConfirm(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Model)
	}{
		{"recovery", func(m *Model) { m.status.RecoveryRequired = true }},
		{"declaration", func(m *Model) { m.status.DeclarationRevision = 1 }},
		{"active operation", func(m *Model) { m.status.ActiveOperation = "apply" }},
		{"source revision", func(m *Model) { m.profiles[0].Revision++ }},
		{"disabled selected node", func(m *Model) { m.nodes.Nodes[0].Disabled = true }},
		{"changed node response", func(m *Model) { m.nodesRequest++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newInitialTUIFake()
			m := initNodesPage(t, api)
			m, previewCmd := previewInitialTUI(t, m)
			m, _ = updated(t, m, previewCmd())
			if m.initial.pending == nil {
				t.Fatal("baseline first-run preview missing")
			}
			tc.mutate(&m)
			m, stageCmd := updated(t, m, initialKey("y"))
			if stageCmd != nil || api.stageCalls != 0 || m.initial.active() {
				t.Fatal("changed source or runtime state authorized a stale first-run stage")
			}
			if !strings.Contains(m.initial.notice, "no write sent") {
				t.Fatal("stale confirmation did not explain that no write was sent")
			}
		})
	}
}
