package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

func selectedSnapshotStageTUI(t *testing.T, api *snapshotStageTUIFake) Model {
	t.Helper()
	m := readySnapshotStageTUI(t, api)
	var load tea.Cmd
	m, load = updated(t, m, profileStageKey('3'))
	if m.page != nodesPage || load == nil {
		t.Fatal("could not enter the current accepted nodes page")
	}
	snapshot := int64(24)
	m, _ = updated(t, m, nodesLoaded{
		request: m.nodesRequest, profileID: "source-1", offset: 0,
		value: apiv1.ProfileNodeListResponse{
			ProfileID: "source-1", SnapshotID: &snapshot,
			Total: 2, Limit: nodePageSize, Offset: 0,
			Nodes: []apiv1.ProfileNodeSummary{
				{NodeID: "node-disabled", DisplayName: "disabled", Disabled: true},
				{NodeID: "node-added", DisplayName: "masked", Disabled: false},
			},
		},
	})
	if !m.nodesReady {
		t.Fatal("nodes page was not loaded")
	}
	m.nodesScroll = 1
	if !strings.Contains(m.View(), "m: PREVIEW selected rebind") {
		t.Fatal("Nodes page did not explain that replacement requires preview")
	}
	return m
}

func TestTUINodesExplicitChoicePreviewStageAndReadback(t *testing.T) {
	api := newSnapshotStageTUIFake()
	api.preview.ReplacementSelectedNodeID = "node-added"
	api.stage.ReplacementSelectedNodeID = "node-added"
	m := selectedSnapshotStageTUI(t, api)
	m, cmd := updated(t, m, profileStageKey('m'))
	if cmd == nil || m.page != profilesPage || !m.profileStage.previewing ||
		m.profileStage.context.replacementSelectedNodeID != "node-added" ||
		api.previewCalls != 0 || api.stageCalls != 0 {
		t.Fatal("explicit node choice did not schedule an isolated preview")
	}
	m, ignored := updated(t, m, profileStageKey('y'))
	if ignored != nil || api.stageCalls != 0 {
		t.Fatal("stage was possible before preview returned")
	}
	m, _ = updated(t, m, cmd())
	if api.previewCalls != 1 || api.previewRequest.ReplacementSelectedNodeID != "node-added" ||
		api.previewRequest.ExpectedDeclarationRevision != 9 || api.previewRequest.SnapshotID != 24 ||
		m.profileStage.pending == nil {
		t.Fatal("preview did not bind accepted snapshot, revision and exact chosen node")
	}
	view := m.View()
	for _, want := range []string{"EXPLICIT replacement CurrentSelected: node-added", "Node diff: +1", "NOT Core check", "y: CONFIRM stage ONLY"} {
		if !strings.Contains(view, want) {
			t.Fatalf("explicit selected preview omitted %q", want)
		}
	}
	for _, secret := range []string{"PRIVATE_TOKEN", "SECRET_NEVER_RENDER", "hidden.invalid"} {
		if strings.Contains(view, secret) {
			t.Fatalf("untrusted source data leaked to selected preview: %q", secret)
		}
	}
	m, stageCmd := updated(t, m, profileStageKey('y'))
	if stageCmd == nil || !m.profileStage.writing || api.stageCalls != 0 {
		t.Fatal("explicit selected confirmation was not a single bounded stage")
	}
	m, readbackCmd := updated(t, m, stageCmd())
	if api.stageCalls != 1 || api.stageRequest.ReplacementSelectedNodeID != "node-added" ||
		api.stageRequest.CandidateSHA256 != api.preview.CandidateSHA256 ||
		api.stageRequest.RuntimeOverlaySHA256 != api.preview.RuntimeOverlaySHA256 ||
		!m.profileStage.awaitingReadback || readbackCmd == nil {
		t.Fatalf("confirmed selected stage lost exact preview binding: %+v", api.stageRequest)
	}
	m, _ = updated(t, m, readbackCmd())
	if m.profileStage.awaitingReadback || !strings.Contains(m.profileStage.notice, "Verified staged") ||
		api.status.ConfigRevision != 4 || api.status.AppliedGenerationID == nil ||
		*api.status.AppliedGenerationID != 17 || api.stageCalls != 1 {
		t.Fatalf("selected stage was confused with Core Apply: %+v", m.profileStage)
	}
}

func TestTUINodesExplicitChoiceRejectsUnsafeOrStaleSource(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Model)
	}{
		{"disabled node", func(m *Model) { m.nodes.Nodes[1].Disabled = true }},
		{"URL-shaped ID", func(m *Model) { m.nodes.Nodes[1].NodeID = "https://private.example/?token=NEVER_SHOW" }},
		{"unsafe terminal ID", func(m *Model) { m.nodes.Nodes[1].NodeID = "node\ncredential=NEVER_SHOW" }},
		{"stale node snapshot", func(m *Model) { snapshot := int64(25); m.nodes.SnapshotID = &snapshot }},
		{"stale source snapshot", func(m *Model) { snapshot := int64(26); m.profiles[0].CurrentSnapshotID = &snapshot }},
		{"no node snapshot", func(m *Model) { m.nodes.SnapshotID = nil }},
		{"partial profiles", func(m *Model) { m.profilesTruncated = true }},
		{"no nodes", func(m *Model) { m.nodes.Nodes = nil }},
		{"invalid total", func(m *Model) { m.nodes.Total = 1 }},
		{"unavailable nodes", func(m *Model) { m.nodesReady = false }},
		{"source no longer enabled", func(m *Model) { m.profiles[0].Enabled = false }},
		{"incomplete status", func(m *Model) { m.statusReady = false }},
		{"narrow terminal", func(m *Model) { m.width = 50; m.height = 12 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newSnapshotStageTUIFake()
			m := selectedSnapshotStageTUI(t, api)
			tc.change(&m)
			m, cmd := updated(t, m, profileStageKey('m'))
			if cmd != nil || api.previewCalls != 0 || api.stageCalls != 0 ||
				m.page != nodesPage || m.profileStage.active() ||
				strings.Contains(m.View(), "NEVER_SHOW") {
				t.Fatal("stale or unsafe Node page was permitted to stage")
			}
		})
	}
}

func TestTUINodesExplicitPreviewRefusesForgedOrStaleServerReply(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*snapshotStageTUIFake)
	}{
		{"omitted explicit ID", func(a *snapshotStageTUIFake) { a.preview.ReplacementSelectedNodeID = "" }},
		{"wrong explicit ID", func(a *snapshotStageTUIFake) { a.preview.ReplacementSelectedNodeID = "node-untrusted" }},
		{"unsafe raw ID", func(a *snapshotStageTUIFake) {
			a.preview.ReplacementSelectedNodeID = "https://private/?token=NEVER_SHOW"
		}},
		{"preview conflict", func(a *snapshotStageTUIFake) { a.previewError = errors.New("secret https://private/?token=NEVER_SHOW") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newSnapshotStageTUIFake()
			tc.change(api)
			m := selectedSnapshotStageTUI(t, api)
			m, cmd := updated(t, m, profileStageKey('m'))
			m, _ = updated(t, m, cmd())
			m, stage := updated(t, m, profileStageKey('y'))
			if stage != nil || m.profileStage.pending != nil ||
				api.stageCalls != 0 || !strings.Contains(m.profileStage.notice, "no write sent") ||
				strings.Contains(m.View(), "NEVER_SHOW") {
				t.Fatal("untrusted explicit preview authorized a stage or leaked response")
			}
		})
	}
}

func TestTUINodesExplicitChoiceDiscardResizeAndStageReceiptMismatch(t *testing.T) {
	api := newSnapshotStageTUIFake()
	api.preview.ReplacementSelectedNodeID = "node-added"
	api.stage.ReplacementSelectedNodeID = "node-added"
	m := selectedSnapshotStageTUI(t, api)
	m, cmd := updated(t, m, profileStageKey('m'))
	late := cmd()
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	m, _ = updated(t, m, late)
	if m.profileStage.pending != nil || api.stageCalls != 0 {
		t.Fatal("late preview after Esc re-authorized explicit stage")
	}
	m = selectedSnapshotStageTUI(t, api)
	m, cmd = updated(t, m, profileStageKey('m'))
	m, _ = updated(t, m, cmd())
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 45, Height: 12})
	m, unsafe := updated(t, m, profileStageKey('y'))
	if unsafe != nil || m.profileStage.pending != nil || api.stageCalls != 0 {
		t.Fatal("terminal resize failed to cancel explicit choice")
	}
	m = selectedSnapshotStageTUI(t, api)
	m, cmd = updated(t, m, profileStageKey('m'))
	m, _ = updated(t, m, cmd())
	m.profiles[0].Revision++
	m, unsafe = updated(t, m, profileStageKey('y'))
	if unsafe != nil || api.stageCalls != 0 || m.profileStage.pending != nil {
		t.Fatal("changed source revision allowed stale explicit choice")
	}
	m = selectedSnapshotStageTUI(t, api)
	m, cmd = updated(t, m, profileStageKey('m'))
	m, _ = updated(t, m, cmd())
	api.stage.ReplacementSelectedNodeID = "node-impersonated"
	m, stageCmd := updated(t, m, profileStageKey('y'))
	m, statusCmd := updated(t, m, stageCmd())
	if statusCmd == nil || m.profileStage.awaitingReadback ||
		!strings.Contains(m.profileStage.notice, "NEVER auto-retry") || api.stageCalls != 1 {
		t.Fatal("wrong stage replacement echo was trusted as success")
	}
}
