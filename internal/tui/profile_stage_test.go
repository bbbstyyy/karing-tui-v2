package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

type snapshotStageTUIFake struct {
	*fakeAPI
	preview        apiv1.ProfileDeclarationPreviewResponse
	stage          apiv1.ProfileDeclarationStageResponse
	previewError   error
	stageError     error
	previewCalls   int
	stageCalls     int
	previewID      string
	stageID        string
	previewRequest apiv1.ProfileDeclarationPreviewRequest
	stageRequest   apiv1.ProfileDeclarationStageRequest
}

func newSnapshotStageTUIFake() *snapshotStageTUIFake {
	snapshot := int64(24)
	applied := int64(17)
	return &snapshotStageTUIFake{
		fakeAPI: &fakeAPI{
			status: apiv1.StatusResponse{
				APIVersion: apiv1.Version, CoreConfigured: true,
				DeclarationRevision: 9, ConfigRevision: 4,
				AppliedGenerationID:       &applied,
				LastKnownGoodGenerationID: &applied,
			},
			profiles: []apiv1.ProfileSourceResponse{{
				ProfileID: "source-1", Revision: 6,
				Source: apiv1.ProfileSourceSpec{
					Format: "clash-yaml", Enabled: true,
					Location: "https://hidden.invalid/sub?token=PRIVATE_TOKEN",
				},
				CurrentSnapshotID: &snapshot,
				LastError:         "upstream credential=SECRET_NEVER_RENDER",
			}},
		},
		preview: apiv1.ProfileDeclarationPreviewResponse{
			ProfileID: "source-1", SnapshotID: snapshot,
			SourceRevision: 6, BaseDeclarationRevision: 9,
			SnapshotNodeCount: 3, EffectiveNodeCount: 3,
			AddedNodeCount: 1, RemovedNodeCount: 1, RetainedNodeCount: 2,
			AddedNodeIDs:         []string{"node-added"},
			RemovedNodeIDs:       []string{"node-removed"},
			RetainedNodeIDs:      []string{"node-old-1", "node-old-2"},
			CandidateSHA256:      strings.Repeat("a", 64),
			RuntimeOverlaySHA256: strings.Repeat("b", 64),
		},
		stage: apiv1.ProfileDeclarationStageResponse{
			ProfileID: "source-1", SnapshotID: snapshot,
			SourceRevision: 6, DeclarationRevision: 10,
			DeclarationSHA256: strings.Repeat("a", 64),
		},
	}
}

func (f *snapshotStageTUIFake) PreviewProfileDeclaration(ctx context.Context, id string,
	req apiv1.ProfileDeclarationPreviewRequest) (apiv1.ProfileDeclarationPreviewResponse, error) {
	f.previewCalls++
	f.previewID, f.previewRequest = id, req
	if _, ok := ctx.Deadline(); !ok {
		return apiv1.ProfileDeclarationPreviewResponse{}, errors.New("preview without bound")
	}
	return f.preview, f.previewError
}

func (f *snapshotStageTUIFake) StageProfileDeclaration(ctx context.Context, id string,
	req apiv1.ProfileDeclarationStageRequest) (apiv1.ProfileDeclarationStageResponse, error) {
	f.stageCalls++
	f.stageID, f.stageRequest = id, req
	if _, ok := ctx.Deadline(); !ok {
		return apiv1.ProfileDeclarationStageResponse{}, errors.New("stage without bound")
	}
	if f.stageError == nil {
		f.status.DeclarationRevision = f.stage.DeclarationRevision
	}
	return f.stage, f.stageError
}

func profileStageKey(ch rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}}
}

func readySnapshotStageTUI(t *testing.T, api *snapshotStageTUIFake) Model {
	t.Helper()
	m := NewModel(context.Background(), api)
	m.width, m.height = 90, 24
	m, _ = updated(t, m, statusLoaded{request: 1, value: api.status})
	m, _ = updated(t, m, profilesLoaded{request: 1,
		value: apiv1.ProfileSourceListResponse{Profiles: api.profiles}})
	m, _ = updated(t, m, profileStageKey('2'))
	if !m.statusReady || !m.profilesReady || m.page != profilesPage {
		t.Fatal("profile-stage fixture not ready")
	}
	return m
}

func previewSnapshotStageTUI(t *testing.T, m Model) (Model, tea.Cmd) {
	t.Helper()
	m, cmd := updated(t, m, profileStageKey('b'))
	if cmd == nil || !m.profileStage.previewing || m.profileStage.pending != nil {
		t.Fatal("b did not schedule a read-only source preview")
	}
	return m, cmd
}

func TestSnapshotStageTUIRequiresDiffPreviewConfirmAndDurableReadback(t *testing.T) {
	api := newSnapshotStageTUIFake()
	m := readySnapshotStageTUI(t, api)
	m, cmd := previewSnapshotStageTUI(t, m)
	if api.previewCalls != 0 || api.stageCalls != 0 {
		t.Fatal("beginning snapshot stage performed synchronous I/O")
	}
	m, rejected := updated(t, m, profileStageKey('y'))
	if rejected != nil || api.stageCalls != 0 {
		t.Fatal("confirmation before preview was admitted")
	}
	m, _ = updated(t, m, cmd())
	if api.previewCalls != 1 || api.previewID != "source-1" ||
		api.previewRequest.SnapshotID != 24 ||
		api.previewRequest.ExpectedDeclarationRevision != 9 ||
		m.profileStage.pending == nil || api.stageCalls != 0 {
		t.Fatalf("preview not bound to accepted snapshot/base: %+v", m.profileStage)
	}
	view := m.View()
	for _, want := range []string{
		"Node diff: +1 added  -1 removed  =2 retained",
		"Candidate", "Declaration SHA256", "Overlay SHA256",
		"NOT Core check", "y: CONFIRM stage ONLY",
	} {
		if want == "Candidate" {
			continue
		}
		if !strings.Contains(view, want) {
			t.Fatalf("review lacks %q: %s", want, view)
		}
	}
	for _, secret := range []string{"PRIVATE_TOKEN", "SECRET_NEVER_RENDER", "hidden.invalid"} {
		if strings.Contains(view, secret) {
			t.Fatalf("source secrets leaked into preview: %q", view)
		}
	}
	m, stageCmd := updated(t, m, profileStageKey('y'))
	if stageCmd == nil || !m.profileStage.writing || api.stageCalls != 0 {
		t.Fatal("explicit confirmation did not schedule one stage")
	}
	m, ignored := updated(t, m, profileStageKey('y'))
	if ignored != nil || api.stageCalls != 0 {
		t.Fatal("duplicate stage was issued during write")
	}
	m, readbackCmd := updated(t, m, stageCmd())
	if api.stageCalls != 1 || api.stageID != "source-1" ||
		api.stageRequest.SnapshotID != 24 ||
		api.stageRequest.ExpectedSourceRevision != 6 ||
		api.stageRequest.ExpectedDeclarationRevision != 9 ||
		api.stageRequest.CandidateSHA256 != strings.Repeat("a", 64) ||
		api.stageRequest.RuntimeOverlaySHA256 != strings.Repeat("b", 64) ||
		!m.profileStage.awaitingReadback || readbackCmd == nil {
		t.Fatalf("stage was not SHA and revision bound: %+v", api.stageRequest)
	}
	m, _ = updated(t, m, readbackCmd())
	if m.profileStage.awaitingReadback ||
		!strings.Contains(m.profileStage.notice, "Verified staged declaration rev 10") ||
		api.status.ConfigRevision != 4 ||
		api.status.AppliedGenerationID == nil || *api.status.AppliedGenerationID != 17 ||
		api.stageCalls != 1 {
		t.Fatalf("stage was confused with Core apply: %+v", m.profileStage)
	}
}

func TestSnapshotStageTUIRejectsForgedPreviewWithoutLeakingSecrets(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*apiv1.ProfileDeclarationPreviewResponse)
	}{
		{"wrong profile", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.ProfileID = "source-2" }},
		{"wrong snapshot", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.SnapshotID = 25 }},
		{"wrong source rev", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.SourceRevision++ }},
		{"stale base", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.BaseDeclarationRevision++ }},
		{"incorrect counts", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.AddedNodeCount++ }},
		{"more effective than source", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.SnapshotNodeCount = 2 }},
		{"duplicate sampled node", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.RetainedNodeIDs[0] = "node-added" }},
		{"missing sample", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.RemovedNodeIDs = nil }},
		{"forged truncation", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.AddedIDsTruncated = true }},
		{"unsafe stable ID", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.AddedNodeIDs[0] = "https://a?token=SUPER_SECRET" }},
		{"oversized node count", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.EffectiveNodeCount = 10001 }},
		{"bad digest", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.CandidateSHA256 = "SECRET_DIGEST" }},
		{"already applied", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.Applied = true }},
		{"Core-checked claim", func(p *apiv1.ProfileDeclarationPreviewResponse) { p.CoreValidated = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newSnapshotStageTUIFake()
			tc.change(&api.preview)
			m := readySnapshotStageTUI(t, api)
			m, cmd := previewSnapshotStageTUI(t, m)
			m, _ = updated(t, m, cmd())
			m, confirm := updated(t, m, profileStageKey('y'))
			if confirm != nil || m.profileStage.pending != nil || api.stageCalls != 0 ||
				!strings.Contains(m.View(), "no write sent") ||
				strings.Contains(m.View(), "SUPER_SECRET") ||
				strings.Contains(m.View(), "SECRET_DIGEST") {
				t.Fatalf("unsafe preview permitted stage or leaked input: %q", m.View())
			}
		})
	}
}

func TestSnapshotStageTUICancelResizeStaleReplyAndSourceGuard(t *testing.T) {
	api := newSnapshotStageTUIFake()
	m := readySnapshotStageTUI(t, api)
	m, cmd := previewSnapshotStageTUI(t, m)
	late := cmd()
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	m, _ = updated(t, m, late)
	if m.profileStage.pending != nil || api.stageCalls != 0 {
		t.Fatal("late reply after Esc authorized stage")
	}
	m, cmd = previewSnapshotStageTUI(t, m)
	m, _ = updated(t, m, cmd())
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 40, Height: 8})
	m, unsafe := updated(t, m, profileStageKey('y'))
	if unsafe != nil || m.profileStage.pending != nil || api.stageCalls != 0 {
		t.Fatal("resize did not cancel an unconfirmed stage")
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 90, Height: 24})
	m, cmd = previewSnapshotStageTUI(t, m)
	m, _ = updated(t, m, cmd())
	m.profiles[0].Revision++
	m, unsafe = updated(t, m, profileStageKey('y'))
	if unsafe != nil || api.stageCalls != 0 {
		t.Fatal("changed source revision was staged")
	}
	m, cmd = previewSnapshotStageTUI(t, readySnapshotStageTUI(t, api))
	m, _ = updated(t, m, cmd())
	m, _ = updated(t, m, profileStageKey('1'))
	if m.page != profilesPage || m.profileStage.pending == nil || api.stageCalls != 0 {
		t.Fatal("modal stage confirmation unexpectedly allowed page navigation")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.profileStage.pending != nil || api.stageCalls != 0 {
		t.Fatal("Esc failed to discard a pending stage")
	}
}

func TestSnapshotStageTUIFailClosedUnavailableSourcesAndLegacyAPI(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*Model)
	}{
		{"no initial declaration", func(m *Model) { m.status.DeclarationRevision = 0 }},
		{"missing status", func(m *Model) { m.statusReady = false }},
		{"recovering", func(m *Model) { m.status.RecoveryRequired = true }},
		{"busy daemon", func(m *Model) { m.status.ActiveOperation = "apply" }},
		{"partial profile list", func(m *Model) { m.profilesTruncated = true }},
		{"disabled profile", func(m *Model) { m.profiles[0].Enabled = false }},
		{"missing snapshot", func(m *Model) { m.profiles[0].CurrentSnapshotID = nil }},
		{"untrusted ID", func(m *Model) { m.profiles[0].ProfileID = "https://host?token=PRIVATE" }},
		{"invalid format", func(m *Model) { m.profiles[0].Format = "unknown" }},
		{"small terminal", func(m *Model) { m.width, m.height = 60, 10 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newSnapshotStageTUIFake()
			m := readySnapshotStageTUI(t, api)
			tc.mutate(&m)
			m, cmd := updated(t, m, profileStageKey('b'))
			if cmd != nil || m.profileStage.active() || api.stageCalls != 0 ||
				strings.Contains(m.View(), "PRIVATE") {
				t.Fatal("invalid status/source permitted stage")
			}
		})
	}
	api := &fakeAPI{}
	m := NewModel(context.Background(), api)
	m, _ = updated(t, m, profileStageKey('2'))
	m, cmd := updated(t, m, profileStageKey('b'))
	if cmd != nil || !strings.Contains(m.View(), "API unavailable") {
		t.Fatal("legacy read-only TUI should not attempt snapshot stage")
	}
	if err := profile.ValidateProfileID("source-1"); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotStageTUIUncertainResponseAndReadbackNeverAutoRetry(t *testing.T) {
	api := newSnapshotStageTUIFake()
	api.stageError = errors.New("https://private.invalid?token=SHOULD_NOT_LEAK")
	m := readySnapshotStageTUI(t, api)
	m, cmd := previewSnapshotStageTUI(t, m)
	m, _ = updated(t, m, cmd())
	m, stage := updated(t, m, profileStageKey('y'))
	m, statusCmd := updated(t, m, stage())
	if statusCmd == nil || m.profileStage.awaitingReadback ||
		!strings.Contains(m.profileStage.notice, "NEVER auto-retry") ||
		strings.Contains(m.View(), "SHOULD_NOT_LEAK") {
		t.Fatal("uncertain stage was treated as durable success")
	}
	m, _ = updated(t, m, statusCmd())
	m, duplicate := updated(t, m, profileStageKey('y'))
	if duplicate != nil || api.stageCalls != 1 {
		t.Fatal("uncertain stage silently retried")
	}

	api = newSnapshotStageTUIFake()
	m = readySnapshotStageTUI(t, api)
	m, cmd = previewSnapshotStageTUI(t, m)
	m, _ = updated(t, m, cmd())
	m, stage = updated(t, m, profileStageKey('y'))
	m, statusCmd = updated(t, m, stage())
	if !m.profileStage.awaitingReadback {
		t.Fatal("successful-looking reply did not require readback")
	}
	api.status.ConfigRevision++
	m, _ = updated(t, m, statusCmd())
	if !strings.Contains(m.profileStage.notice, "inconsistent") ||
		strings.Contains(m.profileStage.notice, "Verified staged") ||
		api.stageCalls != 1 {
		t.Fatal("changed Core generation/config was treated as safe stage success")
	}
}
