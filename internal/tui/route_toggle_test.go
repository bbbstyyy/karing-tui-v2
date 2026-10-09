package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func (f *fakeAPI) RouteEditContext(context.Context) (apiv1.RouteEditContext, error) {
	return apiv1.RouteEditContext{}, errors.New("not configured")
}
func (f *fakeAPI) PreviewRouteEdit(context.Context, apiv1.RouteEditRequest) (apiv1.RouteEditPreviewResponse, error) {
	return apiv1.RouteEditPreviewResponse{}, errors.New("not configured")
}
func (f *fakeAPI) StageRouteEdit(context.Context, apiv1.RouteEditStageRequest) (apiv1.RouteEditStageResponse, error) {
	return apiv1.RouteEditStageResponse{}, errors.New("not configured")
}

type routeToggleFakeAPI struct {
	*configInspectFakeAPI
	contextValue apiv1.RouteEditContext
	contextError error
	previewError error
	stageError   error
	contextCalls int
	previewCalls int
	stageCalls   int
	lastPreview  apiv1.RouteEditRequest
	lastStage    apiv1.RouteEditStageRequest
}

func newRouteToggleFake() *routeToggleFakeAPI {
	snapshot := configInspectFixture()
	snapshot.CurrentDeclarationRevision = snapshot.AppliedDeclarationRevision
	snapshot.StagedUnapplied, snapshot.RoutingChanged, snapshot.DNSChanged = false, false, false
	id := snapshot.GenerationID
	return &routeToggleFakeAPI{
		configInspectFakeAPI: &configInspectFakeAPI{fakeAPI: &fakeAPI{}, value: snapshot},
		contextValue: apiv1.RouteEditContext{
			APIVersion: apiv1.Version, DeclarationRevision: snapshot.CurrentDeclarationRevision,
			DeclarationSHA256: strings.Repeat("a", 64), ConfigRevision: snapshot.ConfigRevision,
			AppliedGenerationID: &id, SelectionRevision: 5,
		},
	}
}

func (f *routeToggleFakeAPI) RouteEditContext(ctx context.Context) (apiv1.RouteEditContext, error) {
	f.contextCalls++
	if _, ok := ctx.Deadline(); !ok {
		return apiv1.RouteEditContext{}, errors.New("missing deadline")
	}
	return f.contextValue, f.contextError
}
func (f *routeToggleFakeAPI) PreviewRouteEdit(ctx context.Context, r apiv1.RouteEditRequest) (apiv1.RouteEditPreviewResponse, error) {
	f.previewCalls++
	f.lastPreview = r
	if f.previewError != nil { return apiv1.RouteEditPreviewResponse{}, f.previewError }
	old:=f.value.Layers[0].Groups[0]
	before,afterEnabled,afterTarget,afterDNS:=old.Enabled,old.Enabled,old.Target,old.DNSProfile
	if r.Enabled != nil { afterEnabled=*r.Enabled }
	if r.Target != nil { afterTarget=*r.Target }
	if r.DNSProfileID != nil { afterDNS=*r.DNSProfileID }
	return apiv1.RouteEditPreviewResponse{
		APIVersion:apiv1.Version,Request:r,Origin:"cn_preset_override",
		BeforeEnabled:before,AfterEnabled:afterEnabled,
		BeforeTarget:old.Target,AfterTarget:afterTarget,
		BeforeDNSProfileID:old.DNSProfile,AfterDNSProfileID:afterDNS,
		CandidateSHA256:strings.Repeat("b",64),
		NativeConfigSHA256:strings.Repeat("c",64),NativeSchemaID:"native",
		RouteEntryCount:1,DNSServerCount:2,RuleSetCount:0,
		CompilerValidated:true,
	},nil
}

func (f *routeToggleFakeAPI) StageRouteEdit(ctx context.Context, r apiv1.RouteEditStageRequest) (apiv1.RouteEditStageResponse, error) {
	f.stageCalls++
	f.lastStage = r
	if f.stageError != nil {
		return apiv1.RouteEditStageResponse{}, f.stageError
	}
	f.value.StagedUnapplied = true
	f.value.CurrentDeclarationRevision++
	f.value.RoutingChanged = true
	return apiv1.RouteEditStageResponse{
		DeclarationRevision: r.ExpectedDeclarationRevision + 1,
		DeclarationSHA256:   r.CandidateSHA256, NativeConfigSHA256: r.NativeConfigSHA256,
		CompilerValidated: true, Staged: true,
	}, nil
}

func toggleKey(t *testing.T, m Model, key rune) (Model, tea.Cmd) {
	t.Helper()
	return updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}})
}
func loadedToggleModel(t *testing.T, api *routeToggleFakeAPI) Model {
	t.Helper()
	m := NewModel(context.Background(), api)
	m, load := toggleKey(t, m, '7')
	if load == nil {
		t.Fatal("routing page load not scheduled")
	}
	m, _ = updated(t, m, load())
	if !m.inspection.ready {
		t.Fatal("routing inspection not ready")
	}
	return m
}

func TestRouteToggleRequiresPreviewAndConfirmAndNeverAppliesCore(t *testing.T) {
	api := newRouteToggleFake()
	m := loadedToggleModel(t, api)
	if len(m.inspection.routeRows) != 1 || !strings.Contains(m.View(), "> #1 cn.example") {
		t.Fatalf("missing bounded selected route row: %q", m.View())
	}
	m, preview := toggleKey(t, m, 'e')
	if preview == nil || api.previewCalls != 0 || api.stageCalls != 0 {
		t.Fatal("preview made synchronous write or was not scheduled")
	}
	m, _ = updated(t, m, preview())
	if m.inspection.pending == nil || api.contextCalls != 1 || api.previewCalls != 1 ||
		api.lastPreview.Layer != domain.LayerCustom || api.lastPreview.GroupID != "cn.example" ||
		api.lastPreview.Enabled == nil || *api.lastPreview.Enabled ||
		api.lastPreview.ExpectedSelectionRevision != 5 || api.stageCalls != 0 {
		t.Fatalf("incorrect guarded preview: %+v", m.inspection.pending)
	}
	if strings.Contains(m.View(), "password") || !strings.Contains(m.View(), "y: CONFIRM") {
		t.Fatalf("missing safe confirmation: %q", m.View())
	}
	m, stage := toggleKey(t, m, 'y')
	if stage == nil || api.stageCalls != 0 || !m.inspection.writing {
		t.Fatal("confirmation did not schedule a single asynchronous stage")
	}
	m, reload := updated(t, m, stage())
	if api.stageCalls != 1 || reload == nil || !m.inspection.active ||
		m.inspection.pending != nil || api.lastStage.CandidateSHA256 != strings.Repeat("b", 64) {
		t.Fatal("stage did not invalidate stale inspection")
	}
	m, _ = updated(t, m, reload())
	if !m.inspection.ready || len(m.inspection.routeRows) != 0 ||
		!strings.Contains(m.View(), "staged=true") {
		t.Fatal("staged declaration was incorrectly offered for editing")
	}
	m, unsafe := toggleKey(t, m, 'e')
	if unsafe != nil || api.stageCalls != 1 {
		t.Fatal("duplicate stage allowed after editing applied view")
	}
}

func TestRouteToggleCancelStaleAndUnsafeInspectionAreReadOnly(t *testing.T) {
	api := newRouteToggleFake()
	m := loadedToggleModel(t, api)
	m, preview := toggleKey(t, m, 'e')
	m, _ = updated(t, m, preview())
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	m, command := toggleKey(t, m, 'y')
	if command != nil || api.stageCalls != 0 || m.inspection.pending != nil {
		t.Fatal("Esc did not cancel the preview")
	}
	api.contextValue.DeclarationRevision++
	m, preview = toggleKey(t, m, 'e')
	m, _ = updated(t, m, preview())
	if m.inspection.pending != nil || api.previewCalls != 1 {
		t.Fatal("stale declaration context was accepted")
	}
	api = newRouteToggleFake()
	api.value.StagedUnapplied = true
	api.value.CurrentDeclarationRevision++
	api.value.RoutingChanged = true
	m = loadedToggleModel(t, api)
	if len(m.inspection.routeRows) != 0 {
		t.Fatal("staged drift was editable")
	}
	api = newRouteToggleFake()
	api.value.Layers[0].Groups[0].ID = "https://secret:pw@host.invalid?token=x"
	m = loadedToggleModel(t, api)
	if len(m.inspection.routeRows) != 0 || strings.Contains(m.View(), "secret:pw") {
		t.Fatal("secret-shaped group ID became an editable row")
	}
}

func TestRouteToggleIgnoresLatePreviewAndUncertainStage(t *testing.T) {
	api := newRouteToggleFake()
	m := loadedToggleModel(t, api)
	m, late := toggleKey(t, m, 'e')
	m, _ = toggleKey(t, m, '8')
	m, _ = updated(t, m, late())
	if m.inspection.pending != nil || m.page != dnsInspectPage {
		t.Fatal("late preview crossed inspection page boundary")
	}
	m, _ = toggleKey(t, m, '7')
	m, preview := toggleKey(t, m, 'e')
	m, _ = updated(t, m, preview())
	api.stageError = errors.New("password=SECRET_UPSTREAM")
	m, stage := toggleKey(t, m, 'y')
	m, reload := updated(t, m, stage())
	if reload == nil || api.stageCalls != 1 || !strings.Contains(m.View(), "DO NOT auto-retry") ||
		strings.Contains(m.View(), "SECRET_UPSTREAM") {
		t.Fatal("uncertain stage not handled safely")
	}
	m, _ = updated(t, m, reload())
	if m.inspection.pending != nil || api.stageCalls != 1 {
		t.Fatal("uncertain stage retried automatically")
	}
}
