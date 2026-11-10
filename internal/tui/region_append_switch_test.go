package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	tea "github.com/charmbracelet/bubbletea"
)

// Keep this fixture faithful to generated routing: a disabled auto append has
// no emitted route group, yet its pinned declaration switch still exists.
func regionInspectionFixture(site, ip bool) apiv1.ConfigInspectionResponse {
	raw := configInspectFixture()
	raw.CurrentDeclarationRevision = raw.AppliedDeclarationRevision
	raw.StagedUnapplied, raw.RoutingChanged, raw.DNSChanged = false, false, false
	raw.RegionAppendCode = "cn"
	raw.RegionGeoSiteEnabled, raw.RegionGeoIPEnabled = site, ip
	add := func(index int, id string) {
		raw.Layers[index].GroupCount = 1
		raw.Layers[index].ActiveCount = 1
		raw.Layers[index].Groups = []apiv1.ConfigInspectionRouteGroup{{
			ID: id, Order: 1, Enabled: true, Origin: "region_append",
			MatchKinds: []string{"rule_set"}, Target: domain.TargetRef{Kind: domain.TargetDirect},
		}}
		raw.RouteTotal++
	}
	if site {
		add(1, "region:auto-geosite:cn")
	}
	if ip {
		add(2, "region:auto-geoip:cn")
	}
	return raw
}

func TestRegionTUIProjectsOffSwitchForReenableAndGuardsTargets(t *testing.T) {
	for _, state := range []struct{ site, ip bool }{{false, false}, {true, true}, {true, false}, {false, true}} {
		raw := regionInspectionFixture(state.site, state.ip)
		routing, _, err := projectConfigInspection(raw)
		if err != nil {
			t.Fatal(err)
		}
		rows := projectRouteToggleRows(raw, routing)
		if len(rows) != 3 || rows[1].id != "region:auto-geosite:cn" ||
			rows[2].id != "region:auto-geoip:cn" ||
			rows[1].enabled != state.site || rows[2].enabled != state.ip ||
			rows[1].target.Kind != domain.TargetDirect || rows[2].target.Kind != domain.TargetDirect {
			t.Fatalf("region switches were lost or unlocked: %+v", rows)
		}
		for _, row := range rows[1:] {
			if row.line >= len(routing) || !strings.Contains(routing[row.line], "CN region") {
				t.Fatalf("region metadata row absent: %+v", row)
			}
		}
	}

	unsafe := regionInspectionFixture(true, false)
	unsafe.Layers[1].Groups[0].Target.Kind = domain.TargetBlock
	lines, _, err := projectConfigInspection(unsafe)
	if err != nil {
		t.Fatal(err)
	}
	rows := projectRouteToggleRows(unsafe, lines)
	if len(rows) != 1 {
		t.Fatalf("forged target enabled CN edit: %+v", rows)
	}

	partial := regionInspectionFixture(false, false)
	partial.RouteTruncated = true
	if len(projectRouteToggleRows(partial, nil)) != 0 {
		t.Fatal("truncated config editable")
	}

	staged := regionInspectionFixture(false, false)
	staged.CurrentDeclarationRevision++
	staged.StagedUnapplied = true
	if len(projectRouteToggleRows(staged, nil)) != 0 {
		t.Fatal("unapplied config editable")
	}

	other := regionInspectionFixture(false, false)
	other.RegionAppendCode = "us"
	projected, _, err := projectConfigInspection(other)
	if err != nil {
		t.Fatal(err)
	}
	if len(projectRouteToggleRows(other, projected)) != 1 {
		t.Fatal("non-CN regions editable")
	}
}

type regionRouteFakeAPI struct{ *routeToggleFakeAPI }

func (f *regionRouteFakeAPI) PreviewRouteEdit(ctx context.Context, r apiv1.RouteEditRequest) (apiv1.RouteEditPreviewResponse, error) {
	f.previewCalls++
	f.lastPreview = r
	if r.Enabled == nil || r.Target != nil || r.DNSProfileID != nil ||
		r.Layer != domain.LayerGeoSite || r.GroupID != "region:auto-geosite:cn" {
		return apiv1.RouteEditPreviewResponse{}, errors.New("unexpected region write")
	}
	return apiv1.RouteEditPreviewResponse{
		APIVersion: apiv1.Version, Request: r, Origin: "region_append_toggle",
		BeforeEnabled: f.value.RegionGeoSiteEnabled, AfterEnabled: *r.Enabled,
		BeforeTarget:       domain.TargetRef{Kind: domain.TargetDirect},
		AfterTarget:        domain.TargetRef{Kind: domain.TargetDirect},
		CandidateSHA256:    strings.Repeat("b", 64),
		NativeConfigSHA256: strings.Repeat("c", 64),
		NativeSchemaID:     "native", RouteEntryCount: 2, DNSServerCount: 2,
		CompilerValidated: true,
	}, nil
}
func TestRegionTUIOffToOnPreviewConfirmStageOnly(t *testing.T) {
	base := newRouteToggleFake()
	base.value = regionInspectionFixture(false, true)
	api := &regionRouteFakeAPI{routeToggleFakeAPI: base}
	m := NewModel(context.Background(), api)
	m, loaded := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'7'}})
	if loaded == nil {
		t.Fatal("inspection not scheduled")
	}
	m, _ = updated(t, m, loaded())
	if !m.inspection.ready || len(m.inspection.routeRows) != 3 {
		t.Fatalf("switch unavailable: %+v", m.inspection.routeRows)
	}
	m.inspection.routeSelected = 1 // GeoSite is off; no native matcher exists.
	m, blocked := toggleKey(t, m, 't')
	if blocked != nil || m.inspection.chooser != nil {
		t.Fatal("region target chooser exposed")
	}
	m, blocked = toggleKey(t, m, 'g')
	if blocked != nil || m.inspection.chooser != nil {
		t.Fatal("region DNS chooser exposed")
	}
	m, cmd := toggleKey(t, m, 'e')
	if cmd == nil || api.previewCalls != 0 {
		t.Fatal("region preview is not async")
	}
	m, _ = updated(t, m, cmd())
	if m.inspection.pending == nil || api.previewCalls != 1 ||
		api.lastPreview.Enabled == nil || !*api.lastPreview.Enabled ||
		api.lastPreview.Target != nil || api.lastPreview.DNSProfileID != nil ||
		!strings.Contains(m.View(), "Field: enabled") {
		t.Fatal("region transition did not use one-field compiler preview")
	}
	m, stage := toggleKey(t, m, 'y')
	if stage == nil || api.stageCalls != 0 {
		t.Fatal("region was staged without confirmation")
	}
	m, reload := updated(t, m, stage())
	if api.stageCalls != 1 || api.lastStage.GroupID != "region:auto-geosite:cn" ||
		api.lastStage.Enabled == nil || !*api.lastStage.Enabled || reload == nil ||
		m.inspection.pending != nil {
		t.Fatal("region explicit stage was not CAS bound")
	}
	m, _ = updated(t, m, reload())
	if len(m.inspection.routeRows) != 0 || !m.inspection.ready ||
		!strings.Contains(m.View(), "staged=true") {
		t.Fatal("staged region write should be read-only until explicit core apply")
	}
}
