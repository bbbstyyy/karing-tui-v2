package tui

import (
	"context"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestRouteBindingTargetChooserPreviewConfirmAndNoCoreApply(t *testing.T) {
	api := newRouteToggleFake()
	m := loadedToggleModel(t, api)
	m, cmd := toggleKey(t, m, 't')
	if cmd != nil || m.inspection.chooser == nil || len(m.inspection.chooser.options) < 2 ||
		api.previewCalls != 0 || api.stageCalls != 0 {
		t.Fatalf("target menu did not open without I/O: %+v", m.inspection.chooser)
	}
	for _, option := range m.inspection.chooser.options {
		if option.target.Kind == domain.TargetBlock {
			t.Fatal("BLOCK target offered with existing group DNS")
		}
	}
	if !strings.Contains(m.View(), "Routing binding chooser") || !strings.Contains(m.View(), "direct") {
		t.Fatalf("target options unavailable in TUI: %s", m.View())
	}
	m, preview := updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if preview == nil || api.previewCalls != 0 {
		t.Fatal("Enter preview called daemon synchronously")
	}
	m, _ = updated(t, m, preview())
	if m.inspection.pending == nil || api.lastPreview.Target == nil || api.lastPreview.Target.Kind != domain.TargetDirect ||
		api.lastPreview.Enabled != nil || api.lastPreview.DNSProfileID != nil ||
		api.previewCalls != 1 || api.stageCalls != 0 ||
		!strings.Contains(m.View(), "Field: target") || !strings.Contains(m.View(), "After:  direct") {
		t.Fatalf("target preview incorrectly persisted: %+v %q", m.inspection.pending, m.View())
	}
	m, stage := toggleKey(t, m, 'y')
	if stage == nil || api.stageCalls != 0 {
		t.Fatal("stage not gated behind explicit y")
	}
	m, reload := updated(t, m, stage())
	if api.stageCalls != 1 || reload == nil || api.lastStage.Target == nil ||
		api.lastStage.Target.Kind != domain.TargetDirect {
		t.Fatal("typed target not CAS staged")
	}
	m, _ = updated(t, m, reload())
	if !m.inspection.ready || len(m.inspection.routeRows) != 0 ||
		!strings.Contains(m.View(), "staged=true") {
		t.Fatal("post-stage inspection still permits stale edit")
	}
}

func TestRouteBindingDNSChooserClearsWithCompilerReceipt(t *testing.T) {
	api := newRouteToggleFake()
	m := loadedToggleModel(t, api)
	m, cmd := toggleKey(t, m, 'g')
	if cmd != nil || m.inspection.chooser == nil || len(m.inspection.chooser.options) != 1 ||
		m.inspection.chooser.options[0].dnsID != "" {
		t.Fatal("DNS clear option missing or chooser sent an RPC")
	}
	if !strings.Contains(m.View(), "use declared role fallback") {
		t.Fatal("clear action did not describe semantics")
	}
	m, preview := updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m, _ = updated(t, m, preview())
	if m.inspection.pending == nil || api.lastPreview.DNSProfileID == nil ||
		*api.lastPreview.DNSProfileID != "" || api.lastPreview.Target != nil ||
		api.lastPreview.Enabled != nil || !strings.Contains(m.View(), "Field: dns") {
		t.Fatal("DNS change did not preserve all other route fields")
	}
	m, stage := toggleKey(t, m, 'y')
	_, reload := updated(t, m, stage())
	if reload == nil || api.stageCalls != 1 || api.lastStage.DNSProfileID == nil ||
		*api.lastStage.DNSProfileID != "" {
		t.Fatal("DNS clear stage was not acknowledged")
	}
}

func TestRouteBindingDNSChooserSupportsExistingSecondGroupResolver(t *testing.T) {
	api := newRouteToggleFake()
	api.value.DNS.ProfileCount++
	api.value.DNS.Profiles = append(api.value.DNS.Profiles, apiv1.ConfigInspectionDNSProfile{
		ID: "group-dns-2", Role: domain.DNSRoleGroup, Transport: domain.DNSTransportUDP,
		Port: 53, UpstreamKind: "IP literal",
	})
	m := loadedToggleModel(t, api)
	m, _ = toggleKey(t, m, 'g')
	if m.inspection.chooser == nil || len(m.inspection.chooser.options) != 2 {
		t.Fatal("existing role=group resolver is not offered")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyDown})
	m, preview := updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m, _ = updated(t, m, preview())
	if m.inspection.pending == nil || api.lastPreview.DNSProfileID == nil ||
		*api.lastPreview.DNSProfileID != "group-dns-2" {
		t.Fatal("alternate group-role DNS preview failed")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.inspection.pending != nil || api.stageCalls != 0 {
		t.Fatal("Escape staged a candidate")
	}
}

func TestRouteBindingChooserReadOnlyWhenUnsafeAndStaged(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*apiv1.ConfigInspectionResponse)
		noEdit bool
		noDNS  bool
	}{
		{"staged", func(r *apiv1.ConfigInspectionResponse) {
			r.CurrentDeclarationRevision++
			r.StagedUnapplied = true
			r.RoutingChanged = true
		}, true, true},
		{"partial routes", func(r *apiv1.ConfigInspectionResponse) {
			r.RouteTotal++
			r.RouteTruncated = true
			r.Layers[1].GroupCount = 1
		}, true, true},
		{"partial DNS", func(r *apiv1.ConfigInspectionResponse) {
			r.DNS.ProfileCount++
			r.DNS.Truncated = true
		}, false, true},
		{"unsafe current DNS", func(r *apiv1.ConfigInspectionResponse) {
			r.Layers[0].Groups[0].DNSProfile = "https://x?token=secret"
		}, true, true},
		{"unsafe current target", func(r *apiv1.ConfigInspectionResponse) {
			r.Layers[0].Groups[0].Target = domain.TargetRef{
				Kind: domain.TargetSpecificNode, ProfileID: "p", NodeID: "https://x?token=secret",
			}
		}, true, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			api := newRouteToggleFake()
			tt.mutate(&api.value)
			// Partial routing fixture needs a consistent layer count.
			m := NewModel(context.Background(), api)
			m, load := toggleKey(t, m, '7')
			m, _ = updated(t, m, load())
			if !m.inspection.ready {
				t.Fatal("projected inspection rejected test fixture")
			}
			if tt.noEdit && len(m.inspection.routeRows) != 0 {
				t.Fatal("unsafe snapshot editable")
			}
			m, _ = toggleKey(t, m, 'g')
			if tt.noDNS && m.inspection.chooser != nil {
				t.Fatal("unsafe DNS snapshot editable")
			}
			if !tt.noEdit {
				m, _ = toggleKey(t, m, 't')
				if m.inspection.chooser == nil {
					t.Fatal("partial DNS incorrectly disabled safe target edit")
				}
			}
			if api.previewCalls != 0 || api.stageCalls != 0 {
				t.Fatal("menu navigation caused write")
			}
		})
	}
}

func TestRouteBindingRejectsLatePreviewAfterLeavingPage(t *testing.T) {
	api := newRouteToggleFake()
	m := loadedToggleModel(t, api)
	m, _ = toggleKey(t, m, 't')
	m, late := updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m, _ = toggleKey(t, m, '8')
	m, _ = updated(t, m, late())
	if m.inspection.pending != nil || m.page != dnsInspectPage {
		t.Fatal("late target preview crossed page boundary")
	}
	m, _ = toggleKey(t, m, '7')
	m, _ = toggleKey(t, m, 't')
	if m.inspection.chooser == nil {
		t.Fatal("modal stale state prevented fresh view")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.inspection.chooser != nil || api.stageCalls != 0 {
		t.Fatal("cancel issued remote write")
	}
}

func TestRouteBindingTargetInventoryIncludesOnlySafeObservedReferences(t *testing.T) {
	api := newRouteToggleFake()
	ref := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "p", NodeID: "stable-node"}
	unsafe := domain.TargetRef{Kind: domain.TargetCustomURLTest, GroupID: "token=SHOULD_NOT_KEEP"}
	api.value.Layers[1].GroupCount = 2
	api.value.Layers[1].ActiveCount = 2
	api.value.Layers[1].Groups = []apiv1.ConfigInspectionRouteGroup{
		{ID: "geosite-1", Enabled: true, Target: ref, Origin: "custom"},
		{ID: "geosite-2", Enabled: true, Target: unsafe, Origin: "custom"},
	}
	api.value.RouteTotal += 2
	m := loadedToggleModel(t, api)
	m, _ = toggleKey(t, m, 't')
	if m.inspection.chooser == nil {
		t.Fatal("target inventory did not load")
	}
	found := false
	for _, opt := range m.inspection.chooser.options {
		if opt.target == ref {
			found = true
		}
		if opt.target == unsafe {
			t.Fatal("untrusted target retained")
		}
	}
	if !found || strings.Contains(m.View(), "SHOULD_NOT_KEEP") {
		t.Fatalf("observed safe node not offered / unsafe data retained: %q", m.View())
	}
}

func TestRouteBindingMenuRendersBoundedSmallTerminal(t *testing.T) {
	api := newRouteToggleFake()
	m := loadedToggleModel(t, api)
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 38, Height: 8})
	m, _ = toggleKey(t, m, 't')
	if !strings.Contains(m.View(), "> ") {
		t.Fatalf("initial candidate hidden at small viewport: %s", m.View())
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyDown})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyDown})
	view := m.View()
	if !strings.Contains(view, "> ") {
		t.Fatalf("selected choice out of viewport: %s", view)
	}
	lines := strings.Split(strings.TrimSuffix(view, "\n"), "\n")
	if len(lines) > 8 {
		t.Fatalf("height overflow: %d", len(lines))
	}
	for _, line := range lines {
		if runeWidthOfLine(line) > 38 {
			t.Fatalf("width overflow: %q", line)
		}
	}
}
