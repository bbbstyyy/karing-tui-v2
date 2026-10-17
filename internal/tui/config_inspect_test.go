package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func (f *fakeAPI) InspectConfig(context.Context) (apiv1.ConfigInspectionResponse, error) {
	return apiv1.ConfigInspectionResponse{}, errors.New("config inspection not configured")
}

type configInspectFakeAPI struct {
	*fakeAPI
	value apiv1.ConfigInspectionResponse
	err   error
	calls int
}

func (f *configInspectFakeAPI) InspectConfig(ctx context.Context) (apiv1.ConfigInspectionResponse, error) {
	f.calls++
	if deadline, ok := ctx.Deadline(); !ok || deadline.IsZero() {
		return apiv1.ConfigInspectionResponse{}, errors.New("missing deadline")
	}
	return f.value, f.err
}

func configInspectFixture() apiv1.ConfigInspectionResponse {
	return apiv1.ConfigInspectionResponse{
		APIVersion: apiv1.Version, Evidence: "applied_declaration",
		ConfigRevision: 7, GenerationID: 22,
		AppliedDeclarationRevision: 9, CurrentDeclarationRevision: 10,
		StagedUnapplied: true, RoutingChanged: true, DNSChanged: true,
		CNPreset: true, RegionAppend: true, RouteTotal: 2,
		Layers: []apiv1.ConfigInspectionLayer{
			{Layer: domain.LayerCustom, Enabled: true, GroupCount: 1, ActiveCount: 1,
				Groups: []apiv1.ConfigInspectionRouteGroup{{
					ID: "cn.example", Order: 1, Enabled: true, Origin: "cn_preset",
					MatchKinds: []string{"domain_suffix", "rule_set"},
					Target:     domain.TargetRef{Kind: domain.TargetCurrentSelected},
					DNSProfile: "group-dns",
				}}},
			{Layer: domain.LayerGeoSite, Enabled: true},
			{Layer: domain.LayerGeoIP, Enabled: true},
			{Layer: domain.LayerACL, Enabled: true},
			{Layer: domain.LayerFinal, Enabled: true, GroupCount: 1, ActiveCount: 1,
				Groups: []apiv1.ConfigInspectionRouteGroup{{
					ID: "FINAL", Enabled: true, Origin: "declaration",
					Target: domain.TargetRef{Kind: domain.TargetDirect},
				}}},
		},
		DNS: apiv1.ConfigInspectionDNS{
			OutboundProfile: "outbound", DirectProfile: "direct",
			ProfileCount: 2,
			Profiles: []apiv1.ConfigInspectionDNSProfile{
				{ID: "outbound", Role: domain.DNSRoleOutbound, Transport: domain.DNSTransportUDP,
					Port: 53, UpstreamKind: "IP literal"},
				{ID: "group-dns", Role: domain.DNSRoleGroup, Transport: domain.DNSTransportTCP,
					Port: 5353, UpstreamKind: "hostname (bootstrap required)",
					BootstrapID: "bootstrap-1", Detour: &domain.TargetRef{Kind: domain.TargetCurrentSelected}},
			},
		},
	}
}

func TestInspectionRoutingAndDNSScreensAreExplicitReadOnly(t *testing.T) {
	api := &configInspectFakeAPI{fakeAPI: &fakeAPI{}, value: configInspectFixture()}
	m := NewModel(context.Background(), api)
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'7'}})
	if cmd == nil || api.calls != 0 {
		t.Fatal("route page triggered synchronous I/O")
	}
	m, _ = updated(t, m, cmd())
	if api.calls != 1 || !m.inspection.ready || m.page != routingInspectPage {
		t.Fatalf("route projection was not stored safely: %+v", m.inspection)
	}
	view := m.View()
	for _, expect := range []string{
		"APPLIED DECLARATION", "custom > geosite > geoip > acl > FINAL",
		"cn.example", "cn_preset", "domain_suffix,rule_set", "group-dns",
		"staged=true", "routing changed=true", "DNS changed=true",
	} {
		if !strings.Contains(view, expect) {
			t.Fatalf("missing routing evidence %q in: %s", expect, view)
		}
	}
	m, same := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'8'}})
	if same != nil || m.page != dnsInspectPage || api.calls != 1 {
		t.Fatal("same applied snapshot was unnecessarily refetched")
	}
	view = m.View()
	for _, expect := range []string{
		"DNS: declarative bindings only", "Profiles: 2", "outbound", "group-dns",
		"hostname (bootstrap required)", "bootstrap-1", "current_selected",
		"NOT proof",
	} {
		if !strings.Contains(view, expect) {
			t.Fatalf("missing DNS evidence %q in: %s", expect, view)
		}
	}
	m, reload := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if reload == nil || api.calls != 1 || !m.inspection.active || m.inspection.ready {
		t.Fatal("r did not schedule fresh async inspection")
	}
	m, _ = updated(t, m, reload())
	if api.calls != 2 || !m.inspection.ready {
		t.Fatal("manual refresh failed")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	if m.inspection.ready || len(m.inspection.dns) != 0 || len(m.inspection.routing) != 0 {
		t.Fatal("leaving inspection retained source metadata")
	}
}

func TestInspectionRedactsUntrustedIDsAndErrors(t *testing.T) {
	raw := configInspectFixture()
	raw.Layers[0].Groups[0].ID = "https://alice:password@bad.invalid?token=SUPER_PRIVATE"
	raw.DNS.Profiles[1].ID = "secret-TOKEN_DNS"
	raw.DNS.Profiles[1].Detour = &domain.TargetRef{
		Kind: domain.TargetSpecificNode, ProfileID: "p", NodeID: "token=SENSITIVE_NODE",
	}
	routing, dns, err := projectConfigInspection(raw)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(append(routing, dns...), "\n")
	for _, sensitive := range []string{"SUPER_PRIVATE", "SENSITIVE_NODE", "TOKEN_DNS", "\x1b"} {
		if strings.Contains(joined, sensitive) {
			t.Fatalf("sensitive ID passed projection: %q", sensitive)
		}
	}
	if !strings.Contains(joined, "[redacted]") {
		t.Fatal("unsafe group/DNS IDs were not visibly masked")
	}
	api := &configInspectFakeAPI{fakeAPI: &fakeAPI{}, err: errors.New("password=UPSTREAM_SECRET\x1b[31m")}
	m := NewModel(context.Background(), api)
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'8'}})
	m, _ = updated(t, m, cmd())
	if !m.inspection.failed || strings.Contains(fmt.Sprintf("%+v", m.inspection), "UPSTREAM_SECRET") ||
		strings.Contains(m.View(), "UPSTREAM_SECRET") {
		t.Fatalf("untrusted daemon error reached UI state: %+v", m.inspection)
	}
}

func TestInspectionRejectsInvalidEvidenceAndStaleSnapshots(t *testing.T) {
	for _, bad := range []func(*apiv1.ConfigInspectionResponse){
		func(r *apiv1.ConfigInspectionResponse) { r.Evidence = "observed" },
		func(r *apiv1.ConfigInspectionResponse) { r.RouteTotal++ },
		func(r *apiv1.ConfigInspectionResponse) { r.Layers[4].Enabled = false },
		func(r *apiv1.ConfigInspectionResponse) {
			r.Layers[0].Groups[0].MatchKinds = []string{"secret-domain.example"}
		},
		func(r *apiv1.ConfigInspectionResponse) { r.DNS.Profiles[0].UpstreamKind = "https://user:pass@dns" },
		func(r *apiv1.ConfigInspectionResponse) { r.DNS.ProfileCount++ },
	} {
		raw := configInspectFixture()
		bad(&raw)
		if _, _, err := projectConfigInspection(raw); err == nil {
			t.Fatalf("invalid/unsafe inspection accepted: %+v", raw)
		}
	}
	api := &configInspectFakeAPI{fakeAPI: &fakeAPI{}, value: configInspectFixture()}
	m := NewModel(context.Background(), api)
	m, old := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'7'}})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	m, fresh := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'7'}})
	m, _ = updated(t, m, old())
	if m.inspection.ready || !m.inspection.active {
		t.Fatal("late response to abandoned snapshot was accepted")
	}
	m, _ = updated(t, m, fresh())
	if !m.inspection.ready {
		t.Fatal("new snapshot was not accepted")
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 37, Height: 8})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if m.inspection.scroll != 1 {
		t.Fatal("inspection page could not scroll")
	}
	lines := strings.Split(strings.TrimSuffix(m.View(), "\n"), "\n")
	if len(lines) > 8 {
		t.Fatalf("inspection overran small terminal height: %d", len(lines))
	}
	for _, line := range lines {
		if runeWidthOfLine(line) > 37 {
			t.Fatalf("inspection overran small terminal width: %q", line)
		}
	}
}
