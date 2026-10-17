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

func (f *fakeAPI) RouteExplain(context.Context, apiv1.RouteExplainRequest) (apiv1.RouteExplainResponse, error) {
	return apiv1.RouteExplainResponse{}, errors.New("route probe not configured")
}

type fakeRouteProbeAPI struct {
	*fakeAPI
	response apiv1.RouteExplainResponse
	err      error
	calls    int
	last     apiv1.RouteExplainRequest
	spoof    bool
}

func (f *fakeRouteProbeAPI) RouteExplain(ctx context.Context, request apiv1.RouteExplainRequest) (apiv1.RouteExplainResponse, error) {
	f.calls++
	f.last = request
	f.checkDeadline(ctx)
	if f.err != nil {
		return apiv1.RouteExplainResponse{}, f.err
	}
	response := f.response
	if !f.spoof {
		response.Entry = request.Entry
		response.Input = request
	}
	return response, nil
}

func enterRoutePage(t *testing.T, api *fakeRouteProbeAPI) Model {
	t.Helper()
	m := NewModel(context.Background(), api)
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'4'}})
	if m.page != routePage {
		t.Fatal("route page not selected")
	}
	return m
}

func routeKey(t *testing.T, m Model, key string) (Model, tea.Cmd) {
	t.Helper()
	return updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
}

func TestRouteProbeShowsAppliedSourceAndDNSWithoutObservedClaim(t *testing.T) {
	api := &fakeRouteProbeAPI{fakeAPI: &fakeAPI{}, response: apiv1.RouteExplainResponse{
		Evidence: "simulated", Decision: "route", GenerationID: 82,
		ConfigRevision: 7, DeclarationRevision: 5, RoutingMode: "rule",
		Source: "group", Layer: domain.LayerCustom, GroupID: "ads",
		Action: "route", Target: &domain.TargetRef{Kind: domain.TargetDirect},
		DNSProfileID: "group-dns", RuleIndex: func() *int { n := 30; return &n }(),
		Trace: func() []apiv1.RouteExplainStep {
			steps := make([]apiv1.RouteExplainStep, 35)
			for i := range steps {
				steps[i] = apiv1.RouteExplainStep{RuleIndex: i, Result: "false", Source: "synthetic"}
			}
			steps[30] = apiv1.RouteExplainStep{
				RuleIndex: 30, Result: "true", Source: "group",
				Layer: domain.LayerCustom, GroupID: "ads",
				Action: "route", DNSProfileID: "group-dns",
			}
			return steps
		}(),
	}}
	m := enterRoutePage(t, api)
	m, _ = routeKey(t, m, "e")
	m, _ = routeKey(t, m, "EXAMPLE.COM")
	if m.route.input != "EXAMPLE.COM" {
		t.Fatalf("unexpected input: %q", m.route.input)
	}
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil || !m.route.active || api.calls != 0 {
		t.Fatal("probe not scheduled asynchronously")
	}
	m, _ = updated(t, m, cmd())
	if api.calls != 1 || api.last.Entry != "rule" || api.last.Domain != "example.com" {
		t.Fatalf("incorrect route query: %+v", api.last)
	}
	if !api.observedDeadline || !m.route.ready {
		t.Fatal("probe did not use bounded local request")
	}
	view := strings.Join(m.routeProbeLines(), "\n")
	for _, wanted := range []string{
		"SIMULATION", "Evidence: simulated", "Decision: route",
		"generation: 82", "declaration rev: 5", "layer: custom",
		"group: ads", "target: direct", "DNS profile binding: group-dns",
		"NOT observed DNS use", "#30 true", "18 intermediate trace rules omitted",
	} {
		if !strings.Contains(view, wanted) {
			t.Fatalf("missing %q in route view:\n%s", wanted, view)
		}
	}
	if len(m.route.result.trace) != maxRouteProbeTrace+1 {
		t.Fatalf("unexpected trace cap: %d", len(m.route.result.trace))
	}
	if m.route.result.traceTotal != 35 {
		t.Fatal("trace total lost")
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 36, Height: 8})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if m.route.scroll != 1 {
		t.Fatal("route scrolling did not advance")
	}
	lines := strings.Split(strings.TrimSuffix(m.View(), "\n"), "\n")
	if len(lines) > 8 {
		t.Fatalf("route view exceeded viewport: %d lines", len(lines))
	}
	for _, line := range lines {
		if runeWidthOfLine(line) > 36 {
			t.Fatalf("route line exceeded width: %q", line)
		}
	}
}

func TestRouteProbeEditingValidationAndEntryIsolation(t *testing.T) {
	api := &fakeRouteProbeAPI{fakeAPI: &fakeAPI{}, response: apiv1.RouteExplainResponse{
		Evidence: "unknown", Decision: "unknown", GenerationID: 8,
		UnknownConditions: []string{"rule_set:opaque", "process_name"},
		Trace: []apiv1.RouteExplainStep{
			{RuleIndex: 0, Result: "unknown", Layer: domain.LayerGeoSite},
		},
	}}
	m := enterRoutePage(t, api)
	m, _ = routeKey(t, m, "e")
	m, _ = routeKey(t, m, "q")
	if m.quitting || m.route.input != "q" {
		t.Fatal("typing q in route editor must not quit")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyCtrlU})
	m, _ = routeKey(t, m, "https://token=SECRET.invalid/")
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil || api.calls != 0 || !m.route.invalid {
		t.Fatal("invalid address was sent to daemon")
	}
	m, _ = routeKey(t, m, "e")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyCtrlU})
	m, _ = routeKey(t, m, "2001:db8::1")
	m, cmd = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("valid IPv6 probe not scheduled")
	}
	m, _ = updated(t, m, cmd())
	if api.last.IP != "2001:db8::1" || api.last.Domain != "" || !m.route.ready {
		t.Fatalf("incorrect IPv6 probe: %+v", api.last)
	}
	view := strings.Join(m.routeProbeLines(), "\n")
	for _, expected := range []string{"Evidence: unknown", "UNKNOWN", "rule_set:opaque", "unknown/unattributed"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("unknown semantics lost: %s", view)
		}
	}
	if strings.Contains(view, "SECRET.invalid") {
		t.Fatal("old unsubmitted input leaked into result")
	}
	m, _ = routeKey(t, m, "t")
	if m.route.entry != domain.InboundDirect || m.route.ready {
		t.Fatal("entry change failed to invalidate old result")
	}
	m, cmd = routeKey(t, m, "r")
	if cmd == nil {
		t.Fatal("r did not re-query for Direct entry")
	}
	m, _ = updated(t, m, cmd())
	if api.last.Entry != "direct" {
		t.Fatal("Direct entry was not used")
	}
	m, _ = routeKey(t, m, "t")
	m, cmd = routeKey(t, m, "r")
	if cmd == nil {
		t.Fatal("r did not re-query Selected entry")
	}
	m, _ = updated(t, m, cmd())
	if api.last.Entry != "selected" {
		t.Fatal("Selected entry was not used")
	}
}

func TestRouteProbeStaleResponseAndSecretErrorAreDiscarded(t *testing.T) {
	api := &fakeRouteProbeAPI{fakeAPI: &fakeAPI{}, response: apiv1.RouteExplainResponse{
		Evidence: "simulated", Decision: "route", GenerationID: 2,
		Source: "custom", Layer: domain.LayerACL, GroupID: "live",
	}}
	m := enterRoutePage(t, api)
	m, _ = routeKey(t, m, "e")
	m, _ = routeKey(t, m, "test.invalid")
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil || !m.route.active {
		t.Fatal("missing outstanding command")
	}
	m, _ = routeKey(t, m, "r")
	if !m.route.active || api.calls != 0 {
		t.Fatal("duplicate probe issued while one is active")
	}
	m, _ = routeKey(t, m, "1")
	if m.page != dashboardPage || !m.route.discard {
		t.Fatal("leaving page did not invalidate explanation")
	}
	m, _ = updated(t, m, cmd())
	m, _ = routeKey(t, m, "4")
	if m.route.ready || strings.Contains(m.View(), "group: live") {
		t.Fatal("stale route result resurrected after page switch")
	}
	api.err = errors.New("token=SECRET_CREDENTIAL\x1b[31m")
	m, cmd = routeKey(t, m, "r")
	if cmd == nil {
		t.Fatal("missing retry")
	}
	m, _ = updated(t, m, cmd())
	if !m.route.failed || m.route.ready || strings.Contains(m.View(), "SECRET_CREDENTIAL") {
		t.Fatalf("untrusted error leaked: %q", m.View())
	}
	api.err = nil
	api.spoof = true
	api.response.Entry = "selected"
	m, cmd = routeKey(t, m, "r")
	m, _ = updated(t, m, cmd())
	if m.route.ready || !m.route.failed {
		t.Fatal("response for wrong entry was accepted")
	}
}

func TestRouteProbeInputBoundsAndControlSafety(t *testing.T) {
	for _, input := range []string{
		"", ".", "a..b", "-bad.invalid", "bad-.invalid", "user:pass@host",
		"https://secret.invalid", "host/route", "中文.invalid", "fe80::1%eth0",
		strings.Repeat("a", 64) + ".org", strings.Repeat("b", 254),
	} {
		if _, err := parseRouteProbeInput(input, domain.InboundRule); err == nil {
			t.Fatalf("unsafe input accepted: %q", input)
		}
	}
	for _, input := range []string{"a", "localhost", "EXAMPLE.com.", "192.0.2.1", "2001:db8::9"} {
		if _, err := parseRouteProbeInput(input, domain.InboundRule); err != nil {
			t.Fatalf("valid input rejected: %q: %v", input, err)
		}
	}
	api := &fakeRouteProbeAPI{fakeAPI: &fakeAPI{}}
	m := enterRoutePage(t, api)
	m, _ = routeKey(t, m, "e")
	m, _ = routeKey(t, m, strings.Repeat("a", maxRouteProbeInput+100))
	m, _ = routeKey(t, m, "\x1b[31m\u202e中文")
	if len(m.route.input) != maxRouteProbeInput || strings.Contains(m.route.input, "\x1b") {
		t.Fatal("unbounded or unsafe route input")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.route.editing {
		t.Fatal("escape must leave edit mode")
	}
}
