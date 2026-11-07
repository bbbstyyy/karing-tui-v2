package tui

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const (
	maxRouteProbeInput   = 253
	maxRouteProbeTrace   = 16
	maxRouteProbeUnknown = 4
)

// A route probe never loads a mutable declaration or accesses the data plane.
// It asks the daemon to interpret one immutable, applied generation.
type routeProbeState struct {
	entry   domain.InboundRole
	input   string
	editing bool
	active  bool
	discard bool
	ready   bool
	failed  bool
	invalid bool
	seq     uint64
	scroll  int
	result  routeProbeSummary
}

type routeProbeSummary struct {
	entry               string
	query               string
	evidence            string
	decision            string
	configRevision      uint64
	generationID        int64
	declarationRevision uint64
	routingMode         string
	privateDirect       bool
	rule                string
	source              string
	layer               string
	group               string
	target              string
	dnsProfile          string
	action              string
	unknown             []string
	unknownOmitted      int
	trace               []string
	traceTotal          int
	traceOmitted        int
}

type routeProbeLoaded struct {
	sequence uint64
	result   routeProbeSummary
	err      error
}

func parseRouteProbeInput(input string, entry domain.InboundRole) (apiv1.RouteExplainRequest, error) {
	value := strings.TrimSpace(input)
	if len(value) == 0 || len(value) > maxRouteProbeInput {
		return apiv1.RouteExplainRequest{}, errors.New("address must contain 1..253 bytes")
	}
	request := apiv1.RouteExplainRequest{Entry: string(entry)}
	if ip, err := netip.ParseAddr(value); err == nil {
		if ip.Zone() != "" {
			return apiv1.RouteExplainRequest{}, errors.New("scoped IP addresses are not accepted")
		}
		request.IP = ip.Unmap().String()
		return request, nil
	}
	value = strings.ToLower(strings.TrimSuffix(value, "."))
	if len(value) == 0 || len(value) > 253 {
		return apiv1.RouteExplainRequest{}, errors.New("invalid hostname length")
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return apiv1.RouteExplainRequest{}, errors.New("invalid hostname label")
		}
		for _, ch := range label {
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
				return apiv1.RouteExplainRequest{}, errors.New("hostname must use ASCII letters, numbers or hyphens")
			}
		}
	}
	request.Domain = value
	return request, nil
}

func (m *Model) beginRouteProbeEditing() {
	if m.route.active {
		return
	}
	m.route.editing = true
	m.route.ready = false
	m.route.failed = false
	m.route.invalid = false
	m.route.scroll = 0
	m.route.result = routeProbeSummary{}
}

func (m *Model) cycleRouteProbeEntry() {
	if m.route.active {
		return
	}
	switch m.route.entry {
	case domain.InboundRule:
		m.route.entry = domain.InboundDirect
	case domain.InboundDirect:
		m.route.entry = domain.InboundSelected
	default:
		m.route.entry = domain.InboundRule
	}
	m.route.ready = false
	m.route.failed = false
	m.route.invalid = false
	m.route.scroll = 0
	m.route.result = routeProbeSummary{}
}

func (m Model) updateRouteProbeEditing(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit
	case "esc":
		m.route.editing = false
		m.route.invalid = false
		return m, nil
	case "enter":
		m.route.editing = false
		return m, m.startRouteProbe()
	case "backspace", "ctrl+h":
		if len(m.route.input) > 0 {
			runes := []rune(m.route.input)
			m.route.input = string(runes[:len(runes)-1])
		}
	case "ctrl+u":
		m.route.input = ""
	case "tab":
		m.route.editing = false
		return m, m.switchPage(dashboardPage)
	default:
		if msg.Type == tea.KeyRunes {
			for _, ch := range msg.Runes {
				if ch >= 0x21 && ch <= 0x7e && len(m.route.input) < maxRouteProbeInput {
					m.route.input += string(ch)
				}
			}
		}
	}
	m.route.invalid = false
	return m, nil
}

func (m *Model) startRouteProbe() tea.Cmd {
	if m.route.active || m.page != routePage {
		return nil
	}
	request, err := parseRouteProbeInput(m.route.input, m.route.entry)
	if err != nil {
		m.route.ready = false
		m.route.failed = false
		m.route.invalid = true
		m.route.result = routeProbeSummary{}
		return nil
	}
	m.route.input = request.Domain
	if request.IP != "" {
		m.route.input = request.IP
	}
	m.route.seq++
	m.route.active = true
	m.route.discard = false
	m.route.invalid = false
	m.route.failed = false
	m.route.ready = false
	m.route.scroll = 0
	m.route.result = routeProbeSummary{}
	return loadRouteProbe(m.ctx, m.api, m.route.seq, request)
}

func loadRouteProbe(ctx context.Context, api API, sequence uint64, request apiv1.RouteExplainRequest) tea.Cmd {
	return func() tea.Msg {
		loaded := routeProbeLoaded{sequence: sequence}
		if api == nil {
			loaded.err = errors.New("missing TUI client")
			return loaded
		}
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		response, err := api.RouteExplain(bounded, request)
		if err == nil {
			err = validateRouteProbeResponse(response, request)
		}
		if err != nil {
			// Never retain a raw daemon error: it may contain subscription credentials.
			loaded.err = errors.New("route probe unavailable")
			return loaded
		}
		loaded.result = projectRouteProbe(response)
		return loaded
	}
}

func validateRouteProbeResponse(response apiv1.RouteExplainResponse, request apiv1.RouteExplainRequest) error {
	if response.GenerationID <= 0 || response.Entry != request.Entry ||
		response.Input.Entry != request.Entry || response.Input.Domain != request.Domain ||
		response.Input.IP != request.IP {
		return errors.New("route probe identity mismatch")
	}
	switch response.Evidence {
	case "simulated":
		if response.Decision != "route" && response.Decision != "reject" {
			return errors.New("inconsistent simulated decision")
		}
	case "unknown":
		if response.Decision != "unknown" {
			return errors.New("inconsistent unknown decision")
		}
	default:
		return errors.New("unsupported route evidence")
	}
	return nil
}

func clipRouteText(value string) string {
	return safeText(value, 120)
}

func routeProbeTarget(target *domain.TargetRef) string {
	if target == nil {
		return "unattributed"
	}
	switch target.Kind {
	case domain.TargetSpecificNode:
		return clipRouteText(string(target.Kind) + " " + target.ProfileID + "/" + target.NodeID)
	case domain.TargetCustomURLTest:
		return clipRouteText(string(target.Kind) + " " + target.GroupID)
	default:
		return clipRouteText(string(target.Kind))
	}
}

func projectRouteProbe(response apiv1.RouteExplainResponse) routeProbeSummary {
	summary := routeProbeSummary{
		entry:    string(response.Entry),
		evidence: response.Evidence, decision: response.Decision,
		configRevision:      response.ConfigRevision,
		generationID:        response.GenerationID,
		declarationRevision: response.DeclarationRevision,
		routingMode:         clipRouteText(response.RoutingMode),
		privateDirect:       response.PrivateDirect,
		source:              clipRouteText(response.Source),
		layer:               clipRouteText(string(response.Layer)),
		group:               clipRouteText(response.GroupID),
		target:              routeProbeTarget(response.Target),
		dnsProfile:          clipRouteText(response.DNSProfileID),
		action:              clipRouteText(response.Action),
		traceTotal:          len(response.Trace),
	}
	if response.Input.Domain != "" {
		summary.query = response.Input.Domain
	} else {
		summary.query = response.Input.IP
	}
	if response.RuleIndex != nil {
		summary.rule = fmt.Sprint(*response.RuleIndex)
	} else {
		summary.rule = "unattributed"
	}
	for _, condition := range response.UnknownConditions {
		if len(summary.unknown) == maxRouteProbeUnknown {
			break
		}
		summary.unknown = append(summary.unknown, clipRouteText(condition))
	}
	summary.unknownOmitted = len(response.UnknownConditions) - len(summary.unknown)
	count := min(len(response.Trace), maxRouteProbeTrace)
	for _, step := range response.Trace[:count] {
		summary.trace = append(summary.trace, formatRouteProbeTrace(step))
	}
	if response.RuleIndex != nil && *response.RuleIndex >= count {
		for _, step := range response.Trace[count:] {
			if step.RuleIndex == *response.RuleIndex {
				summary.trace = append(summary.trace, formatRouteProbeTrace(step))
				break
			}
		}
	}
	summary.traceOmitted = len(response.Trace) - len(summary.trace)
	return summary
}

func formatRouteProbeTrace(step apiv1.RouteExplainStep) string {
	layer := string(step.Layer)
	if layer == "" {
		layer = "synthetic/unknown"
	}
	origin := layer
	if step.GroupID != "" {
		origin += "/" + step.GroupID
	}
	line := fmt.Sprintf("#%d %s %s %s action=%s dns=%s",
		step.RuleIndex, step.Result, step.Source, origin, step.Action, step.DNSProfileID)
	return safeText(line, 180)
}

func (m *Model) acceptRouteProbe(msg routeProbeLoaded) {
	if !m.route.active || m.route.seq != msg.sequence {
		return
	}
	m.route.active = false
	if m.route.discard || m.page != routePage {
		return
	}
	if msg.err != nil {
		m.route.ready = false
		m.route.failed = true
		m.route.result = routeProbeSummary{}
		return
	}
	m.route.ready = true
	m.route.failed = false
	m.route.result = msg.result
	m.route.scroll = 0
}

func (m Model) routeProbeLines() []string {
	entry := string(m.route.entry)
	if entry == "" {
		entry = "rule"
	}
	input := m.route.input
	if input == "" {
		input = "(press e to enter hostname or IP)"
	}
	lines := []string{
		"Route Probe - read-only applied-generation SIMULATION, not live traffic",
		"Entry: " + entry + " (t cycles Rule / Direct / Selected)",
		"Address: " + input,
	}
	switch {
	case m.route.editing:
		return append(lines, "Editing ASCII domain/IP; Enter queries the local daemon only.")
	case m.route.active:
		return append(lines, "Waiting for bounded local explanation; no packet is sent to destination.")
	case m.route.invalid:
		return append(lines, "Invalid address: use an ASCII hostname or IP (max 253 bytes).")
	case m.route.failed:
		return append(lines, "Explanation unavailable or inconsistent; no route decision is assumed.")
	case !m.route.ready:
		return append(lines, "Press e to edit; r to simulate. No route has been evaluated.")
	}
	s := m.route.result
	lines = append(lines,
		fmt.Sprintf("Evidence: %s | Decision: %s | Rule index: %s", s.evidence, s.decision, s.rule),
		fmt.Sprintf("Applied-at-query generation: %d  config rev: %d  declaration rev: %d", s.generationID, s.configRevision, s.declarationRevision),
		fmt.Sprintf("Routing mode: %s | private-direct: %t", s.routingMode, s.privateDirect),
		fmt.Sprintf("Source: %s | layer: %s | group: %s", fallbackRouteField(s.source), fallbackRouteField(s.layer), fallbackRouteField(s.group)),
		fmt.Sprintf("Action: %s | target: %s", fallbackRouteField(s.action), s.target),
		"DNS profile binding: "+fallbackRouteField(s.dnsProfile)+" (NOT observed DNS use)",
		"Generation is a snapshot at query time; current declaration/core may differ.",
	)
	if s.evidence == "unknown" {
		lines = append(lines, "UNKNOWN: an earlier rule cannot be evaluated; no later FINAL assumed.")
	}
	for _, reason := range s.unknown {
		lines = append(lines, "Unknown condition: "+reason)
	}
	if s.unknownOmitted > 0 {
		lines = append(lines, fmt.Sprintf("... %d additional unknown conditions suppressed", s.unknownOmitted))
	}
	lines = append(lines, fmt.Sprintf("Native trace: %d rules; %d selected lines", s.traceTotal, len(s.trace)))
	lines = append(lines, s.trace...)
	if s.traceOmitted > 0 {
		lines = append(lines, fmt.Sprintf("... %d intermediate trace rules omitted (bounded view)", s.traceOmitted))
	}
	return lines
}

func fallbackRouteField(value string) string {
	if value == "" {
		return "unknown/unattributed"
	}
	return value
}
