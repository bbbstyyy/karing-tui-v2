package tui

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const (
	maxObservedRows      = 30
	maxConnectionUnknown = 2
)

// The daemon returns privacy-sensitive connection metadata. Only bounded,
// explicitly allowlisted projections may reach persistent TUI model state.
type selectionObservation struct {
	sequence uint64
	active   bool
	discard  bool
	ready    bool
	failed   bool
	result   selectionSummary
}

type selectionSummary struct {
	target    string
	persisted bool
	live      string
}

type selectionObservationLoaded struct {
	sequence uint64
	result   selectionSummary
	failed   bool
}

type connectionsObservation struct {
	sequence uint64
	active   bool
	discard  bool
	ready    bool
	failed   bool
	scroll   int
	result   connectionsSummary
}

type connectionsSummary struct {
	generationID   int64
	configRevision uint64
	total          int
	upload         int64
	download       int64
	rows           []connectionSummary
}

type connectionSummary struct {
	destination    string
	port           string
	inbound        string
	network        string
	upload         int64
	download       int64
	sourceEvidence string
	sourceDecision string
	sourceLayer    string
	sourceGroup    string
	sourceTarget   string
	dnsBinding     string
	unknown        []string
	unknownOmitted int
}

type connectionsObservationLoaded struct {
	sequence uint64
	result   connectionsSummary
	failed   bool
}

func (s *selectionObservation) discardAndForget() {
	s.discard = true
	s.ready, s.failed = false, false
	s.result = selectionSummary{}
}

func (s *connectionsObservation) discardAndForget() {
	s.discard = true
	s.ready, s.failed = false, false
	s.scroll = 0
	s.result = connectionsSummary{}
}

func (m *Model) requestSelectionObservation() tea.Cmd {
	if m.page != selectionPage || m.selection.active {
		return nil
	}
	m.selection.sequence++
	m.selection.active = true
	m.selection.discard = false
	m.selection.ready, m.selection.failed = false, false
	m.selection.result = selectionSummary{}
	return loadSelectionObservation(m.ctx, m.api, m.selection.sequence)
}

func loadSelectionObservation(ctx context.Context, api API, sequence uint64) tea.Cmd {
	return func() tea.Msg {
		msg := selectionObservationLoaded{sequence: sequence}
		if api == nil {
			msg.failed = true
			return msg
		}
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		raw, err := api.CurrentSelection(bounded)
		if err != nil {
			msg.failed = true
			return msg
		}
		if err := raw.Target.Validate(); err != nil {
			msg.failed = true
			return msg
		}
		if raw.Applied && (raw.LiveRuntimeTag == "" || raw.LiveRuntimeTag != raw.RuntimeTag) {
			msg.failed = true
			return msg
		}
		result := selectionSummary{
			target:    routeProbeTarget(&raw.Target),
			persisted: raw.Persisted,
			live:      "not observed (core stopped or unavailable)",
		}
		if raw.LiveRuntimeTag != "" {
			if raw.Applied {
				result.live = "matches durable intent"
			} else {
				result.live = "MISMATCH (durable intent not live)"
			}
		}
		msg.result = result
		return msg
	}
}

func (m *Model) acceptSelectionObservation(msg selectionObservationLoaded) {
	if !m.selection.active || msg.sequence != m.selection.sequence {
		return
	}
	m.selection.active = false
	if m.page != selectionPage || m.selection.discard {
		return
	}
	m.selection.ready = !msg.failed
	m.selection.failed = msg.failed
	if !msg.failed {
		m.selection.result = msg.result
	}
}

func (m Model) selectionObservationLines() []string {
	lines := []string{
		"CurrentSelected: read-only intent and live selector evidence",
		"Changing selection requires daemon-side CAS, not yet available in TUI.",
	}
	switch {
	case m.selection.active:
		return append(lines, "Reading local daemon selection...")
	case m.selection.failed:
		return append(lines, "Selection unavailable or inconsistent; no default assumed. Press r.")
	case !m.selection.ready:
		return append(lines, "Press r to inspect persisted and live selection.")
	}
	s := m.selection.result
	lines = append(lines, "Selected typed target: "+s.target)
	if s.persisted {
		lines = append(lines, "Intent: persisted (survives core restarts)")
	} else {
		lines = append(lines, "Intent: bound declaration default (not explicitly persisted)")
	}
	lines = append(lines, "Live selector readback: "+s.live)
	return append(lines, "No core or declaration was changed by this page.")
}

func (m *Model) requestConnectionsObservation() tea.Cmd {
	if m.page != connectionsPage || m.connections.active {
		return nil
	}
	m.connections.sequence++
	m.connections.active = true
	m.connections.discard = false
	m.connections.ready, m.connections.failed = false, false
	m.connections.scroll = 0
	m.connections.result = connectionsSummary{}
	return loadConnectionsObservation(m.ctx, m.api, m.connections.sequence)
}

func loadConnectionsObservation(ctx context.Context, api API, sequence uint64) tea.Cmd {
	return func() tea.Msg {
		msg := connectionsObservationLoaded{sequence: sequence}
		if api == nil {
			msg.failed = true
			return msg
		}
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		raw, err := api.ObservedConnections(bounded)
		if err != nil || raw.Evidence != "observed" || raw.GenerationID <= 0 {
			msg.failed = true
			return msg
		}
		summary, err := projectObservedConnections(raw)
		if err != nil {
			msg.failed = true
			return msg
		}
		msg.result = summary
		return msg
	}
}

func projectObservedConnections(raw apiv1.ObservedConnectionsResponse) (connectionsSummary, error) {
	result := connectionsSummary{
		generationID:   raw.GenerationID,
		configRevision: raw.ConfigRevision,
		total:          len(raw.Connections),
		upload:         raw.UploadTotal,
		download:       raw.DownloadTotal,
	}
	limit := min(len(raw.Connections), maxObservedRows)
	result.rows = make([]connectionSummary, 0, limit)
	for _, rawRow := range raw.Connections[:limit] {
		if rawRow.Evidence != "observed" {
			return connectionsSummary{}, errors.New("connection evidence mismatch")
		}
		switch rawRow.SourceEvidence {
		case "unknown":
			if rawRow.SourceDecision != "" && rawRow.SourceDecision != "unknown" {
				return connectionsSummary{}, errors.New("inconsistent unknown source")
			}
		case "simulated":
			if rawRow.SourceDecision != "route" && rawRow.SourceDecision != "reject" {
				return connectionsSummary{}, errors.New("inconsistent simulated source")
			}
		default:
			return connectionsSummary{}, errors.New("unsupported source evidence")
		}
		row := connectionSummary{
			destination:    safeConnectionDestination(rawRow.Host, rawRow.DestinationIP),
			port:           safeConnectionPort(rawRow.DestinationPort),
			inbound:        safeConnectionInbound(rawRow.Inbound),
			network:        safeConnectionNetwork(rawRow.Network),
			upload:         rawRow.Upload,
			download:       rawRow.Download,
			sourceEvidence: rawRow.SourceEvidence,
		}
		if rawRow.SourceEvidence == "simulated" {
			row.sourceDecision = rawRow.SourceDecision
			row.sourceLayer = safeConnectionLayer(rawRow.SourceLayer)
			row.sourceGroup = clipRouteText(rawRow.SourceGroupID)
			if rawRow.SourceTarget != nil && rawRow.SourceTarget.Validate() == nil {
				row.sourceTarget = routeProbeTarget(rawRow.SourceTarget)
			}
			row.dnsBinding = clipRouteText(rawRow.SourceDNSProfileID)
		} else {
			for _, reason := range rawRow.SourceUnknownConditions {
				if len(row.unknown) == maxConnectionUnknown {
					break
				}
				row.unknown = append(row.unknown, safeConnectionUnknownReason(reason))
			}
			row.unknownOmitted = len(rawRow.SourceUnknownConditions) - len(row.unknown)
		}
		result.rows = append(result.rows, row)
	}
	return result, nil
}

func safeConnectionUnknownReason(raw string) string {
	switch raw {
	case "inbound", "network", "destination_port", "destination_ip", "source_explain_error",
		"source_generation_mismatch", "routing_mode_readback", "routing_mode_mismatch",
		"domain", "ip", "port", "process_name", "ip_is_private", "routing_mode":
		return raw
	default:
		if strings.HasPrefix(raw, "rule_set:") {
			return "rule_set (opaque)"
		}
		return "other_unknown_condition"
	}
}

func safeConnectionDestination(host, ip string) string {
	if host != "" {
		if parsed, err := parseRouteProbeInput(host, domain.InboundRule); err == nil {
			if parsed.Domain != "" {
				return clipRouteText(parsed.Domain)
			}
			if parsed.IP != "" {
				return parsed.IP
			}
		}
	}
	if value, err := netip.ParseAddr(ip); err == nil && value.Zone() == "" {
		return value.Unmap().String()
	}
	return "unavailable"
}

func safeConnectionPort(raw string) string {
	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || value == 0 {
		return "?"
	}
	return strconv.FormatUint(value, 10)
}

func safeConnectionInbound(raw string) string {
	switch {
	case strings.HasSuffix(raw, "/"+domain.InboundTagRule):
		return "Rule"
	case strings.HasSuffix(raw, "/"+domain.InboundTagDirect):
		return "Direct"
	case strings.HasSuffix(raw, "/"+domain.InboundTagSelected):
		return "Selected"
	default:
		return "unknown"
	}
}

func safeConnectionNetwork(raw string) string {
	if raw == "tcp" || raw == "udp" {
		return raw
	}
	return "unknown"
}

func safeConnectionLayer(layer domain.RoutingLayer) string {
	switch layer {
	case domain.LayerCustom, domain.LayerGeoSite, domain.LayerGeoIP, domain.LayerACL, domain.LayerFinal:
		return string(layer)
	default:
		return "unattributed"
	}
}

func (m *Model) acceptConnectionsObservation(msg connectionsObservationLoaded) {
	if !m.connections.active || msg.sequence != m.connections.sequence {
		return
	}
	m.connections.active = false
	if m.page != connectionsPage || m.connections.discard {
		return
	}
	m.connections.ready = !msg.failed
	m.connections.failed = msg.failed
	if !msg.failed {
		m.connections.result = msg.result
	}
	m.connections.scroll = 0
}

func (m Model) connectionsObservationLines() []string {
	lines := []string{
		"Connections: OBSERVED core snapshot (no streaming/polling)",
		"Source attribution: SIMULATED or UNKNOWN; not observed native source groups.",
	}
	switch {
	case m.connections.active:
		return append(lines, "Fetching one bounded local connection snapshot...")
	case m.connections.failed:
		return append(lines, "Observation unavailable or inconsistent. Press r to retry.")
	case !m.connections.ready:
		return append(lines, "Press r to fetch one connection snapshot.")
	}
	s := m.connections.result
	lines = append(lines,
		fmt.Sprintf("Generation: %d | config revision: %d", s.generationID, s.configRevision),
		fmt.Sprintf("Transfer totals (bytes): up=%d down=%d", s.upload, s.download),
		fmt.Sprintf("Showing %d of %d active connections (no history)", len(s.rows), s.total),
	)
	if s.total > len(s.rows) {
		lines = append(lines, fmt.Sprintf("%d connections omitted by TUI cap", s.total-len(s.rows)))
	}
	if s.total == 0 {
		return append(lines, "No active connections observed at query time.")
	}
	for i, row := range s.rows {
		lines = append(lines, fmt.Sprintf("%d. %s %s %s:%s up=%d down=%d",
			i+1, row.inbound, row.network, row.destination, row.port, row.upload, row.download))
		switch row.sourceEvidence {
		case "simulated":
			lines = append(lines, fmt.Sprintf("   source[SIMULATED]: %s %s/%s target=%s dns=%s (binding only)",
				row.sourceDecision, fallbackRouteField(row.sourceLayer),
				fallbackRouteField(row.sourceGroup), fallbackRouteField(row.sourceTarget),
				fallbackRouteField(row.dnsBinding)))
		default:
			reasons := strings.Join(row.unknown, ",")
			if reasons == "" {
				reasons = "unavailable"
			}
			if row.unknownOmitted > 0 {
				reasons += fmt.Sprintf(" +%d more", row.unknownOmitted)
			}
			lines = append(lines, "   source[UNKNOWN]: "+reasons+" (no source inferred)")
		}
	}
	return lines
}
