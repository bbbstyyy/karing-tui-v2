package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const (
	maxInspectRoutes = 128
	maxInspectDNS    = 64
)

// Only pre-sanitized, capped display strings enter Model. Raw DNS hosts,
// arbitrary rule matcher contents and the native configuration never do.
type configInspectionState struct {
	sequence uint64
	active   bool
	ready    bool
	failed   bool
	scroll   int
	routing  []string
	dns      []string
}

type configInspectionLoaded struct {
	sequence uint64
	failed   bool
	routing  []string
	dns      []string
}

func (s *configInspectionState) discardAndForget() {
	s.sequence++
	s.active, s.ready, s.failed = false, false, false
	s.scroll = 0
	s.routing, s.dns = nil, nil
}

func (m *Model) requestConfigInspection() tea.Cmd {
	if (m.page != routingInspectPage && m.page != dnsInspectPage) || m.inspection.active {
		return nil
	}
	m.inspection.sequence++
	m.inspection.active = true
	m.inspection.ready, m.inspection.failed = false, false
	m.inspection.routing, m.inspection.dns = nil, nil
	m.inspection.scroll = 0
	return loadConfigInspection(m.ctx, m.api, m.inspection.sequence)
}

func loadConfigInspection(ctx context.Context, api API, seq uint64) tea.Cmd {
	return func() tea.Msg {
		msg := configInspectionLoaded{sequence: seq, failed: true}
		if api == nil {
			return msg
		}
		bounded, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		raw, err := api.InspectConfig(bounded)
		if err != nil {
			return msg
		}
		routing, dns, err := projectConfigInspection(raw)
		if err != nil {
			return msg
		}
		msg.failed = false
		msg.routing, msg.dns = routing, dns
		return msg
	}
}

func (m *Model) acceptConfigInspection(msg configInspectionLoaded) {
	if !m.inspection.active || msg.sequence != m.inspection.sequence ||
		(m.page != routingInspectPage && m.page != dnsInspectPage) {
		return
	}
	m.inspection.active = false
	m.inspection.ready = !msg.failed
	m.inspection.failed = msg.failed
	m.inspection.scroll = 0
	if !msg.failed {
		m.inspection.routing, m.inspection.dns = msg.routing, msg.dns
	}
}

func (m Model) configInspectionLines() []string {
	title := "Routing"
	if m.page == dnsInspectPage {
		title = "DNS"
	}
	switch {
	case m.inspection.active:
		return []string{title + ": reading bounded applied declaration snapshot..."}
	case m.inspection.failed:
		return []string{title + ": inspection unavailable or inconsistent; press r to retry.",
			"No previous applied configuration or live DNS path is inferred."}
	case !m.inspection.ready:
		return []string{title + ": press r to load applied declaration."}
	case m.page == dnsInspectPage:
		return m.inspection.dns
	default:
		return m.inspection.routing
	}
}

func projectConfigInspection(raw apiv1.ConfigInspectionResponse) ([]string, []string, error) {
	if raw.Evidence != "applied_declaration" || raw.GenerationID <= 0 ||
		raw.AppliedDeclarationRevision == 0 || raw.CurrentDeclarationRevision == 0 ||
		len(raw.Layers) != 5 || raw.RouteTotal < 1 || raw.DNS.ProfileCount < 0 ||
		len(raw.DNS.Profiles) > maxInspectDNS || raw.DNS.ProfileCount < len(raw.DNS.Profiles) ||
		(raw.DNS.Truncated != (raw.DNS.ProfileCount > len(raw.DNS.Profiles))) {
		return nil, nil, errors.New("inconsistent inspection header")
	}
	head := fmt.Sprintf("Stored applied generation %d / config rev %d / declaration rev %d",
		raw.GenerationID, raw.ConfigRevision, raw.AppliedDeclarationRevision)
	drift := fmt.Sprintf("Current declaration rev %d | staged=%t",
		raw.CurrentDeclarationRevision, raw.StagedUnapplied)
	changes := fmt.Sprintf("Preview delta: routing changed=%t DNS changed=%t rule sets changed=%t",
		raw.RoutingChanged, raw.DNSChanged, raw.RuleSetsChanged)
	if !raw.StagedUnapplied && (raw.RoutingChanged || raw.DNSChanged || raw.RuleSetsChanged ||
		raw.CurrentDeclarationRevision != raw.AppliedDeclarationRevision) {
		return nil, nil, errors.New("inconsistent staged changes")
	}
	if raw.StagedUnapplied && raw.CurrentDeclarationRevision == raw.AppliedDeclarationRevision {
		return nil, nil, errors.New("inconsistent staged revision")
	}
	common := []string{
		head,
		"Evidence: APPLIED DECLARATION reconstruction, not live route/DNS observation",
		drift, changes,
	}
	routing := append([]string(nil), common...)
	routing = append(routing,
		fmt.Sprintf("Order: custom > geosite > geoip > acl > FINAL | CN preset=%t region auto=%t",
			raw.CNPreset, raw.RegionAppend),
		fmt.Sprintf("Groups: %d total; capped at %d non-FINAL rows; truncated=%t",
			raw.RouteTotal, maxInspectRoutes, raw.RouteTruncated),
		"Source and match categories only; matcher values/servers are never included.",
		"Shadowing/actual rule hits are not inferred here; use page 4 for simulation.",
	)
	layers := []domain.RoutingLayer{
		domain.LayerCustom, domain.LayerGeoSite, domain.LayerGeoIP, domain.LayerACL, domain.LayerFinal,
	}
	shown, total := 0, 0
	for i, layer := range raw.Layers {
		if layer.Layer != layers[i] || layer.GroupCount < 0 ||
			layer.ActiveCount < 0 || layer.ActiveCount > layer.GroupCount ||
			len(layer.Groups) > layer.GroupCount || (!layer.Enabled && layer.ActiveCount != 0) {
			return nil, nil, errors.New("invalid layer metadata")
		}
		if i == 4 && (!layer.Enabled || layer.GroupCount != 1 ||
			layer.ActiveCount != 1 || len(layer.Groups) != 1) {
			return nil, nil, errors.New("invalid FINAL layer")
		}
		total += layer.GroupCount
		routing = append(routing, fmt.Sprintf("[%s] layer enabled=%t active=%d total=%d",
			layer.Layer, layer.Enabled, layer.ActiveCount, layer.GroupCount))
		for _, row := range layer.Groups {
			if i == 4 && (row.ID != "FINAL" || !row.Enabled) {
				return nil, nil, errors.New("invalid FINAL group")
			}
			if row.Target.Kind != "" && row.Target.Validate() != nil {
				return nil, nil, errors.New("invalid routing target")
			}
			if row.Enabled && row.Target.Kind == "" {
				return nil, nil, errors.New("enabled group with no target")
			}
			switch row.Origin {
			case "custom", "cn_preset", "region_append", "declaration":
			default:
				return nil, nil, errors.New("unrecognized group provenance")
			}
			for _, kind := range row.MatchKinds {
				if !inspectionMatchKind(kind) {
					return nil, nil, errors.New("unrecognized matcher category")
				}
			}
			matcher := strings.Join(row.MatchKinds, ",")
			if matcher == "" {
				matcher = "none"
			}
			state := "off"
			if row.Enabled && layer.Enabled {
				state = "on"
			}
			routing = append(routing,
				fmt.Sprintf("  #%d %s (%s) [%s] match=%s",
					row.Order, inspectionSafeID(row.ID), row.Origin, state, matcher),
				fmt.Sprintf("      target=%s dns=%s",
					inspectionTarget(row.Target), inspectionSafeID(row.DNSProfile)))
			if i != 4 {
				shown++
			}
		}
	}
	if total != raw.RouteTotal || shown > maxInspectRoutes ||
		raw.RouteTruncated != (shown < total-1) {
		return nil, nil, errors.New("inconsistent route truncation")
	}
	dns := append([]string(nil), common...)
	dns = append(dns,
		"DNS: declarative bindings only. NOT proof of DNS request path or remote resolution.",
		fmt.Sprintf("Roles: outbound=%s direct=%s proxy=%s fallback=%s",
			inspectionSafeID(raw.DNS.OutboundProfile), inspectionSafeID(raw.DNS.DirectProfile),
			inspectionSafeID(raw.DNS.ProxyProfile), inspectionSafeID(raw.DNS.FallbackProfile)),
		fmt.Sprintf("Profiles: %d total; capped at %d; truncated=%t",
			raw.DNS.ProfileCount, maxInspectDNS, raw.DNS.Truncated),
		"DNS server addresses and credentials are deliberately omitted.",
	)
	seen := make(map[string]bool)
	for _, row := range raw.DNS.Profiles {
		if row.Port == 0 || row.ID == "" || seen[row.ID] {
			return nil, nil, errors.New("invalid DNS profile")
		}
		seen[row.ID] = true
		switch row.Role {
		case domain.DNSRoleBootstrap, domain.DNSRoleOutbound, domain.DNSRoleDirect,
			domain.DNSRoleProxy, domain.DNSRoleGroup, domain.DNSRoleFallback:
		default:
			return nil, nil, errors.New("invalid DNS role")
		}
		if row.Transport != domain.DNSTransportUDP && row.Transport != domain.DNSTransportTCP {
			return nil, nil, errors.New("invalid DNS transport")
		}
		if row.UpstreamKind != "IP literal" && row.UpstreamKind != "hostname (bootstrap required)" {
			return nil, nil, errors.New("invalid DNS upstream kind")
		}
		if row.Role != domain.DNSRoleGroup && row.Detour != nil {
			return nil, nil, errors.New("unexpected DNS detour")
		}
		detour := "role default"
		if row.Detour != nil {
			if err := row.Detour.Validate(); err != nil {
				return nil, nil, errors.New("invalid DNS detour")
			}
			detour = inspectionTarget(*row.Detour)
		}
		dns = append(dns,
			fmt.Sprintf("  %s [%s] %s/%d upstream=%s",
				inspectionSafeID(row.ID), row.Role, row.Transport, row.Port, row.UpstreamKind),
			fmt.Sprintf("      bootstrap=%s detour=%s", inspectionSafeID(row.BootstrapID), detour))
	}
	// Final defensive sanitizer: no raw upstream error or matcher payload is
	// retained in the Bubble Tea model even if a hostile daemon replies.
	for i := range routing {
		routing[i] = safeText(routing[i], 320)
	}
	for i := range dns {
		dns[i] = safeText(dns[i], 320)
	}
	return routing, dns, nil
}

func inspectionMatchKind(kind string) bool {
	switch domain.PredicateKind(kind) {
	case domain.PredicateDomain, domain.PredicateDomainSuffix, domain.PredicateDomainKeyword,
		domain.PredicateDomainRegex, domain.PredicateIPCIDR, domain.PredicateRuleSet,
		domain.PredicatePort, domain.PredicateNetwork, domain.PredicateProcessName:
		return true
	default:
		return false
	}
}

// IDs are imported/user-controlled references. Never echo URL-like or
// credential-like content into a diagnostic screen.
func inspectionSafeID(s string) string {
	if s == "" {
		return "-"
	}
	lower := strings.ToLower(s)
	for _, secret := range []string{"://", "token", "secret", "password", "passwd",
		"apikey", "api_key", "@", "?", "#", "\\", "\x1b"} {
		if strings.Contains(lower, secret) {
			return "[redacted]"
		}
	}
	if len(s) > 120 {
		return "[oversized]"
	}
	return safeText(s, 120)
}

func inspectionTarget(t domain.TargetRef) string {
	switch t.Kind {
	case domain.TargetSpecificNode:
		return "node " + inspectionSafeID(t.ProfileID) + "/" + inspectionSafeID(t.NodeID)
	case domain.TargetCustomURLTest:
		return "custom_urltest " + inspectionSafeID(t.GroupID)
	case domain.TargetDirect, domain.TargetBlock, domain.TargetCurrentSelected, domain.TargetGlobalURLTest:
		return string(t.Kind)
	case "":
		return "unset"
	default:
		return "unknown"
	}
}
