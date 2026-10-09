package tui

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	tea "github.com/charmbracelet/bubbletea"
)

type routeBindingChoice struct {
	kind   string
	target domain.TargetRef
	dnsID  string
}
type routeBindingChooser struct {
	row      routeToggleRow
	kind     string
	options  []routeBindingChoice
	selected int
}

// Do not store unsanitized, potentially credential-shaped reference IDs.
func routeBindingSafeRef(t domain.TargetRef) bool {
	if t.Kind == "" {
		return t == (domain.TargetRef{})
	}
	if t.Validate() != nil {
		return false
	}
	for _, id := range []string{t.GroupID, t.ProfileID, t.NodeID} {
		if id != "" && inspectionSafeID(id) != id {
			return false
		}
	}
	return true
}

// Targets are limited to built-ins plus *already bound* stable references in
// the complete applied declaration. We do not infer the complete node set.
func projectRouteBindingChoices(raw apiv1.ConfigInspectionResponse) ([]domain.TargetRef, []string, bool) {
	if raw.StagedUnapplied || raw.RouteTruncated || raw.CurrentDeclarationRevision != raw.AppliedDeclarationRevision {
		return nil, nil, false
	}
	targets := []domain.TargetRef{
		{Kind: domain.TargetDirect}, {Kind: domain.TargetBlock},
		{Kind: domain.TargetCurrentSelected}, {Kind: domain.TargetGlobalURLTest},
	}
	seen := make(map[domain.TargetRef]bool, maxInspectRoutes+5)
	for _, target := range targets {
		seen[target] = true
	}
	for _, layer := range raw.Layers {
		for _, group := range layer.Groups {
			target := group.Target
			if target.Kind != "" && routeBindingSafeRef(target) && !seen[target] {
				targets = append(targets, target)
				seen[target] = true
			}
		}
	}
	// Incomplete DNS lists do not authorize a new group-role binding.
	dnsComplete := !raw.DNS.Truncated && raw.DNS.ProfileCount == len(raw.DNS.Profiles)
	if !dnsComplete {
		return targets, nil, false
	}
	groups := make([]string, 0, len(raw.DNS.Profiles))
	for _, dns := range raw.DNS.Profiles {
		if dns.Role == domain.DNSRoleGroup && dns.ID != "" && inspectionSafeID(dns.ID) == dns.ID {
			groups = append(groups, dns.ID)
		}
	}
	return targets, groups, true
}

func (m *Model) beginRouteBindingChooser(kind string) {
	if m.page != routingInspectPage || !m.inspection.ready || m.inspection.active ||
		m.inspection.previewing || m.inspection.writing || m.inspection.pending != nil ||
		m.inspection.chooser != nil || m.inspection.routeSelected < 0 ||
		m.inspection.routeSelected >= len(m.inspection.routeRows) {
		return
	}
	row := m.inspection.routeRows[m.inspection.routeSelected]
	options := make([]routeBindingChoice, 0, maxInspectRoutes+5)
	switch kind {
	case "target":
		for _, candidate := range m.inspection.targetChoices {
			if candidate == row.target || candidate.Kind == domain.TargetBlock && row.dnsProfile != "" {
				continue
			}
			if routeBindingSafeRef(candidate) && candidate.Kind != "" {
				options = append(options, routeBindingChoice{kind: kind, target: candidate})
			}
		}
	case "dns":
		if !m.inspection.dnsComplete {
			m.inspection.notice = "DNS list incomplete; binding edit disabled. No write sent."
			return
		}
		if row.dnsProfile != "" {
			options = append(options, routeBindingChoice{kind: kind, dnsID: ""})
		}
		if row.target.Kind != domain.TargetBlock {
			for _, id := range m.inspection.dnsChoices {
				if id != row.dnsProfile {
					options = append(options, routeBindingChoice{kind: kind, dnsID: id})
				}
			}
		}
	default:
		return
	}
	if len(options) == 0 {
		m.inspection.notice = "No other safe candidate in this applied snapshot; no write sent."
		return
	}
	m.inspection.chooser = &routeBindingChooser{row: row, kind: kind, options: options}
	m.inspection.notice = ""
	// Make the first selectable candidate visible even in a 32x7 terminal.
	m.inspection.scroll = max(0, 5-max(1, m.height-5))
}

func routeBindingChoiceText(choice routeBindingChoice) string {
	if choice.kind == "target" {
		return inspectionTarget(choice.target)
	}
	if choice.kind == "dns" {
		if choice.dnsID == "" {
			return "clear group binding (use declared role fallback)"
		}
		return inspectionSafeID(choice.dnsID)
	}
	return "unknown"
}

func (m Model) routeBindingChooserLines() []string {
	chooser := m.inspection.chooser
	if chooser == nil {
		return nil
	}
	current := inspectionTarget(chooser.row.target)
	if chooser.kind == "dns" {
		current = inspectionSafeID(chooser.row.dnsProfile)
	}
	lines := []string{
		"Routing binding chooser (not applied)",
		fmt.Sprintf("Group: %s [%s] origin=%s", inspectionSafeID(chooser.row.id), chooser.row.layer, chooser.row.origin),
		"Current " + chooser.kind + ": " + current,
		"j/k to choose; Enter to compile preview; Esc cancels.",
	}
	for i, option := range chooser.options {
		cursor := "  "
		if i == chooser.selected {
			cursor = "> "
		}
		lines = append(lines, cursor+routeBindingChoiceText(option))
	}
	return lines
}

func (m *Model) moveRouteBindingChooser(delta int) {
	c := m.inspection.chooser
	if c == nil {
		return
	}
	next := c.selected + delta
	if next < 0 || next >= len(c.options) {
		return
	}
	c.selected = next
	line := 4 + next
	available := max(1, m.height-5)
	if line < m.inspection.scroll {
		m.inspection.scroll = line
	} else if line >= m.inspection.scroll+available {
		m.inspection.scroll = line - available + 1
	}
}

func (m *Model) previewRouteBindingChoice() tea.Cmd {
	if m.page != routingInspectPage || m.inspection.chooser == nil ||
		m.inspection.active || m.inspection.previewing || m.inspection.writing || m.inspection.pending != nil {
		return nil
	}
	c := m.inspection.chooser
	if c.selected < 0 || c.selected >= len(c.options) {
		return nil
	}
	row, choice := c.row, c.options[c.selected]
	m.inspection.chooser = nil
	m.inspection.previewSeq++
	m.inspection.previewing = true
	m.inspection.notice = "Strict compiler preview in progress; no declaration write."
	m.inspection.scroll = row.line
	return previewRouteEdit(m.ctx, m.api, m.inspection.previewSeq, row, choice,
		m.inspection.declarationRevision, m.inspection.configRevision, m.inspection.generationID)
}

func previewRouteEdit(ctx context.Context, api API, seq uint64, row routeToggleRow, choice routeBindingChoice,
	declarationRevision, configRevision uint64, generationID int64) tea.Cmd {
	return func() tea.Msg {
		result := routeTogglePreviewLoaded{sequence: seq, failed: true}
		if api == nil || declarationRevision == 0 || generationID <= 0 {
			return result
		}
		bounded, cancel := context.WithTimeout(ctx, 28*time.Second)
		defer cancel()
		binding, err := api.RouteEditContext(bounded)
		if err != nil || binding.APIVersion != apiv1.Version ||
			binding.DeclarationRevision != declarationRevision || binding.ConfigRevision != configRevision ||
			binding.AppliedGenerationID == nil || *binding.AppliedGenerationID != generationID ||
			!validRouteToggleDigest(binding.DeclarationSHA256) {
			return result
		}
		req := apiv1.RouteEditRequest{
			ExpectedDeclarationRevision: binding.DeclarationRevision,
			ExpectedDeclarationSHA256:   binding.DeclarationSHA256,
			ExpectedConfigRevision:      binding.ConfigRevision,
			ExpectedGenerationID:        cloneGenerationID(binding.AppliedGenerationID),
			ExpectedSelectionRevision:   binding.SelectionRevision,
			Layer:                       row.layer, GroupID: row.id,
		}
		afterEnabled, afterTarget, afterDNS := row.enabled, row.target, row.dnsProfile
		switch choice.kind {
		case "enabled":
			afterEnabled = !row.enabled
			req.Enabled = &afterEnabled
		case "target":
			if !routeBindingSafeRef(choice.target) || choice.target.Kind == "" || choice.target == row.target ||
				choice.target.Kind == domain.TargetBlock && row.dnsProfile != "" {
				return result
			}
			afterTarget = choice.target
			req.Target = &afterTarget
		case "dns":
			if choice.dnsID == row.dnsProfile || choice.dnsID != "" && inspectionSafeID(choice.dnsID) != choice.dnsID ||
				choice.dnsID != "" && row.target.Kind == domain.TargetBlock {
				return result
			}
			afterDNS = choice.dnsID
			req.DNSProfileID = &afterDNS
		default:
			return result
		}
		preview, err := api.PreviewRouteEdit(bounded, req)
		expectedOrigin := row.origin
		if expectedOrigin == "cn_preset" {
			expectedOrigin = "cn_preset_override"
		}
		if err != nil || preview.APIVersion != apiv1.Version ||
			!reflect.DeepEqual(preview.Request, req) || preview.Origin != expectedOrigin ||
			preview.BeforeEnabled != row.enabled || preview.AfterEnabled != afterEnabled ||
			!reflect.DeepEqual(preview.BeforeTarget, row.target) || !reflect.DeepEqual(preview.AfterTarget, afterTarget) ||
			preview.BeforeDNSProfileID != row.dnsProfile || preview.AfterDNSProfileID != afterDNS ||
			!validRouteToggleDigest(preview.CandidateSHA256) ||
			!validRouteToggleDigest(preview.NativeConfigSHA256) ||
			preview.NativeSchemaID == "" || preview.RouteEntryCount < 0 ||
			preview.DNSServerCount < 0 || preview.RuleSetCount < 0 ||
			!preview.CompilerValidated || preview.CoreValidated || preview.Staged || preview.Applied {
			return result
		}
		result.failed = false
		result.receipt = &routeToggleReceipt{
			row: row, choice: choice,
			stage: apiv1.RouteEditStageRequest{
				RouteEditRequest:   req,
				CandidateSHA256:    preview.CandidateSHA256,
				NativeConfigSHA256: preview.NativeConfigSHA256,
			},
		}
		return result
	}
}

func (m Model) routeBindingReceiptLines() []string {
	receipt := m.inspection.pending
	if receipt == nil {
		return nil
	}
	row, choice := receipt.row, receipt.choice
	before, after := "", ""
	switch choice.kind {
	case "enabled":
		before, after = fmt.Sprint(row.enabled), fmt.Sprint(!row.enabled)
	case "target":
		before, after = inspectionTarget(row.target), inspectionTarget(choice.target)
	case "dns":
		before, after = inspectionSafeID(row.dnsProfile), inspectionSafeID(choice.dnsID)
	}
	return []string{
		"COMPILER PREVIEW - NOT core checked, staged or applied",
		fmt.Sprintf("Route: %s [%s] origin=%s", inspectionSafeID(row.id), row.layer, row.origin),
		"Field: " + choice.kind,
		"Before: " + before, "After:  " + after,
		"y: STAGE the declaration only; Esc: cancel.",
		"Staging does NOT modify active core or prove live DNS paths.",
	}
}
