package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

// routeToggleRow holds safe route identity and typed binding references.
// No raw matcher, upstream DNS address or credentials are retained.
type routeToggleRow struct {
	layer   domain.RoutingLayer
	id      string
	origin  string
	enabled bool
	target domain.TargetRef
	dnsProfile string
	line    int
}

type routeToggleReceipt struct {
	row routeToggleRow
	choice routeBindingChoice
	stage apiv1.RouteEditStageRequest
}

type routeTogglePreviewLoaded struct {
	sequence uint64
	failed   bool
	receipt  *routeToggleReceipt
}

type routeToggleWriteLoaded struct {
	sequence uint64
	failed   bool
}

// Only untruncated, currently applied declarations may seed TUI edits. A
// previously staged declaration is never silently edited using stale applied
// rows. A derived region group, FINAL, or unsafe ID is never actionable.
func projectRouteToggleRows(raw apiv1.ConfigInspectionResponse, lines []string) []routeToggleRow {
	if raw.APIVersion != apiv1.Version ||
		raw.StagedUnapplied || raw.RouteTruncated ||
		raw.CurrentDeclarationRevision != raw.AppliedDeclarationRevision ||
		raw.GenerationID <= 0 {
		return nil
	}
	rows := make([]routeToggleRow, 0)
	searchFrom := 0
	for _, layer := range raw.Layers {
		for _, group := range layer.Groups {
			state := "off"
			if group.Enabled && layer.Enabled {
				state = "on"
			}
			matcher := strings.Join(group.MatchKinds, ",")
			if matcher == "" {
				matcher = "none"
			}
			label := safeText(fmt.Sprintf("  #%d %s (%s) [%s] match=%s",
				group.Order, inspectionSafeID(group.ID), group.Origin, state, matcher), 320)
			for searchFrom < len(lines) && lines[searchFrom] != label {
				searchFrom++
			}
			if searchFrom >= len(lines) {
				// The UI must never associate a command with a different row.
				return nil
			}
			line := searchFrom
			searchFrom++
			if layer.Layer == domain.LayerFinal || group.Origin == "region_append" ||
				(group.Origin != "custom" && group.Origin != "cn_preset") ||
				group.ID == "" || inspectionSafeID(group.ID) != group.ID ||
			!routeBindingSafeRef(group.Target) ||
			(group.DNSProfile != "" && inspectionSafeID(group.DNSProfile) != group.DNSProfile) {
				continue
			}
			rows = append(rows, routeToggleRow{
				layer: layer.Layer, id: group.ID, origin: group.Origin,
				enabled: group.Enabled, target: group.Target, dnsProfile: group.DNSProfile, line: line,
			})
		}
	}
	return rows
}

func (m *Model) moveRouteToggle(delta int) {
	if m.page != routingInspectPage || !m.inspection.ready || len(m.inspection.routeRows) == 0 {
		return
	}
	next := m.inspection.routeSelected + delta
	if next < 0 || next >= len(m.inspection.routeRows) {
		return
	}
	m.inspection.routeSelected = next
	line := m.inspection.routeRows[next].line
	available := max(1, m.height-5)
	if line < m.inspection.scroll {
		m.inspection.scroll = line
	} else if line >= m.inspection.scroll+available {
		m.inspection.scroll = line - available + 1
	}
}

func (m *Model) startRouteToggle() tea.Cmd {
	if m.page != routingInspectPage || !m.inspection.ready ||
		m.inspection.active || m.inspection.previewing || m.inspection.writing ||
		m.inspection.pending != nil || m.inspection.chooser != nil || len(m.inspection.routeRows) == 0 ||
		m.inspection.routeSelected >= len(m.inspection.routeRows) {
		return nil
	}
	row := m.inspection.routeRows[m.inspection.routeSelected]
	m.inspection.previewSeq++
	m.inspection.previewing = true
	m.inspection.notice = "Validating candidate against the current daemon declaration..."
	return previewRouteToggle(m.ctx, m.api, m.inspection.previewSeq, row,
		m.inspection.declarationRevision, m.inspection.configRevision, m.inspection.generationID)
}

func previewRouteToggle(ctx context.Context, api API, sequence uint64, row routeToggleRow,
	declarationRevision, configRevision uint64, generationID int64) tea.Cmd {
	return previewRouteEdit(ctx, api, sequence, row, routeBindingChoice{kind: "enabled"},
		declarationRevision, configRevision, generationID)
}

func validRouteToggleDigest(s string) bool {
	return validSelectionDigest(s) && strings.ToLower(s) == s
}

func (m *Model) acceptRouteTogglePreview(msg routeTogglePreviewLoaded) {
	if !m.inspection.previewing || msg.sequence != m.inspection.previewSeq ||
		m.page != routingInspectPage {
		return
	}
	m.inspection.previewing = false
	if msg.failed || msg.receipt == nil {
		m.inspection.notice = "Preview unavailable or stale; reload and select again. No write sent."
		return
	}
	m.inspection.pending = msg.receipt
	m.inspection.notice = "Compiler preview passed, core NOT checked. Confirm staging explicitly."
}

func (m *Model) confirmRouteToggle() tea.Cmd {
	if m.page != routingInspectPage || m.inspection.pending == nil ||
		m.inspection.previewing || m.inspection.writing {
		return nil
	}
	receipt := *m.inspection.pending
	m.inspection.pending = nil
	m.inspection.writeSeq++
	m.inspection.writing = true
	m.inspection.ready = false
	m.inspection.routeRows = nil
	m.inspection.notice = "Staging declaration only; active core remains unchanged..."
	return writeRouteToggle(m.ctx, m.api, m.inspection.writeSeq, receipt)
}

func writeRouteToggle(ctx context.Context, api API, sequence uint64, receipt routeToggleReceipt) tea.Cmd {
	return func() tea.Msg {
		result := routeToggleWriteLoaded{sequence: sequence, failed: true}
		if api == nil {
			return result
		}
		bounded, cancel := context.WithTimeout(ctx, 35*time.Second)
		defer cancel()
		staged, err := api.StageRouteEdit(bounded, receipt.stage)
		if err != nil ||
			staged.DeclarationRevision != receipt.stage.ExpectedDeclarationRevision+1 ||
			staged.DeclarationSHA256 != receipt.stage.CandidateSHA256 ||
			staged.NativeConfigSHA256 != receipt.stage.NativeConfigSHA256 ||
			!staged.CompilerValidated || staged.CoreValidated || !staged.Staged || staged.Applied {
			// Timeouts and broken responses can follow a durable commit.
			// No retry or assumption of rollback is safe.
			return result
		}
		result.failed = false
		return result
	}
}

func (m *Model) acceptRouteToggleWrite(msg routeToggleWriteLoaded) tea.Cmd {
	if !m.inspection.writing || msg.sequence != m.inspection.writeSeq {
		return nil
	}
	m.inspection.writing = false
	if m.page != routingInspectPage {
		m.inspection.discardAndForget()
		return nil
	}
	refresh := m.requestConfigInspection()
	if msg.failed {
		m.inspection.notice = "Stage uncertain/rejected. Reload declaration; DO NOT auto-retry."
	} else {
		m.inspection.notice = "Declaration staged, NOT applied. Review before explicit core apply."
	}
	return refresh
}
