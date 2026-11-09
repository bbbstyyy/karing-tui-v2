package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/cnreadiness"
)

// Read-only, fail-closed view of the exact Karing CN source snapshot.
// No editable groups, download, application or resource-management controls.
type cnReadinessState struct {
	sequence uint64
	cancel   context.CancelFunc
	active   bool
	ready    bool
	failed   bool
	scroll   int
	rows     []string
}

type cnReadinessLoaded struct {
	sequence uint64
	failed   bool
	rows     []string // already projected; never hold an untrusted full API report
}

func (s *cnReadinessState) discardAndForget() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.sequence++
	s.active, s.ready, s.failed = false, false, false
	s.scroll = 0
	s.rows = nil
}

func (m *Model) requestCNReadiness() tea.Cmd {
	if m.page != cnReadinessPage || m.cnReadiness.active {
		return nil
	}
	if m.cnReadiness.cancel != nil {
		m.cnReadiness.cancel()
	}
	ctx, cancel := context.WithCancel(m.ctx)
	m.cnReadiness.cancel = cancel
	m.cnReadiness.sequence++
	m.cnReadiness.active = true
	m.cnReadiness.ready, m.cnReadiness.failed = false, false
	m.cnReadiness.rows = nil
	m.cnReadiness.scroll = 0
	return loadCNReadiness(ctx, m.api, m.cnReadiness.sequence)
}

func loadCNReadiness(ctx context.Context, api API, sequence uint64) tea.Cmd {
	return func() tea.Msg {
		message := cnReadinessLoaded{sequence: sequence, failed: true}
		if api == nil {
			return message
		}
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		raw, err := api.CNReadiness(bounded)
		if err != nil || bounded.Err() != nil || !cnreadiness.ValidPinnedReport(raw) {
			// Neither raw body nor raw errors may ever enter UI state.
			return message
		}
		rows := []string{
			fmt.Sprintf("Pinned Karing CN: %d groups / %d default on (SOURCE ONLY)", raw.TotalGroupCount, raw.DefaultEnabledCount),
			fmt.Sprintf("Rule resources: %d logical refs / %d file candidates", raw.LogicalResourceRefs, raw.FileBackedCandidates),
			"Missing upstream: geoip:bing; source licenses unresolved",
			"Five layers: Custom > GeoSite > GeoIP > ACL > FINAL; subscription/ISP excluded",
			"Original group order (NOT an applied Core or DNS readback):",
		}
		for _, group := range raw.Groups {
			enabled := "off"
			if group.EnabledByDefault {
				enabled = "on"
			}
			rows = append(rows, fmt.Sprintf("%02d  %-24s  %-3s  %-16s  %s",
				group.Order, group.ID, enabled, group.TargetKind, group.Name))
		}
		for i := range rows {
			rows[i] = safeText(rows[i], 240)
		}
		message.failed = false
		message.rows = rows
		return message
	}
}

func (m *Model) acceptCNReadiness(msg cnReadinessLoaded) {
	if !m.cnReadiness.active || msg.sequence != m.cnReadiness.sequence {
		return
	}
	m.cnReadiness.active = false
	if m.cnReadiness.cancel != nil {
		m.cnReadiness.cancel()
		m.cnReadiness.cancel = nil
	}
	if m.page != cnReadinessPage {
		return
	}
	m.cnReadiness.ready = !msg.failed
	m.cnReadiness.failed = msg.failed
	if msg.failed {
		m.cnReadiness.rows = nil
		return
	}
	m.cnReadiness.rows = append([]string(nil), msg.rows...)
	m.cnReadiness.scroll = 0
}

func (m Model) cnReadinessLines() []string {
	lines := []string{
		"CN source inventory: NOT READY FOR APPLY OR REDISTRIBUTION.",
		"Source evidence only; no assertion of installed or active CN rules.",
	}
	switch {
	case m.cnReadiness.active:
		return append(lines, "Reading one bounded, read-only daemon snapshot...")
	case m.cnReadiness.failed:
		return append(lines, "CN report unavailable or inconsistent; no readiness assumed. Press r.")
	case !m.cnReadiness.ready:
		return append(lines, "Press r to load source inventory (no writes).")
	default:
		return append(lines, m.cnReadiness.rows...)
	}
}
