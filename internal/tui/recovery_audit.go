package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

// Only allowlisted status enums and numeric metadata enter the model.
type historyState struct {
	sequence uint64
	cancel   context.CancelFunc
	active   bool
	ready    bool
	failed   bool
	scroll   int
	rows     []string
}

type historyLoaded struct {
	sequence uint64
	failed   bool
	rows     []string
}

func (s *historyState) discardAndForget() {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	s.sequence++
	s.active, s.ready, s.failed = false, false, false
	s.scroll = 0
	s.rows = nil
}

func (m *Model) requestHistory() tea.Cmd {
	if m.page != historyPage || m.history.active {
		return nil
	}
	if m.history.cancel != nil {
		m.history.cancel()
	}
	requestCtx, cancel := context.WithCancel(m.ctx)
	m.history.cancel = cancel
	m.history.sequence++
	m.history.active = true
	m.history.ready, m.history.failed = false, false
	m.history.scroll = 0
	m.history.rows = nil
	return loadHistory(requestCtx, m.api, m.history.sequence)
}

func loadHistory(ctx context.Context, api API, sequence uint64) tea.Cmd {
	return func() tea.Msg {
		message := historyLoaded{sequence: sequence, failed: true}
		if api == nil {
			return message
		}
		bounded, cancel := context.WithTimeout(ctx, 29*time.Second)
		defer cancel()
		result, err := api.RecoveryAudit(bounded)
		if err != nil || bounded.Err() != nil || !apiv1.ValidRecoveryAudit(result) {
			return message
		}
		message.failed = false
		message.rows = projectHistoryRows(result)
		return message
	}
}

func (m *Model) acceptHistory(msg historyLoaded) {
	if m.page != historyPage || !m.history.active || msg.sequence != m.history.sequence {
		return
	}
	if m.history.cancel != nil {
		m.history.cancel()
		m.history.cancel = nil
	}
	m.history.active = false
	m.history.ready, m.history.failed = !msg.failed, msg.failed
	m.history.scroll = 0
	if msg.failed {
		m.history.rows = nil
		return
	}
	m.history.rows = msg.rows
}

func (m Model) historyLines() []string {
	if m.history.active {
		return []string{"History: reading a bounded, read-only audit...", "No restore action is available."}
	}
	if m.history.failed {
		return []string{"History: audit unavailable, changed or untrusted.", "Press r to retry the read. Manual restore remains disabled."}
	}
	if !m.history.ready {
		return []string{"History: press r to load. Manual restore remains disabled."}
	}
	return m.history.rows
}

func projectHistoryRows(result apiv1.RecoveryAuditResponse) []string {
	// Only call after strict validation. This projection must never
	// display raw paths, payloads, upstream errors, credentials or URLs.
	rows := []string{
		"History: confirmed generations (read-only; RESTORE DISABLED)",
		"Stored integrity is NOT live core, DNS or routing verification.",
		fmt.Sprintf("Config revision: %d  declaration revision: %d", result.ConfigRevision, result.CurrentDeclarationRevision),
		fmt.Sprintf("Applied: %s  LKG: %s  recovery required: %t  active apply: %t",
			generationLabel(result.AppliedGenerationID), generationLabel(result.LastKnownGoodGenerationID),
			result.RecoveryRequired, result.ActiveApply),
		fmt.Sprintf("Committed records shown: %d (max 12)  more omitted: %t", len(result.Generations), result.Truncated),
	}
	if len(result.Generations) == 0 {
		rows = append(rows, "No committed generation records in this audit.")
	}
	for _, gen := range result.Generations {
		role := "historical"
		switch {
		case gen.Applied && gen.LastKnownGood:
			role = "applied+LKG"
		case gen.Applied:
			role = "applied"
		case gen.LastKnownGood:
			role = "LKG"
		}
		preflight := gen.PreflightStatus
		if preflight == "" {
			preflight = "not_checked"
		}
		rows = append(rows,
			fmt.Sprintf("#%d  config r%d  %s  payload=%t  rule sets=%d",
				gen.GenerationID, gen.CommittedConfigRevision, role, gen.PayloadRetained, gen.RuleSetCount),
			fmt.Sprintf("  status=%s  preflight=%s", gen.Status, preflight),
			fmt.Sprintf("  stored_hash=%t  resources=%t  declaration r%d  restore_ready=false",
				gen.StoredIntegrityVerified, gen.RuleSetResourcesVerified, gen.DeclarationRevision),
		)
	}
	return append(rows, "No restore button or hot-reload command is offered; use CLI for machine-readable audit.")
}
