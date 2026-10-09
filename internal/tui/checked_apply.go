package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

// Applying a declaration may replace the core and interrupt connections.
// Keep the entire confirmation, including risk and selected revision, visible.
const (
	minApplyConfirmWidth  = 64
	minApplyConfirmHeight = 16
)

type checkedApplyState struct {
	sequence      uint64
	statusRequest uint64
	previewing    bool
	writing       bool
	pending       *apiv1.CheckedApplyPreviewResponse
	notice        string
}

type checkedApplyPreviewLoaded struct {
	sequence uint64
	preview  apiv1.CheckedApplyPreviewResponse
	ok       bool
}

type checkedApplyWriteLoaded struct {
	sequence    uint64
	verified    bool
	status      apiv1.StatusResponse
	statusValid bool
	generation  int64
	configRev   uint64
	declaration uint64
}

func sameApplyGeneration(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (s *checkedApplyState) discard() {
	s.sequence++
	s.statusRequest = 0
	s.previewing = false
	s.pending = nil
	s.notice = ""
	// A dispatched write is never cancelled or assumed rolled back by the UI.
}

func safeTUIApplyPreview(p apiv1.CheckedApplyPreviewResponse) bool {
	r := p.Receipt
	if p.APIVersion != apiv1.Version || !p.CompilerValidated || p.CoreValidated || p.Applied ||
		r.DeclarationRevision == 0 || r.DeclarationRevision >= 1<<63-1 ||
		r.ExpectedConfigRevision >= 1<<63-1 ||
		!validRouteToggleDigest(r.DeclarationSHA256) ||
		!validRouteToggleDigest(r.NativeConfigSHA256) ||
		(r.ExpectedAppliedGenerationID != nil && *r.ExpectedAppliedGenerationID <= 0) ||
		p.RouteEntryCount < 0 || p.DNSServerCount < 0 || p.RuleSetCount < 0 ||
		p.NativeSchemaID == "" || len(p.NativeSchemaID) > 64 {
		return false
	}
	if safeText(p.NativeSchemaID, 64) != p.NativeSchemaID ||
		inspectionSafeID(p.NativeSchemaID) != p.NativeSchemaID {
		return false
	}
	return true
}

func (m *Model) startCheckedApplyPreview() tea.Cmd {
	if m.page != dashboardPage || !m.statusReady || m.api == nil ||
		m.checkedApply.previewing || m.checkedApply.writing || m.checkedApply.pending != nil {
		return nil
	}
	if m.width < minApplyConfirmWidth || m.height < minApplyConfirmHeight {
		m.checkedApply.notice = "Apply requires a terminal at least 64x16; no request sent."
		return nil
	}
	if m.status.APIVersion != apiv1.Version || !m.status.CoreConfigured ||
		m.status.RecoveryRequired || m.status.ActiveOperation != "" {
		m.checkedApply.notice = "Apply unavailable: reload status or resolve recovery/active operation."
		return nil
	}
	m.checkedApply.sequence++
	m.checkedApply.previewing = true
	m.checkedApply.statusRequest = m.statusRequest
	m.checkedApply.notice = "Compiling current unapplied declaration (no core check or write)..."
	return loadCheckedApplyPreview(m.ctx, m.api, m.checkedApply.sequence)
}

func loadCheckedApplyPreview(ctx context.Context, api API, sequence uint64) tea.Cmd {
	return func() tea.Msg {
		msg := checkedApplyPreviewLoaded{sequence: sequence}
		if api == nil {
			return msg
		}
		bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		preview, err := api.CheckedApplyPreview(bounded)
		if err != nil || !safeTUIApplyPreview(preview) {
			return msg
		}
		msg.ok = true
		msg.preview = preview
		return msg
	}
}

func (m *Model) acceptCheckedApplyPreview(msg checkedApplyPreviewLoaded) {
	if m.page != dashboardPage || !m.checkedApply.previewing ||
		msg.sequence != m.checkedApply.sequence {
		return
	}
	m.checkedApply.previewing = false
	if !msg.ok || !m.statusReady || m.statusRequest != m.checkedApply.statusRequest ||
		m.status.RecoveryRequired || m.status.ActiveOperation != "" ||
		!m.status.CoreConfigured {
		m.checkedApply.notice = "Apply preview unavailable, invalid or stale; reload status. No write sent."
		return
	}
	r := msg.preview.Receipt
	if r.DeclarationRevision != m.status.DeclarationRevision ||
		r.ExpectedConfigRevision != m.status.ConfigRevision ||
		!sameApplyGeneration(r.ExpectedAppliedGenerationID, m.status.AppliedGenerationID) {
		m.checkedApply.notice = "Apply preview conflicts with Dashboard state; reload. No write sent."
		return
	}
	preview := msg.preview
	m.checkedApply.pending = &preview
	m.checkedApply.notice = ""
}

func (m Model) checkedApplyLines() []string {
	if m.checkedApply.writing {
		return []string{
			"Applying checked declaration (core may restart).",
			"Core check, activation, verification and commit in progress.",
			"Do not repeat the request; a daemon-accepted write may finish after q.",
			"Inspect new status and recovery before further changes.",
		}
	}
	if p := m.checkedApply.pending; p != nil {
		r := p.Receipt
		return []string{
			"CURRENT DECLARATION: COMPILER PREVIEW ONLY",
			fmt.Sprintf("Declaration revision %d  |  config revision %d", r.DeclarationRevision, r.ExpectedConfigRevision),
			fmt.Sprintf("Applied generation %s  |  selection revision %d",
				generationLabel(r.ExpectedAppliedGenerationID), r.ExpectedSelectionRevision),
			"Declaration SHA256: " + r.DeclarationSHA256[:20] + "...",
			"Compiled SHA256:    " + r.NativeConfigSHA256[:20] + "...",
			fmt.Sprintf("Schema: %s", p.NativeSchemaID),
			fmt.Sprintf("Routes: %d  DNS servers: %d  rule sets: %d",
				p.RouteEntryCount, p.DNSServerCount, p.RuleSetCount),
			"Core check has NOT run; no generation was changed by preview.",
			"APPLY MAY RESTART CORE AND INTERRUPT EXISTING CONNECTIONS.",
			"y: APPLY NOW   Esc: cancel   q: quit without sending",
		}
	}
	if m.checkedApply.previewing {
		return []string{
			"Checked apply: strictly compiling current unapplied declaration...",
			"No write or core validation is being performed.",
			"Esc: cancel view   r: reload status   q: quit",
		}
	}
	return nil
}

func (m *Model) confirmCheckedApply() tea.Cmd {
	if m.page != dashboardPage || m.checkedApply.pending == nil ||
		m.checkedApply.previewing || m.checkedApply.writing {
		return nil
	}
	if m.width < minApplyConfirmWidth || m.height < minApplyConfirmHeight {
		m.checkedApply.pending = nil
		m.checkedApply.notice = "Terminal became too small; confirmation discarded. No write sent."
		return nil
	}
	p := *m.checkedApply.pending
	if !safeTUIApplyPreview(p) || !m.statusReady ||
		m.statusRequest != m.checkedApply.statusRequest ||
		p.Receipt.DeclarationRevision != m.status.DeclarationRevision ||
		p.Receipt.ExpectedConfigRevision != m.status.ConfigRevision ||
		!sameApplyGeneration(p.Receipt.ExpectedAppliedGenerationID, m.status.AppliedGenerationID) {
		m.checkedApply.pending = nil
		m.checkedApply.notice = "Dashboard state or receipt changed. Reload and preview again. No write sent."
		return nil
	}
	m.checkedApply.pending = nil
	m.checkedApply.writing = true
	m.checkedApply.sequence++
	m.checkedApply.notice = ""
	m.statusRequest++ // reject any old in-flight status read
	m.statusReady = false
	m.statusError = false
	return writeCheckedApply(m.ctx, m.api, m.checkedApply.sequence, p)
}

func writeCheckedApply(ctx context.Context, api API, sequence uint64, preview apiv1.CheckedApplyPreviewResponse) tea.Cmd {
	return func() tea.Msg {
		msg := checkedApplyWriteLoaded{sequence: sequence}
		if api == nil {
			return msg
		}
		bounded, cancel := context.WithTimeout(ctx, 93*time.Second)
		defer cancel()
		result, err := api.CheckedApply(bounded, preview.Receipt)
		validResponse := err == nil &&
			result.CoreChecked && result.Verified && result.Applied &&
			result.AttemptID > 0 && result.GenerationID > 0 &&
			result.DeclarationRevision == preview.Receipt.DeclarationRevision &&
			result.DeclarationSHA256 == preview.Receipt.DeclarationSHA256 &&
			result.ConfigSHA256 == preview.Receipt.NativeConfigSHA256 &&
			result.NativeSchemaID == preview.NativeSchemaID &&
			result.BaseConfigRevision == preview.Receipt.ExpectedConfigRevision &&
			result.TargetConfigRevision == preview.Receipt.ExpectedConfigRevision+1

		// Always try a bounded durable readback, including for uncertain HTTP
		// errors. Readback alone NEVER triggers an implicit second apply.
		readCtx, readCancel := context.WithTimeout(ctx, 4*time.Second)
		defer readCancel()
		status, readErr := api.Status(readCtx)
		if readErr == nil && status.APIVersion == apiv1.Version {
			msg.status, msg.statusValid = status, true
		}
		if validResponse && msg.statusValid && !status.RecoveryRequired &&
			status.CoreConfigured && status.ConfigRevision == result.TargetConfigRevision &&
			status.AppliedGenerationID != nil &&
			*status.AppliedGenerationID == result.GenerationID {
			msg.verified = true
			msg.generation = result.GenerationID
			msg.configRev = result.TargetConfigRevision
			msg.declaration = result.DeclarationRevision
		}
		return msg
	}
}

func (m *Model) acceptCheckedApplyWrite(msg checkedApplyWriteLoaded) {
	if !m.checkedApply.writing || msg.sequence != m.checkedApply.sequence {
		return
	}
	m.checkedApply.writing = false
	if msg.statusValid {
		m.hasCoreError = msg.status.CoreLastError != ""
		msg.status.CoreLastError = "" // never retain sensitive core errors
		m.status = msg.status
		m.statusReady, m.statusError = true, false
	} else {
		m.statusReady, m.statusError = false, true
	}
	if msg.verified {
		m.checkedApply.notice = fmt.Sprintf(
			"Applied and verified: declaration rev %d, config rev %d, generation %d.",
			msg.declaration, msg.configRev, msg.generation)
	} else {
		m.checkedApply.notice = "Apply uncertain/failed; inspect refreshed status and recovery. NEVER auto-retry."
	}
}

func (m *Model) cancelCheckedApply() {
	m.checkedApply.discard()
	m.checkedApply.notice = "Checked apply cancelled. No apply request sent."
}
