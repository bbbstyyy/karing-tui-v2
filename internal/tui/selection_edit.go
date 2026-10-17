package tui

import (
	"context"
	"encoding/hex"
	"errors"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const (
	maxSelectionShown   = 128
	maxSelectionIDBytes = 256
)

type selectionProposal struct {
	target  domain.TargetRef
	request apiv1.CurrentSelectionCheckedRequest
}

type selectionWriteLoaded struct {
	sequence uint64
	failed   bool
}

// Only the allowlisted target references and optimistic identity fields reach
// TUI model state. Daemon runtime tags and raw error strings are never retained.
func projectSelectionObservation(raw apiv1.CurrentSelectionResponse) (selectionSummary, error) {
	if err := raw.Target.Validate(); err != nil {
		return selectionSummary{}, errors.New("invalid observed target")
	}
	if raw.Applied && (raw.LiveRuntimeTag == "" || raw.LiveRuntimeTag != raw.RuntimeTag) {
		return selectionSummary{}, errors.New("contradictory selector readback")
	}
	if raw.AppliedGenerationID != nil && *raw.AppliedGenerationID <= 0 {
		return selectionSummary{}, errors.New("invalid applied generation")
	}
	if raw.CandidateCount < 0 || len(raw.Candidates) > maxSelectionShown ||
		raw.CandidateCount < len(raw.Candidates) ||
		(raw.CandidatesTruncated && raw.CandidateCount <= len(raw.Candidates)) ||
		(!raw.CandidatesTruncated && raw.CandidateCount != len(raw.Candidates)) {
		return selectionSummary{}, errors.New("invalid candidate count")
	}
	seen := make(map[domain.TargetRef]bool, len(raw.Candidates))
	currentFound := false
	for _, candidate := range raw.Candidates {
		if err := candidate.Validate(); err != nil || !selectionCandidateKind(candidate.Kind) {
			return selectionSummary{}, errors.New("invalid candidate")
		}
		if len(candidate.ProfileID) > maxSelectionIDBytes ||
			len(candidate.NodeID) > maxSelectionIDBytes ||
			len(candidate.GroupID) > maxSelectionIDBytes ||
			seen[candidate] {
			return selectionSummary{}, errors.New("oversized or duplicate candidate")
		}
		seen[candidate] = true
		if candidate == raw.Target {
			currentFound = true
		}
	}
	if len(raw.Candidates) > 0 && !raw.CandidatesTruncated && !currentFound {
		return selectionSummary{}, errors.New("selected target absent from complete candidate list")
	}
	result := selectionSummary{
		target:     safeText(routeProbeTarget(&raw.Target), 120),
		targetRef:  raw.Target,
		persisted:  raw.Persisted,
		live:       "not observed (core stopped or unavailable)",
		candidates: append([]domain.TargetRef(nil), raw.Candidates...),
		total:      raw.CandidateCount,
		truncated:  raw.CandidatesTruncated,
		expected: apiv1.CurrentSelectionCheckedRequest{
			ExpectedSelectionRevision:   raw.SelectionRevision,
			ExpectedConfigRevision:      raw.ConfigRevision,
			ExpectedGenerationID:        cloneGenerationID(raw.AppliedGenerationID),
			ExpectedDeclarationRevision: raw.DeclarationRevision,
			ExpectedDeclarationSHA256:   raw.DeclarationSHA256,
		},
	}
	if raw.LiveRuntimeTag != "" {
		if raw.Applied {
			result.live = "matches durable intent"
		} else {
			result.live = "MISMATCH (durable intent not live)"
		}
	}
	// For the first confirmed TUI slice, only offer mutations with a
	// complete, generation-bound list. Without an applied generation, core
	// state cannot be proven by this endpoint; keep it read-only.
	result.editable = len(result.candidates) > 0 && !result.truncated &&
		raw.AppliedGenerationID != nil && raw.DeclarationRevision > 0 &&
		validSelectionDigest(raw.DeclarationSHA256)
	return result, nil
}

func cloneGenerationID(value *int64) *int64 {
	if value == nil {
		return nil
	}
	id := *value
	return &id
}

func validSelectionDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	bytes, err := hex.DecodeString(value)
	return err == nil && len(bytes) == 32
}

func selectionCandidateKind(kind domain.TargetKind) bool {
	switch kind {
	case domain.TargetSpecificNode, domain.TargetGlobalURLTest, domain.TargetCustomURLTest:
		return true
	default:
		return false
	}
}

func (m *Model) proposeSelection() {
	if m.page != selectionPage || !m.selection.ready || m.selection.active ||
		m.selection.writing || m.selection.pending != nil {
		return
	}
	s := m.selection.result
	if !s.editable || m.selection.selected < 0 || m.selection.selected >= len(s.candidates) {
		m.selection.notice = "Selection unavailable: reload a complete applied-generation candidate list."
		return
	}
	target := s.candidates[m.selection.selected]
	if target == s.targetRef {
		m.selection.notice = "Already selected; no write sent."
		return
	}
	request := s.expected
	request.Target = target
	m.selection.pending = &selectionProposal{target: target, request: request}
	m.selection.notice = ""
}

func (m *Model) confirmSelection() tea.Cmd {
	if m.page != selectionPage || m.selection.pending == nil ||
		m.selection.active || !m.selection.ready || m.selection.writing {
		return nil
	}
	proposal := *m.selection.pending
	m.selection.pending = nil
	m.selection.writeSeq++
	m.selection.writing = true
	m.selection.notice = ""
	m.selection.ready = false
	m.selection.result = selectionSummary{}
	return writeSelection(m.ctx, m.api, m.selection.writeSeq, proposal)
}

func writeSelection(ctx context.Context, api API, sequence uint64, proposal selectionProposal) tea.Cmd {
	return func() tea.Msg {
		result := selectionWriteLoaded{sequence: sequence, failed: true}
		if api == nil || proposal.request.ExpectedSelectionRevision >= 1<<63-1 {
			return result
		}
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		response, err := api.SetCurrentSelectionChecked(bounded, proposal.request)
		if err != nil {
			// A 409 means no write, but a network/502 error may mean the
			// durable CAS committed. Never retry automatically.
			return result
		}
		if response.Target != proposal.target ||
			response.SelectionRevision != proposal.request.ExpectedSelectionRevision+1 ||
			response.ConfigRevision != proposal.request.ExpectedConfigRevision ||
			!sameSelectionGeneration(response.AppliedGenerationID, proposal.request.ExpectedGenerationID) ||
			response.DeclarationRevision != proposal.request.ExpectedDeclarationRevision ||
			response.DeclarationSHA256 != proposal.request.ExpectedDeclarationSHA256 ||
			!response.Persisted {
			return result
		}
		result.failed = false
		return result
	}
}

func sameSelectionGeneration(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (m *Model) acceptSelectionWrite(msg selectionWriteLoaded) tea.Cmd {
	if !m.selection.writing || msg.sequence != m.selection.writeSeq {
		return nil
	}
	m.selection.writing = false
	if m.page != selectionPage {
		m.selection.discardAndForget()
		return nil
	}
	if msg.failed {
		m.selection.notice = "Write uncertain/conflicted; reloading state. No auto-retry."
	} else {
		m.selection.notice = "Write accepted; reloading durable/live selector readback."
	}
	return m.requestSelectionObservation()
}
