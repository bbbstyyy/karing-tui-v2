package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

// Snapshot-to-declaration staging is an optional TUI capability. Older fake
// clients and read-only implementations remain compatible with API.
type profileStageAPI interface {
	PreviewProfileDeclaration(context.Context, string, apiv1.ProfileDeclarationPreviewRequest) (apiv1.ProfileDeclarationPreviewResponse, error)
	StageProfileDeclaration(context.Context, string, apiv1.ProfileDeclarationStageRequest) (apiv1.ProfileDeclarationStageResponse, error)
}

var _ profileStageAPI = (*client.Client)(nil)

const (
	minProfileStageWidth  = 68
	minProfileStageHeight = 16
	maxPreviewNodeSample  = 32
	maxProfileStageNodes  = 10000
)

type profileStageContext struct {
	profileID                 string
	snapshotID                int64
	replacementSelectedNodeID string
	sourceRevision            uint64
	declarationRevision       uint64
	configRevision            uint64
	appliedGeneration         *int64
	lastKnownGood             *int64
	statusRequest             uint64
	profilesRequest           uint64
}

type profileStageReceipt struct {
	context         profileStageContext
	candidateSHA256 string
	overlaySHA256   string
	snapshotNodes   int
	effectiveNodes  int
	added           int
	removed         int
	retained        int
}

type profileStageState struct {
	sequence         uint64
	previewing       bool
	writing          bool
	awaitingReadback bool
	context          profileStageContext
	pending          *profileStageReceipt
	notice           string
}

type profileStagePreviewLoaded struct {
	sequence uint64
	receipt  profileStageReceipt
	ok       bool
}

type profileStageWriteLoaded struct {
	sequence uint64
	ok       bool
}

func (s *profileStageState) active() bool {
	return s.previewing || s.writing || s.awaitingReadback || s.pending != nil
}

func (s *profileStageState) discard() {
	s.sequence++
	s.previewing = false
	s.pending = nil
	s.awaitingReadback = false
	s.notice = ""
	// An already dispatched write must never be interpreted as cancelled.
}

func profileStageCopyGeneration(v *int64) *int64 {
	if v == nil {
		return nil
	}
	n := *v
	return &n
}

func profileStageSourceSupported(format string) bool {
	switch format {
	case "sing-box", "clash-yaml", "uri-list", "uri-list-base64":
		return true
	}
	return false
}

func (m *Model) profileStageContextValid(ctx profileStageContext) bool {
	if m.page != profilesPage || m.width < minProfileStageWidth ||
		m.height < minProfileStageHeight || m.api == nil ||
		m.localSource.editing || m.localSource.pending != nil ||
		m.localSource.writing || m.localSource.awaitingReadback ||
		m.profileRefresh.pending != nil || m.profileRefresh.writing ||
		m.profileRefresh.awaitingReadback ||
		!m.profilesReady || m.profilesError || m.profilesTruncated ||
		!m.statusReady || m.statusError || m.status.APIVersion != apiv1.Version ||
		m.status.RecoveryRequired || m.status.ActiveOperation != "" ||
		m.statusRequest != ctx.statusRequest ||
		m.profilesRequest != ctx.profilesRequest ||
		m.status.DeclarationRevision != ctx.declarationRevision ||
		m.status.ConfigRevision != ctx.configRevision ||
		!sameApplyGeneration(m.status.AppliedGenerationID, ctx.appliedGeneration) ||
		!sameApplyGeneration(m.status.LastKnownGoodGenerationID, ctx.lastKnownGood) ||
		ctx.declarationRevision == 0 || ctx.snapshotID <= 0 ||
		(ctx.replacementSelectedNodeID != "" &&
			profile.ValidateExplicitSelectedNodeID(ctx.replacementSelectedNodeID) != nil) ||
		ctx.sourceRevision == 0 || m.selectedProfileID() != ctx.profileID ||
		m.selected < 0 || m.selected >= len(m.profiles) {
		return false
	}
	current := m.profiles[m.selected]
	return current.Enabled && current.Revision == ctx.sourceRevision &&
		current.CurrentSnapshotID != nil && *current.CurrentSnapshotID == ctx.snapshotID &&
		profile.ValidateProfileID(ctx.profileID) == nil &&
		inspectionSafeID(ctx.profileID) == ctx.profileID &&
		profileStageSourceSupported(current.Format)
}

func (m *Model) beginProfileStage() tea.Cmd {
	return m.beginProfileStageForSelected("")
}

// Unlike a normal snapshot preview, this requires the operator to choose the
// EXACT node ID from the current accepted Nodes page. It only previews a
// declaration; a later 'y' stages it and checked Core Apply stays separate.
func (m *Model) beginProfileStageForSelected(selectedNodeID string) tea.Cmd {
	if selectedNodeID != "" && profile.ValidateExplicitSelectedNodeID(selectedNodeID) != nil {
		m.profileStage.notice = "Invalid explicit replacement node. No write sent."
		return nil
	}
	if m.page != profilesPage || m.profileStage.active() {
		return nil
	}
	m.profileStage.notice = ""
	if _, ok := m.api.(profileStageAPI); !ok {
		m.profileStage.notice = "Snapshot staging API unavailable; update the CLI/daemon."
		return nil
	}
	if m.selected < 0 || m.selected >= len(m.profiles) {
		m.profileStage.notice = "Select a source with an accepted snapshot before staging."
		return nil
	}
	current := m.profiles[m.selected]
	var snapshotID int64
	if current.CurrentSnapshotID != nil {
		snapshotID = *current.CurrentSnapshotID
	}
	ctx := profileStageContext{
		profileID: current.ProfileID, snapshotID: snapshotID,
		replacementSelectedNodeID: selectedNodeID,
		sourceRevision:            current.Revision,
		declarationRevision:       m.status.DeclarationRevision,
		configRevision:            m.status.ConfigRevision,
		appliedGeneration:         profileStageCopyGeneration(m.status.AppliedGenerationID),
		lastKnownGood:             profileStageCopyGeneration(m.status.LastKnownGoodGenerationID),
		statusRequest:             m.statusRequest, profilesRequest: m.profilesRequest,
	}
	if !m.profileStageContextValid(ctx) {
		m.profileStage.notice = "Stage requires a complete source, an existing declaration, fresh status and terminal >=68x16. Press r to reload; first run uses Nodes [3] i."
		return nil
	}
	m.profileStage.discard()
	m.localSource.notice = ""
	m.profileRefresh.notice = ""
	m.profileStage.context = ctx
	m.profileStage.previewing = true
	m.profileStage.notice = "Reading snapshot impact; no declaration write or Core check."
	return loadProfileStagePreview(m.ctx, m.api.(profileStageAPI), m.profileStage.sequence, ctx)
}

func profileStagePreviewSafe(raw apiv1.ProfileDeclarationPreviewResponse, ctx profileStageContext) bool {
	if raw.ProfileID != ctx.profileID || raw.SnapshotID != ctx.snapshotID ||
		raw.SourceRevision != ctx.sourceRevision ||
		raw.BaseDeclarationRevision != ctx.declarationRevision ||
		raw.ReplacementSelectedNodeID != ctx.replacementSelectedNodeID ||
		(ctx.replacementSelectedNodeID != "" &&
			profile.ValidateExplicitSelectedNodeID(ctx.replacementSelectedNodeID) != nil) ||
		raw.CoreValidated || raw.Applied ||
		raw.SnapshotNodeCount <= 0 || raw.SnapshotNodeCount > maxProfileStageNodes ||
		raw.EffectiveNodeCount <= 0 || raw.EffectiveNodeCount > maxProfileStageNodes ||
		raw.EffectiveNodeCount > raw.SnapshotNodeCount ||
		raw.AddedNodeCount < 0 || raw.AddedNodeCount > maxProfileStageNodes ||
		raw.RemovedNodeCount < 0 || raw.RemovedNodeCount > maxProfileStageNodes ||
		raw.RetainedNodeCount < 0 || raw.RetainedNodeCount > maxProfileStageNodes ||
		raw.AddedNodeCount+raw.RetainedNodeCount != raw.EffectiveNodeCount ||
		!validRouteToggleDigest(raw.RuntimeOverlaySHA256) ||
		!validRouteToggleDigest(raw.CandidateSHA256) {
		return false
	}
	seen := make(map[string]bool, maxPreviewNodeSample*3)
	for _, sample := range []struct {
		ids       []string
		count     int
		truncated bool
	}{
		{raw.AddedNodeIDs, raw.AddedNodeCount, raw.AddedIDsTruncated},
		{raw.RemovedNodeIDs, raw.RemovedNodeCount, raw.RemovedIDsTruncated},
		{raw.RetainedNodeIDs, raw.RetainedNodeCount, raw.RetainedIDsTruncated},
	} {
		if len(sample.ids) != min(sample.count, maxPreviewNodeSample) ||
			sample.truncated != (sample.count > maxPreviewNodeSample) {
			return false
		}
		for _, id := range sample.ids {
			if profile.ValidateNodeID(id) != nil || inspectionSafeID(id) != id || seen[id] {
				return false
			}
			seen[id] = true
		}
	}
	return true
}

func loadProfileStagePreview(ctx context.Context, api profileStageAPI, sequence uint64, stageCtx profileStageContext) tea.Cmd {
	return func() tea.Msg {
		msg := profileStagePreviewLoaded{sequence: sequence}
		if api == nil {
			return msg
		}
		bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		raw, err := api.PreviewProfileDeclaration(bounded, stageCtx.profileID,
			apiv1.ProfileDeclarationPreviewRequest{
				SnapshotID:                  stageCtx.snapshotID,
				ExpectedDeclarationRevision: stageCtx.declarationRevision,
				ReplacementSelectedNodeID:   stageCtx.replacementSelectedNodeID,
			})
		if err != nil || bounded.Err() != nil || !profileStagePreviewSafe(raw, stageCtx) {
			return msg
		}
		msg.ok = true
		// Store only numeric deltas, immutable hashes and already validated IDs.
		// Never hold original node names, source URL, errors or raw diff arrays.
		msg.receipt = profileStageReceipt{
			context:         stageCtx,
			candidateSHA256: raw.CandidateSHA256,
			overlaySHA256:   raw.RuntimeOverlaySHA256,
			snapshotNodes:   raw.SnapshotNodeCount,
			effectiveNodes:  raw.EffectiveNodeCount,
			added:           raw.AddedNodeCount, removed: raw.RemovedNodeCount,
			retained: raw.RetainedNodeCount,
		}
		return msg
	}
}

func (m *Model) acceptProfileStagePreview(msg profileStagePreviewLoaded) {
	if !m.profileStage.previewing || msg.sequence != m.profileStage.sequence ||
		m.page != profilesPage {
		return
	}
	m.profileStage.previewing = false
	if !msg.ok || !m.profileStageContextValid(m.profileStage.context) ||
		msg.receipt.context.profileID != m.profileStage.context.profileID ||
		msg.receipt.context.snapshotID != m.profileStage.context.snapshotID ||
		msg.receipt.context.sourceRevision != m.profileStage.context.sourceRevision ||
		msg.receipt.context.declarationRevision != m.profileStage.context.declarationRevision ||
		msg.receipt.context.replacementSelectedNodeID != m.profileStage.context.replacementSelectedNodeID ||
		!validRouteToggleDigest(msg.receipt.candidateSHA256) ||
		!validRouteToggleDigest(msg.receipt.overlaySHA256) {
		m.profileStage.discard()
		m.profileStage.notice = "Preview refused; no write sent. Missing selected node? Nodes [3], then m."
		return
	}
	receipt := msg.receipt
	m.profileStage.pending = &receipt
	m.profileStage.notice = ""
}

func (m Model) profileStageLines() []string {
	s := m.profileStage
	if s.pending != nil {
		p := s.pending
		lines := []string{
			"SNAPSHOT -> DECLARATION: PREVIEW ONLY (NOT APPLIED)",
			fmt.Sprintf("Profile: %s | snapshot %d | source revision %d",
				p.context.profileID, p.context.snapshotID, p.context.sourceRevision),
			fmt.Sprintf("Base declaration rev %d -> staged rev %d; config rev %d unchanged",
				p.context.declarationRevision, p.context.declarationRevision+1, p.context.configRevision),
			fmt.Sprintf("Imported %d nodes, effective %d (after overlays)", p.snapshotNodes, p.effectiveNodes),
			fmt.Sprintf("Node diff: +%d added  -%d removed  =%d retained", p.added, p.removed, p.retained),
		}
		if id := p.context.replacementSelectedNodeID; id != "" {
			// Explicit stable IDs are terminal-safe ASCII and at most 128
			// bytes. Render the WHOLE ID in two <=66-column lines even at
			// 68x16; never ask a user to approve a truncated identity.
			lines = append(lines, "EXPLICIT replacement CurrentSelected ID:")
			for offset := 0; offset < len(id); offset += 64 {
				end := min(offset+64, len(id))
				lines = append(lines, "  "+id[offset:end])
			}
			return append(lines,
				"SHA decl: "+p.candidateSHA256[:16]+"... overlay: "+p.overlaySHA256[:16]+"...",
				"Stage is NOT Core Check/Apply; running LKG stays.",
				"y: CONFIRM Stage only; Esc: cancel; [1] a: Core Apply later.",
			)
		}
		return append(lines,
			"Declaration SHA256: "+p.candidateSHA256[:20]+"...",
			"Overlay SHA256:     "+p.overlaySHA256[:20]+"...",
			"Removed/rebound nodes may make Core Apply fail. This is NOT Core check.",
			"y: CONFIRM stage ONLY; Esc: discard; Core Apply is separate [1] a.",
		)
	}
	if s.previewing {
		return []string{
			"Reading snapshot-to-declaration impact (no write).",
			"No changes to the running Core or Last Known Good.",
			"Esc: cancel preview; q: quit.",
		}
	}
	if s.writing {
		return []string{
			"Sending ONE confirmed snapshot stage; Core is not being applied.",
			"An accepted write may finish after TUI disconnect. Never auto-retry.",
		}
	}
	if s.awaitingReadback {
		return []string{
			"Stage receipt accepted; verifying durable declaration status.",
			"No Core apply; do not retry while readback is pending.",
		}
	}
	return nil
}

func (m *Model) confirmProfileStage() tea.Cmd {
	if !m.profileStageContextValid(m.profileStage.context) ||
		m.profileStage.pending == nil || m.profileStage.previewing ||
		m.profileStage.writing || m.profileStage.awaitingReadback {
		m.profileStage.discard()
		m.profileStage.notice = "Stage context changed; reload and preview again. No write sent."
		return nil
	}
	p := *m.profileStage.pending
	if p.context.profileID != m.profileStage.context.profileID ||
		p.context.snapshotID != m.profileStage.context.snapshotID ||
		p.context.sourceRevision != m.profileStage.context.sourceRevision ||
		p.context.declarationRevision != m.profileStage.context.declarationRevision ||
		p.context.replacementSelectedNodeID != m.profileStage.context.replacementSelectedNodeID ||
		(p.context.replacementSelectedNodeID != "" &&
			profile.ValidateExplicitSelectedNodeID(p.context.replacementSelectedNodeID) != nil) ||
		!validRouteToggleDigest(p.candidateSHA256) || !validRouteToggleDigest(p.overlaySHA256) {
		m.profileStage.discard()
		m.profileStage.notice = "Stage receipt invalid; no write sent."
		return nil
	}
	request := apiv1.ProfileDeclarationStageRequest{
		SnapshotID:                  p.context.snapshotID,
		ExpectedSourceRevision:      p.context.sourceRevision,
		ExpectedDeclarationRevision: p.context.declarationRevision,
		CandidateSHA256:             p.candidateSHA256,
		RuntimeOverlaySHA256:        p.overlaySHA256,
		ReplacementSelectedNodeID:   p.context.replacementSelectedNodeID,
	}
	m.profileStage.pending = nil
	m.profileStage.previewing = false
	m.profileStage.writing = true
	m.profileStage.sequence++
	m.profileStage.notice = "One guarded declaration stage in progress; do not retry if uncertain."
	return writeProfileStage(m.ctx, m.api.(profileStageAPI), m.profileStage.sequence, p.context.profileID, request)
}

func writeProfileStage(ctx context.Context, api profileStageAPI, sequence uint64, id string,
	request apiv1.ProfileDeclarationStageRequest) tea.Cmd {
	return func() tea.Msg {
		msg := profileStageWriteLoaded{sequence: sequence}
		if api == nil {
			return msg
		}
		// A sent CAS stage can commit even if the UI exits. A result is not
		// proof until we also read back the new declaration revision.
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 40*time.Second)
		defer cancel()
		response, err := api.StageProfileDeclaration(bounded, id, request)
		msg.ok = err == nil && bounded.Err() == nil &&
			response.ProfileID == id && response.SourceRevision == request.ExpectedSourceRevision &&
			response.SnapshotID == request.SnapshotID &&
			response.DeclarationRevision == request.ExpectedDeclarationRevision+1 &&
			response.DeclarationSHA256 == request.CandidateSHA256 &&
			response.ReplacementSelectedNodeID == request.ReplacementSelectedNodeID &&
			!response.CoreValidated && !response.Applied
		return msg
	}
}

func (m *Model) acceptProfileStageWrite(msg profileStageWriteLoaded) tea.Cmd {
	if !m.profileStage.writing || msg.sequence != m.profileStage.sequence {
		return nil
	}
	m.profileStage.writing = false
	m.profileStage.awaitingReadback = msg.ok
	m.profileStage.pending = nil
	if msg.ok {
		m.profileStage.notice = "Stage response received; re-reading durable declaration before reporting success."
	} else {
		m.profileStage.notice = "Stage rejected/uncertain; inspect declaration state. NEVER auto-retry."
	}
	m.statusRequest++
	m.statusReady, m.statusError = false, false
	return loadStatus(m.ctx, m.api, m.statusRequest)
}

func (m *Model) acceptProfileStageReadback() {
	if !m.profileStage.awaitingReadback {
		return
	}
	m.profileStage.awaitingReadback = false
	base := m.profileStage.context
	if m.statusReady && m.status.APIVersion == apiv1.Version &&
		m.status.DeclarationRevision == base.declarationRevision+1 &&
		m.status.ConfigRevision == base.configRevision &&
		!m.status.RecoveryRequired && m.status.ActiveOperation == "" &&
		sameApplyGeneration(m.status.AppliedGenerationID, base.appliedGeneration) &&
		sameApplyGeneration(m.status.LastKnownGoodGenerationID, base.lastKnownGood) {
		m.profileStage.notice = fmt.Sprintf(
			"Verified staged declaration rev %d; config/Applied/LKG unchanged. [1] a to apply separately.",
			m.status.DeclarationRevision)
		return
	}
	m.profileStage.notice = "Stage readback inconsistent/unavailable; inspect status. NEVER auto-retry."
}
