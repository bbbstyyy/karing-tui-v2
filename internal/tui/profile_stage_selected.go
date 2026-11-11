package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

// beginSelectedSnapshotStageFromNodes is a *deliberate* operator action from
// the current, accepted node page. It does not infer fallback or select the
// live Core. The daemon ultimately validates the simple proxy-only shape,
// candidate membership, independent selector intent and snapshot CAS.
func (m *Model) beginSelectedSnapshotStageFromNodes() tea.Cmd {
	if m.page != nodesPage || m.initial.active() || m.overlayInFlight ||
		m.overlayConfirm != nil || m.profileStage.active() {
		return nil
	}
	m.overlayNotice = ""
	if m.width < minProfileStageWidth || m.height < minProfileStageHeight ||
		!m.profilesReady || m.profilesError || m.profilesTruncated ||
		!m.statusReady || m.statusError || m.status.APIVersion != apiv1.Version ||
		m.status.RecoveryRequired || m.status.ActiveOperation != "" ||
		m.status.DeclarationRevision == 0 ||
		!m.nodesReady || m.nodesError ||
		m.selected < 0 || m.selected >= len(m.profiles) {
		m.overlayNotice = "Replacement requires fresh complete source/status and terminal >=68x16; reload first."
		return nil
	}
	source := m.profiles[m.selected]
	if source.ProfileID == "" || m.nodesProfile != source.ProfileID ||
		m.nodes.ProfileID != source.ProfileID ||
		profile.ValidateProfileID(source.ProfileID) != nil ||
		inspectionSafeID(source.ProfileID) != source.ProfileID ||
		!source.Enabled || source.Revision == 0 ||
		!profileStageSourceSupported(source.Format) ||
		source.CurrentSnapshotID == nil ||
		*source.CurrentSnapshotID <= 0 || m.nodes.SnapshotID == nil ||
		*m.nodes.SnapshotID != *source.CurrentSnapshotID ||
		m.nodes.Limit != nodePageSize || m.nodes.Offset != m.nodesOffset ||
		m.nodes.Total <= 0 || m.nodes.Total > maxProfileStageNodes ||
		len(m.nodes.Nodes) == 0 || len(m.nodes.Nodes) > nodePageSize ||
		m.nodesOffset < 0 || m.nodesOffset+len(m.nodes.Nodes) > m.nodes.Total ||
		m.nodesScroll < 0 || m.nodesScroll >= len(m.nodes.Nodes) {
		m.overlayNotice = "Node page is stale, incomplete or unsafe; reload before choosing replacement."
		return nil
	}
	chosen := m.nodes.Nodes[m.nodesScroll]
	if chosen.Disabled || profile.ValidateExplicitSelectedNodeID(chosen.NodeID) != nil ||
		inspectionSafeID(chosen.NodeID) != chosen.NodeID {
		m.overlayNotice = "Chosen node is disabled or its ID is unsafe. No write sent."
		return nil
	}
	// Node page provided only an allowlisted ID. All substantive candidate
	// rights are rechecked by server-side Preview and guarded Stage.
	m.overlayNotice = ""
	if cmd := m.switchPage(profilesPage); cmd != nil {
		// Profiles navigation is local; any future async navigation must not
		// be executed as a side effect of user selection.
		m.profileStage.notice = "Node choice navigation changed; reload status. No write sent."
		return nil
	}
	return m.beginProfileStageForSelected(chosen.NodeID)
}
