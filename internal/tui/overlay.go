package tui

import (
	"context"
	"errors"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

// overlayProposal captures the entire overlay and its CAS revision before a
// confirmation. Never reconstruct a full replacement from default values.
type overlayProposal struct {
	profileID string
	nodeID    string
	action    string
	request   apiv1.ProfileNodeOverlayPutRequest
}

type overlaySaved struct {
	request   uint64
	profileID string
	nodeID    string
	err       error
}

// Mutations run only in bounded commands, never in Update or View. An I/O error
// is ambiguous: the daemon may have committed the request before the timeout.
func writeOverlay(ctx context.Context, api API, sequence uint64, proposal overlayProposal) tea.Cmd {
	return func() tea.Msg {
		result := overlaySaved{request: sequence, profileID: proposal.profileID, nodeID: proposal.nodeID}
		if api == nil {
			result.err = errors.New("missing TUI client")
			return result
		}
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		response, err := api.PutProfileNodeOverlay(bounded, proposal.profileID, proposal.nodeID, proposal.request)
		if err == nil && (response.ProfileID != proposal.profileID || response.NodeID != proposal.nodeID ||
			response.Revision <= proposal.request.ExpectedRevision) {
			err = errors.New("inconsistent daemon overlay response")
		}
		result.err = err
		return result
	}
}

// Only favorite and disabled are editable in this initial TUI slice. Preserve
// alias and sort rank exactly as observed; the daemon guards concurrent edits
// with overlay revision CAS. Node changes never stage/apply the core.
func (m *Model) proposeOverlay(favorite bool) {
	if m.page != nodesPage || !m.profilesReady || !m.nodesReady ||
		m.nodesProfile != m.selectedProfileID() || m.nodes.SnapshotID == nil ||
		m.nodesScroll < 0 || m.nodesScroll >= len(m.nodes.Nodes) {
		return
	}
	node := m.nodes.Nodes[m.nodesScroll]
	request := apiv1.ProfileNodeOverlayPutRequest{
		ExpectedRevision: node.OverlayRevision,
		Overlay: apiv1.ProfileNodeOverlaySpec{
			Disabled: node.Disabled,
			Favorite: node.Favorite,
			Alias:    node.Alias,
		},
	}
	if node.SortRank != nil {
		rank := *node.SortRank
		request.Overlay.SortRank = &rank
	}
	action := "toggle favorite"
	if favorite {
		request.Overlay.Favorite = !node.Favorite
	} else {
		request.Overlay.Disabled = !node.Disabled
		action = "toggle disabled"
	}
	m.overlayConfirm = &overlayProposal{
		profileID: m.nodesProfile,
		nodeID:    node.NodeID,
		action:    action,
		request:   request,
	}
	m.overlayNotice = ""
}
