package tui

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

func (f *fakeAPI) PutProfileNodeOverlay(
	ctx context.Context, profileID, nodeID string, request apiv1.ProfileNodeOverlayPutRequest,
) (apiv1.ProfileNodeOverlayResponse, error) {
	f.checkDeadline(ctx)
	f.overlayCalls++
	f.lastOverlay = request
	if f.overlayErr != nil {
		return apiv1.ProfileNodeOverlayResponse{}, f.overlayErr
	}
	data := f.nodes[profileID]
	for i := range data.Nodes {
		if data.Nodes[i].NodeID == nodeID {
			if data.Nodes[i].OverlayRevision != request.ExpectedRevision {
				return apiv1.ProfileNodeOverlayResponse{}, errors.New("overlay revision conflict")
			}
			data.Nodes[i].OverlayRevision++
			data.Nodes[i].Disabled = request.Overlay.Disabled
			data.Nodes[i].Favorite = request.Overlay.Favorite
			data.Nodes[i].Alias = request.Overlay.Alias
			data.Nodes[i].SortRank = request.Overlay.SortRank
			f.nodes[profileID] = data
			return apiv1.ProfileNodeOverlayResponse{
				ProfileID: profileID, NodeID: nodeID,
				Revision: data.Nodes[i].OverlayRevision,
				Overlay: request.Overlay,
			}, nil
		}
	}
	return apiv1.ProfileNodeOverlayResponse{}, errors.New("node disappeared")
}

func overlayTestModel(t *testing.T, api *fakeAPI) Model {
	t.Helper()
	m := NewModel(context.Background(), api)
	m, _ = updated(t, m, profilesLoaded{request: 1, value: apiv1.ProfileSourceListResponse{
		Profiles: []apiv1.ProfileSourceResponse{{ProfileID: "work"}},
	}})
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'3'}})
	if cmd == nil {
		t.Fatal("expected load nodes command")
	}
	m, _ = updated(t, m, cmd())
	if !m.nodesReady {
		t.Fatal("expected loaded node page")
	}
	return m
}

func TestOverlayNeedsExplicitConfirmationAndPreservesAllFields(t *testing.T) {
	rank := int64(32)
	snapshot := int64(81)
	api := &fakeAPI{nodes: map[string]apiv1.ProfileNodeListResponse{
		"work": {
			ProfileID: "work", SnapshotID: &snapshot, Total: 2,
			Nodes: []apiv1.ProfileNodeSummary{
				{NodeID: "a", DisplayName: "中文节点", OverlayRevision: 4, Alias: "custom", SortRank: &rank},
				{NodeID: "b", DisplayName: "backup", OverlayRevision: 7, Favorite: true},
			},
		},
	}}
	m := overlayTestModel(t, api)
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	if m.overlayConfirm == nil || api.overlayCalls != 0 || !strings.Contains(m.View(), "CONFIRM") {
		t.Fatal("favorite edit did not require confirmation")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.overlayConfirm != nil || api.overlayCalls != 0 {
		t.Fatal("cancelling should perform no write")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if m.nodesScroll != 1 {
		t.Fatal("node selection failed")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	if m.overlayConfirm == nil || m.overlayConfirm.nodeID != "b" {
		t.Fatal("disabled edit was not bound to selected NodeID")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyUp})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	if m.overlayConfirm == nil || m.overlayConfirm.request.ExpectedRevision != 4 {
		t.Fatal("CAS revision not captured")
	}
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if cmd == nil || !m.overlayInFlight {
		t.Fatal("confirmation did not schedule write")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if api.overlayCalls != 0 {
		t.Fatal("repeated confirmation issued a concurrent write")
	}
	if msg := cmd(); msg == nil {
		t.Fatal("write command returned no result")
	} else {
		var refresh tea.Cmd
		m, refresh = updated(t, m, msg)
		if refresh == nil || m.overlayInFlight {
			t.Fatal("completed overlay did not schedule read-back")
		}
		m, _ = updated(t, m, refresh())
	}
	if api.overlayCalls != 1 ||
		api.lastOverlay.ExpectedRevision != 4 ||
		!api.lastOverlay.Overlay.Favorite ||
		api.lastOverlay.Overlay.Disabled ||
		api.lastOverlay.Overlay.Alias != "custom" ||
		api.lastOverlay.Overlay.SortRank == nil ||
		*api.lastOverlay.Overlay.SortRank != 32 {
		t.Fatalf("full overlay was not preserved: %+v", api.lastOverlay)
	}
	if m.nodesScroll != 0 || !m.nodes.Nodes[0].Favorite ||
		m.nodes.Nodes[0].OverlayRevision != 5 {
		t.Fatal("overlay result not reconciled from fresh node page")
	}
	if !strings.Contains(m.View(), "declaration and running core unchanged") {
		t.Fatal("UI did not disclose no core apply")
	}
}

func TestOverlayFailureIsUncertainRedactedAndReadBackIsRequired(t *testing.T) {
	snapshot := int64(2)
	api := &fakeAPI{
		nodes: map[string]apiv1.ProfileNodeListResponse{
			"work": {
				ProfileID: "work", SnapshotID: &snapshot, Total: 1,
				Nodes: []apiv1.ProfileNodeSummary{{NodeID: "n1", DisplayName: "node", OverlayRevision: 8}},
			},
		},
		overlayErr: errors.New("401?token=SECRET_CREDENTIAL"),
	}
	m := overlayTestModel(t, api)
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'d'}})
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if cmd == nil {
		t.Fatal("missing write")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if m.nodesOffset != 0 || m.overlayConfirm != nil {
		t.Fatal("in-flight mutation allowed navigation")
	}
	m, _ = updated(t, m, overlaySaved{request: m.overlayRequest + 1, profileID: "work", nodeID: "n1"})
	if !m.overlayInFlight {
		t.Fatal("stale write response incorrectly accepted")
	}
	m, readBack := updated(t, m, cmd())
	if m.overlayInFlight || readBack == nil || strings.Contains(m.View(), "SECRET_CREDENTIAL") ||
		!strings.Contains(m.View(), "uncertain") {
		t.Fatalf("failure not safely reported: %s", m.View())
	}
	m, _ = updated(t, m, readBack())
	if m.nodes.Nodes[0].Disabled || api.overlayCalls != 1 {
		t.Fatal("failed write changed locally held node state")
	}
}

func TestOverlayCannotWriteWithoutAcceptedNodeSnapshot(t *testing.T) {
	api := &fakeAPI{nodes: map[string]apiv1.ProfileNodeListResponse{
		"work": {
			ProfileID: "work", Total: 1,
			Nodes: []apiv1.ProfileNodeSummary{{NodeID: "n1", DisplayName: "node"}},
		},
	}}
	m := overlayTestModel(t, api)
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'f'}})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'y'}})
	if m.overlayConfirm != nil || api.overlayCalls != 0 || m.overlayInFlight {
		t.Fatal("node without snapshot must remain read-only")
	}
}
