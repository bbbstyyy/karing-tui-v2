package tui

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

// The first-run API is an optional capability: legacy read-only TUI clients
// retain the existing API interface, while the real Unix client implements it.
type initialProfileAPI interface {
	PreviewInitialProfileDeclaration(context.Context, string, apiv1.InitialProfileDeclarationPreviewRequest) (apiv1.InitialProfileDeclarationPreviewResponse, error)
	StageInitialProfileDeclaration(context.Context, string, apiv1.InitialProfileDeclarationStageRequest) (apiv1.InitialProfileDeclarationStageResponse, error)
}

var _ initialProfileAPI = (*client.Client)(nil)

const (
	minInitialWidth          = 68
	minInitialHeight         = 16
	maxInitialResolverLength = 96
	initialRoutingMode       = "proxy-only-no-cn"
)

type initialProfileState struct {
	sequence         uint64
	editing          bool
	previewing       bool
	writing          bool
	awaitingReadback bool
	pending          *apiv1.InitialProfileDeclarationPreviewResponse
	profileID        string
	nodeID           string
	snapshotID       int64
	sourceRevision   uint64
	resolver         string
	statusRequest    uint64
	profilesRequest  uint64
	nodesRequest     uint64
	notice           string
}

type initialProfilePreviewLoaded struct {
	sequence uint64
	value    apiv1.InitialProfileDeclarationPreviewResponse
	ok       bool
}

type initialProfileStageLoaded struct {
	sequence uint64
	ok       bool
}

func (s *initialProfileState) active() bool {
	return s.editing || s.previewing || s.writing || s.pending != nil
}

func (s *initialProfileState) discard() {
	s.sequence++
	s.editing, s.previewing = false, false
	s.awaitingReadback = false
	s.pending = nil
	s.profileID, s.nodeID, s.resolver = "", "", ""
	s.snapshotID, s.sourceRevision = 0, 0
	s.statusRequest, s.profilesRequest, s.nodesRequest = 0, 0, 0
	// In-flight writes are never cancelled or interpreted as rolled back.
}

func initialResolverValid(value string) (string, bool) {
	addr, err := netip.ParseAddrPort(value)
	if err != nil || !addr.IsValid() || addr.Port() == 0 ||
		addr.Addr().IsUnspecified() || addr.Addr().IsMulticast() ||
		addr.Addr().Zone() != "" {
		return "", false
	}
	return addr.String(), true
}

func (m *Model) beginInitialProfile() {
	if m.page != nodesPage || m.initial.active() {
		return
	}
	m.initial.notice = ""
	if m.api == nil || m.width < minInitialWidth || m.height < minInitialHeight {
		m.initial.notice = "First-run setup requires a local daemon and terminal >= 68x16."
		return
	}
	if _, ok := m.api.(initialProfileAPI); !ok {
		m.initial.notice = "First-run setup API unavailable; update the CLI/daemon."
		return
	}
	if !m.statusReady || m.status.APIVersion != apiv1.Version ||
		m.status.DeclarationRevision != 0 || m.status.ConfigRevision != 0 ||
		m.status.AppliedGenerationID != nil || m.status.LastKnownGoodGenerationID != nil ||
		m.status.RecoveryRequired || m.status.ActiveOperation != "" {
		m.initial.notice = "First-run initialization is allowed only before any declaration or active generation."
		return
	}
	if !m.profilesReady || m.profilesTruncated || m.selected < 0 ||
		m.selected >= len(m.profiles) || !m.profiles[m.selected].Enabled ||
		m.profiles[m.selected].Revision == 0 || m.profiles[m.selected].CurrentSnapshotID == nil ||
		!m.nodesReady || m.nodesError || m.nodesProfile != m.profiles[m.selected].ProfileID ||
		m.nodes.SnapshotID == nil ||
		*m.nodes.SnapshotID != *m.profiles[m.selected].CurrentSnapshotID ||
		m.nodesScroll < 0 || m.nodesScroll >= len(m.nodes.Nodes) {
		m.initial.notice = "Reload a complete accepted source and node page before initialization."
		return
	}
	node := m.nodes.Nodes[m.nodesScroll]
	if profile.ValidateNodeID(node.NodeID) != nil || node.Disabled {
		m.initial.notice = "Selected node is invalid or disabled. Choose another accepted node."
		return
	}
	m.overlayConfirm = nil
	m.initial.discard()
	m.initial.editing = true
	m.initial.profileID = m.nodesProfile
	m.initial.nodeID = node.NodeID
	m.initial.snapshotID = *m.nodes.SnapshotID
	m.initial.sourceRevision = m.profiles[m.selected].Revision
	m.initial.statusRequest = m.statusRequest
	m.initial.profilesRequest = m.profilesRequest
	m.initial.nodesRequest = m.nodesRequest
	m.initial.notice = "Enter an explicit DNS IP:port; no default resolver will be selected."
}

func (m *Model) initialContextStillValid() bool {
	if m.page != nodesPage || m.width < minInitialWidth || m.height < minInitialHeight ||
		!m.statusReady || m.status.APIVersion != apiv1.Version ||
		m.statusRequest != m.initial.statusRequest ||
		m.status.DeclarationRevision != 0 || m.status.ConfigRevision != 0 ||
		m.status.AppliedGenerationID != nil || m.status.LastKnownGoodGenerationID != nil ||
		m.status.RecoveryRequired || m.status.ActiveOperation != "" ||
		!m.profilesReady || m.profilesTruncated ||
		m.profilesRequest != m.initial.profilesRequest ||
		m.nodesRequest != m.initial.nodesRequest || !m.nodesReady || m.nodesError ||
		m.nodesProfile != m.initial.profileID || m.selectedProfileID() != m.initial.profileID ||
		m.nodes.SnapshotID == nil || *m.nodes.SnapshotID != m.initial.snapshotID ||
		m.selected < 0 || m.selected >= len(m.profiles) {
		return false
	}
	source := m.profiles[m.selected]
	if !source.Enabled || source.Revision != m.initial.sourceRevision ||
		source.CurrentSnapshotID == nil || *source.CurrentSnapshotID != m.initial.snapshotID {
		return false
	}
	for _, node := range m.nodes.Nodes {
		if node.NodeID == m.initial.nodeID {
			return !node.Disabled
		}
	}
	return false
}

func (m *Model) initialResolverKey(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		m.initial.discard()
		m.initial.notice = "First-run setup cancelled; no declaration staged."
	case "backspace":
		if len(m.initial.resolver) > 0 {
			m.initial.resolver = m.initial.resolver[:len(m.initial.resolver)-1]
		}
	case "ctrl+u":
		m.initial.resolver = ""
	case "enter":
		resolver, ok := initialResolverValid(m.initial.resolver)
		if !ok || !m.initialContextStillValid() {
			m.initial.notice = "Invalid DNS IP:port or stale source/status; reload before staging."
			return nil
		}
		m.initial.resolver = resolver
		m.initial.editing = false
		m.initial.previewing = true
		m.initial.sequence++
		m.initial.notice = "Fetching read-only first-run preview; no Core operation."
		return loadInitialProfilePreview(m.ctx, m.api.(initialProfileAPI), m.initial.sequence,
			m.initial.profileID, apiv1.InitialProfileDeclarationPreviewRequest{
				SnapshotID:      m.initial.snapshotID,
				SelectedNodeID:  m.initial.nodeID,
				ResolverAddress: m.initial.resolver,
			})
	default:
		// A resolver is a bounded printable IP literal, not arbitrary
		// pasted terminal text, escape sequence, shell or URL.
		if msg.Type == tea.KeyRunes {
			for _, ch := range msg.Runes {
				if !strings.ContainsRune("0123456789abcdefABCDEF.:[]", ch) ||
					len(m.initial.resolver) >= maxInitialResolverLength {
					continue
				}
				m.initial.resolver += string(ch)
			}
		}
	}
	return nil
}

func loadInitialProfilePreview(
	ctx context.Context, api initialProfileAPI, seq uint64, id string,
	request apiv1.InitialProfileDeclarationPreviewRequest,
) tea.Cmd {
	return func() tea.Msg {
		msg := initialProfilePreviewLoaded{sequence: seq}
		if api == nil {
			return msg
		}
		bounded, cancel := context.WithTimeout(ctx, 25*time.Second)
		defer cancel()
		value, err := api.PreviewInitialProfileDeclaration(bounded, id, request)
		if err != nil || value.ProfileID != id || value.SnapshotID != request.SnapshotID ||
			value.SelectedNodeID != request.SelectedNodeID ||
			value.ResolverAddress != request.ResolverAddress ||
			value.SourceRevision == 0 || value.BaseDeclarationRevision != 0 ||
			value.EffectiveNodeCount <= 0 || !validRouteToggleDigest(value.CandidateSHA256) ||
			!validRouteToggleDigest(value.RuntimeOverlaySHA256) ||
			value.RoutingMode != initialRoutingMode || value.CNRulesReady ||
			value.Applied || value.CoreValidated {
			return msg
		}
		msg.ok = true
		msg.value = value
		return msg
	}
}

func (m *Model) acceptInitialPreview(msg initialProfilePreviewLoaded) {
	if !m.initial.previewing || msg.sequence != m.initial.sequence {
		return
	}
	m.initial.previewing = false
	if !msg.ok || !m.initialContextStillValid() ||
		msg.value.ProfileID != m.initial.profileID ||
		msg.value.SnapshotID != m.initial.snapshotID ||
		msg.value.SourceRevision != m.initial.sourceRevision ||
		msg.value.SelectedNodeID != m.initial.nodeID ||
		msg.value.ResolverAddress != m.initial.resolver ||
		msg.value.BaseDeclarationRevision != 0 ||
		msg.value.EffectiveNodeCount <= 0 ||
		!validRouteToggleDigest(msg.value.CandidateSHA256) ||
		!validRouteToggleDigest(msg.value.RuntimeOverlaySHA256) ||
		msg.value.RoutingMode != initialRoutingMode || msg.value.CNRulesReady ||
		msg.value.CoreValidated || msg.value.Applied {
		m.initial.discard()
		m.initial.notice = "First-run preview invalid, unavailable or stale. Reload; no write sent."
		return
	}
	receipt := msg.value
	m.initial.pending = &receipt
	m.initial.notice = ""
}

func (m *Model) confirmInitialStage() tea.Cmd {
	if !m.initialContextStillValid() || m.initial.pending == nil ||
		m.initial.previewing || m.initial.writing {
		m.initial.discard()
		m.initial.notice = "First-run state changed; reload before staging. No write sent."
		return nil
	}
	preview := *m.initial.pending
	if preview.ProfileID != m.initial.profileID ||
		preview.SnapshotID != m.initial.snapshotID ||
		preview.SourceRevision != m.initial.sourceRevision ||
		preview.SelectedNodeID != m.initial.nodeID ||
		preview.ResolverAddress != m.initial.resolver ||
		!validRouteToggleDigest(preview.CandidateSHA256) ||
		!validRouteToggleDigest(preview.RuntimeOverlaySHA256) ||
		preview.RoutingMode != initialRoutingMode || preview.CNRulesReady ||
		preview.Applied || preview.CoreValidated {
		m.initial.discard()
		m.initial.notice = "First-run confirmation receipt invalid; no write sent."
		return nil
	}
	request := apiv1.InitialProfileDeclarationStageRequest{
		SnapshotID:               m.initial.snapshotID,
		ExpectedSourceRevision:   m.initial.sourceRevision,
		SelectedNodeID:           m.initial.nodeID,
		ResolverAddress:          m.initial.resolver,
		CandidateSHA256:          preview.CandidateSHA256,
		RuntimeOverlaySHA256:     preview.RuntimeOverlaySHA256,
		AcknowledgeProxyOnlyNoCN: true,
	}
	m.initial.pending = nil
	m.initial.sequence++
	m.initial.writing = true
	m.initial.notice = "Sending one guarded stage; if disconnected inspect declaration, never retry blindly."
	return writeInitialProfileStage(m.ctx, m.api.(initialProfileAPI),
		m.initial.sequence, m.initial.profileID, request)
}

func writeInitialProfileStage(
	ctx context.Context, api initialProfileAPI, seq uint64, id string,
	request apiv1.InitialProfileDeclarationStageRequest,
) tea.Cmd {
	return func() tea.Msg {
		msg := initialProfileStageLoaded{sequence: seq}
		if api == nil {
			return msg
		}
		// Once dispatched, do not cancel due only to a TUI window closing.
		bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 40*time.Second)
		defer cancel()
		response, err := api.StageInitialProfileDeclaration(bounded, id, request)
		msg.ok = err == nil &&
			response.ProfileID == id && response.SnapshotID == request.SnapshotID &&
			response.SourceRevision == request.ExpectedSourceRevision &&
			response.DeclarationRevision == 1 &&
			response.DeclarationSHA256 == request.CandidateSHA256 &&
			response.RoutingMode == initialRoutingMode &&
			!response.CNRulesReady && !response.CoreValidated && !response.Applied
		return msg
	}
}

func (m *Model) acceptInitialStage(msg initialProfileStageLoaded) tea.Cmd {
	if !m.initial.writing || msg.sequence != m.initial.sequence {
		return nil
	}
	m.initial.writing = false
	m.initial.discard()
	if msg.ok {
		m.initial.awaitingReadback = true
		m.initial.notice = "Stage response received; verifying durable declaration status before reporting success."
	} else {
		m.initial.notice = "Stage failed/uncertain. Inspect current declaration and recovery; NEVER auto-retry."
	}
	m.statusRequest++
	m.statusReady, m.statusError = false, false
	return loadStatus(m.ctx, m.api, m.statusRequest)
}

func (m Model) initialProfileLines() []string {
	if !m.initial.active() {
		return nil
	}
	header := []string{
		"FIRST-RUN DECLARATION -- PROXY ONLY; CN 28-GROUP RULES NOT PRESENT",
		"Current core/applied generation is NOT modified by preview or stage.",
		fmt.Sprintf("Profile: %s  snapshot: %d  source rev: %d",
			m.initial.profileID, m.initial.snapshotID, m.initial.sourceRevision),
		"Selected stable node: " + m.initial.nodeID,
	}
	switch {
	case m.initial.writing:
		return append(header,
			"Sending ONE confirmed CAS stage to daemon...",
			"Disconnects can be uncertain; inspect status and NEVER automatically retry.")
	case m.initial.pending != nil:
		p := m.initial.pending
		return append(header,
			"Explicit DNS IP:port: "+m.initial.resolver,
			fmt.Sprintf("Effective imported nodes: %d", p.EffectiveNodeCount),
			"Runtime overlay SHA256: "+p.RuntimeOverlaySHA256[:20]+"...",
			"Candidate declaration SHA256: "+p.CandidateSHA256[:20]+"...",
			"User acknowledgement: proxy-only; CN not available; Core NOT applied.",
			"y: CONFIRM stage rev 1  Esc: discard without changing daemon")
	case m.initial.previewing:
		return append(header,
			"Fetching read-only source-to-declaration preview...",
			"No Core check, declaration write or apply is performed.")
	default:
		return append(header,
			"Enter a reachable resolver as an IP:port; no default is guessed.",
			"DNS IP:port: "+m.initial.resolver+"_",
			"Enter: preview candidate  Backspace: edit  Ctrl+U: clear  Esc: cancel")
	}
}
