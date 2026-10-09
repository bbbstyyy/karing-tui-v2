package tui

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

const (
	nodePageSize     = 20
	maxProfilesShown = 200
	maxNodeOffset    = 10000
)

type API interface {
	Status(context.Context) (apiv1.StatusResponse, error)
	ProfileSources(context.Context) (apiv1.ProfileSourceListResponse, error)
	ProfileNodes(context.Context, string, int, int) (apiv1.ProfileNodeListResponse, error)
	PutProfileNodeOverlay(context.Context, string, string, apiv1.ProfileNodeOverlayPutRequest) (apiv1.ProfileNodeOverlayResponse, error)
	RouteExplain(context.Context, apiv1.RouteExplainRequest) (apiv1.RouteExplainResponse, error)
	CurrentSelection(context.Context) (apiv1.CurrentSelectionResponse, error)
	SetCurrentSelectionChecked(context.Context, apiv1.CurrentSelectionCheckedRequest) (apiv1.CurrentSelectionResponse, error)
	ObservedConnections(context.Context) (apiv1.ObservedConnectionsResponse, error)
	InspectConfig(context.Context) (apiv1.ConfigInspectionResponse, error)
}

type page uint8

const (
	dashboardPage page = iota
	profilesPage
	nodesPage
	routePage
	selectionPage
	connectionsPage
	routingInspectPage
	dnsInspectPage
)

// profileView contains only fields explicitly safe for a terminal to retain.
type profileView struct {
	ProfileID           string
	Format              string
	Enabled             bool
	Revision            uint64
	CurrentSnapshotID   *int64
	ConsecutiveFailures uint32
}

type Model struct {
	ctx    context.Context
	api    API
	page   page
	width  int
	height int

	status        apiv1.StatusResponse
	statusReady   bool
	statusError   bool
	statusRequest uint64
	hasCoreError  bool

	profiles          []profileView
	profilesReady     bool
	profilesError     bool
	profilesTruncated bool
	profilesRequest   uint64
	selected          int

	nodes          apiv1.ProfileNodeListResponse
	nodesReady     bool
	nodesError     bool
	nodesProfile   string
	nodesOffset    int
	nodesScroll    int
	nodesRequest   uint64
	nodesRestoreID string

	overlayConfirm  *overlayProposal
	overlayInFlight bool
	overlayRequest  uint64
	overlayProfile  string
	overlayNodeID   string
	overlayNotice   string

	route       routeProbeState
	selection   selectionObservation
	connections connectionsObservation
	inspection  configInspectionState

	quitting bool
}

type statusLoaded struct {
	request uint64
	value   apiv1.StatusResponse
	err     error
}

type profilesLoaded struct {
	request uint64
	value   apiv1.ProfileSourceListResponse
	err     error
}

type nodesLoaded struct {
	request   uint64
	profileID string
	offset    int
	value     apiv1.ProfileNodeListResponse
	err       error
}

func NewModel(ctx context.Context, api API) Model {
	if ctx == nil {
		ctx = context.Background()
	}
	return Model{
		ctx: ctx, api: api,
		page: dashboardPage, width: 80, height: 24,
		statusRequest: 1, profilesRequest: 1,
		route: routeProbeState{entry: "rule"},
	}
}

func loadStatus(ctx context.Context, api API, request uint64) tea.Cmd {
	return func() tea.Msg {
		if api == nil {
			return statusLoaded{request: request, err: fmt.Errorf("missing TUI client")}
		}
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		value, err := api.Status(bounded)
		return statusLoaded{request: request, value: value, err: err}
	}
}

func loadProfiles(ctx context.Context, api API, request uint64) tea.Cmd {
	return func() tea.Msg {
		if api == nil {
			return profilesLoaded{request: request, err: fmt.Errorf("missing TUI client")}
		}
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		value, err := api.ProfileSources(bounded)
		return profilesLoaded{request: request, value: value, err: err}
	}
}

func loadNodes(ctx context.Context, api API, request uint64, profileID string, offset int) tea.Cmd {
	return func() tea.Msg {
		if api == nil {
			return nodesLoaded{request: request, profileID: profileID, offset: offset, err: fmt.Errorf("missing TUI client")}
		}
		bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		value, err := api.ProfileNodes(bounded, profileID, offset, nodePageSize)
		return nodesLoaded{request: request, profileID: profileID, offset: offset, value: value, err: err}
	}
}

// Init and Update never perform I/O. All daemon calls execute in bounded tea.Cmds.
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		loadStatus(m.ctx, m.api, m.statusRequest),
		loadProfiles(m.ctx, m.api, m.profilesRequest),
	)
}

func (m Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case statusLoaded:
		if msg.request != m.statusRequest {
			return m, nil
		}
		m.statusReady = msg.err == nil
		m.statusError = msg.err != nil
		if m.statusReady {
			m.hasCoreError = msg.value.CoreLastError != ""
			msg.value.CoreLastError = "" // The raw error can contain credentials.
			m.status = msg.value
		}
		return m, nil
	case profilesLoaded:
		if msg.request != m.profilesRequest {
			return m, nil
		}
		if msg.err != nil {
			m.profilesError = true
			m.profilesReady = false
			return m, nil
		}
		oldID := m.selectedProfileID()
		items := msg.value.Profiles
		m.profilesTruncated = len(items) > maxProfilesShown
		if len(items) > maxProfilesShown {
			items = items[:maxProfilesShown]
		}
		m.profiles = make([]profileView, 0, len(items))
		for _, item := range items {
			var snapshot *int64
			if item.CurrentSnapshotID != nil {
				id := *item.CurrentSnapshotID
				snapshot = &id
			}
			m.profiles = append(m.profiles, profileView{
				ProfileID: item.ProfileID, Format: string(item.Source.Format),
				Enabled: item.Source.Enabled, Revision: item.Revision,
				CurrentSnapshotID: snapshot, ConsecutiveFailures: item.ConsecutiveFailures,
			})
		}
		m.profilesReady, m.profilesError = true, false
		m.selected = 0
		for i, item := range m.profiles {
			if item.ProfileID == oldID {
				m.selected = i
				break
			}
		}
		if m.page == nodesPage && m.nodesProfile != m.selectedProfileID() {
			return m, m.requestNodes(0)
		}
		return m, nil
	case nodesLoaded:
		if msg.request != m.nodesRequest || msg.profileID != m.selectedProfileID() ||
			msg.profileID != m.nodesProfile || msg.offset != m.nodesOffset {
			return m, nil
		}
		if msg.err != nil || msg.value.ProfileID != msg.profileID ||
			msg.value.Offset != msg.offset || msg.value.Total < 0 ||
			msg.value.Limit != nodePageSize || len(msg.value.Nodes) > nodePageSize {
			m.nodesReady, m.nodesError = false, true
			return m, nil
		}
		m.nodes = msg.value
		m.nodesReady, m.nodesError = true, false
		if m.nodesRestoreID != "" {
			for i, node := range m.nodes.Nodes {
				if node.NodeID == m.nodesRestoreID {
					m.nodesScroll = i
					break
				}
			}
			m.nodesRestoreID = ""
		}
		return m, nil
	case overlaySaved:
		if !m.overlayInFlight || msg.request != m.overlayRequest ||
			msg.profileID != m.overlayProfile || msg.nodeID != m.overlayNodeID {
			return m, nil
		}
		m.overlayInFlight = false
		m.overlayProfile, m.overlayNodeID = "", ""
		if msg.err != nil {
			// The request may have reached the daemon. Never assume rollback.
			m.overlayNotice = "Overlay result uncertain; inspect reloaded node state before retrying."
		} else {
			m.overlayNotice = "Overlay saved in daemon; declaration and running core unchanged."
		}
		cmd := m.requestNodes(m.nodesOffset)
		m.nodesRestoreID = msg.nodeID
		return m, cmd
	case routeProbeLoaded:
		m.acceptRouteProbe(msg)
		return m, nil
	case selectionObservationLoaded:
		m.acceptSelectionObservation(msg)
		return m, nil
	case selectionWriteLoaded:
		return m, m.acceptSelectionWrite(msg)
	case connectionsObservationLoaded:
		m.acceptConnectionsObservation(msg)
		return m, nil
	case configInspectionLoaded:
		m.acceptConfigInspection(msg)
		return m, nil
	case tea.KeyMsg:
		if m.selection.writing && msg.String() != "q" && msg.String() != "ctrl+c" {
			return m, nil
		}
		if m.selection.pending != nil {
			switch msg.String() {
			case "y":
				return m, m.confirmSelection()
			case "esc":
				m.selection.pending = nil
				m.selection.notice = "Selection proposal cancelled; no write sent."
				return m, nil
			case "q", "ctrl+c":
				// Quitting cancels an unconfirmed proposal.
			default:
				return m, nil
			}
		}
		if m.page == routePage && m.route.editing {
			return m.updateRouteProbeEditing(msg)
		}
		if m.overlayInFlight && msg.String() != "q" && msg.String() != "ctrl+c" {
			return m, nil
		}
		if m.overlayConfirm != nil {
			switch msg.String() {
			case "y":
				proposal := *m.overlayConfirm
				m.overlayConfirm = nil
				m.overlayRequest++
				m.overlayInFlight = true
				m.overlayProfile, m.overlayNodeID = proposal.profileID, proposal.nodeID
				m.overlayNotice = ""
				return m, writeOverlay(m.ctx, m.api, m.overlayRequest, proposal)
			case "esc":
				m.overlayConfirm = nil
				m.overlayNotice = "Overlay change cancelled; no write was sent."
				return m, nil
			case "q", "ctrl+c":
				// Quitting does not send a write.
			default:
				return m, nil
			}
		}
		switch msg.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "r":
			switch m.page {
			case routePage:
				return m, m.startRouteProbe()
			case selectionPage:
				return m, m.requestSelectionObservation()
			case connectionsPage:
				return m, m.requestConnectionsObservation()
			case routingInspectPage, dnsInspectPage:
				return m, m.requestConfigInspection()
			}
			m.statusRequest++
			m.profilesRequest++
			m.statusReady, m.profilesReady = false, false
			m.statusError, m.profilesError = false, false
			commands := []tea.Cmd{
				loadStatus(m.ctx, m.api, m.statusRequest),
				loadProfiles(m.ctx, m.api, m.profilesRequest),
			}
			if m.page == nodesPage {
				commands = append(commands, m.requestNodes(m.nodesOffset))
			}
			return m, tea.Batch(commands...)
		case "tab":
			return m, m.switchPage(page((int(m.page) + 1) % 8))
		case "1":
			return m, m.switchPage(dashboardPage)
		case "2":
			return m, m.switchPage(profilesPage)
		case "3":
			return m, m.switchPage(nodesPage)
		case "4":
			return m, m.switchPage(routePage)
		case "5":
			return m, m.switchPage(selectionPage)
		case "6":
			return m, m.switchPage(connectionsPage)
		case "7":
			return m, m.switchPage(routingInspectPage)
		case "8":
			return m, m.switchPage(dnsInspectPage)
		case "e":
			if m.page == routePage {
				m.beginRouteProbeEditing()
			}
		case "t":
			if m.page == routePage {
				m.cycleRouteProbeEntry()
			}
		case "esc":
			if m.page == nodesPage {
				return m, m.switchPage(profilesPage)
			}
		case "up", "k":
			if (m.page == routingInspectPage || m.page == dnsInspectPage) && m.inspection.scroll > 0 {
				m.inspection.scroll--
			} else if m.page == selectionPage && m.selection.ready && m.selection.selected > 0 {
				m.selection.selected--
			} else if m.page == connectionsPage && m.connections.scroll > 0 {
				m.connections.scroll--
			} else if m.page == routePage && m.route.scroll > 0 {
				m.route.scroll--
			} else if m.page == profilesPage && m.selected > 0 {
				m.selected--
			} else if m.page == nodesPage && m.nodesScroll > 0 {
				m.nodesScroll--
			}
		case "down", "j":
			if (m.page == routingInspectPage || m.page == dnsInspectPage) &&
				m.inspection.scroll+1 < len(m.configInspectionLines()) {
				m.inspection.scroll++
			} else if m.page == selectionPage && m.selection.ready && m.selection.selected+1 < len(m.selection.result.candidates) {
				m.selection.selected++
			} else if m.page == connectionsPage && m.connections.scroll+1 < len(m.connectionsObservationLines()) {
				m.connections.scroll++
			} else if m.page == routePage && m.route.scroll+1 < len(m.routeProbeLines()) {
				m.route.scroll++
			} else if m.page == profilesPage && m.selected+1 < len(m.profiles) {
				m.selected++
			} else if m.page == nodesPage && m.nodesReady && m.nodesScroll+1 < len(m.nodes.Nodes) {
				m.nodesScroll++
			}
		case "enter":
			if m.page == selectionPage {
				m.proposeSelection()
			} else if m.page == profilesPage && m.selectedProfileID() != "" {
				return m, m.switchPage(nodesPage)
			}
		case "f":
			m.proposeOverlay(true)
		case "d":
			m.proposeOverlay(false)
		case "n":
			if m.page == nodesPage && m.nodesReady && m.nodesOffset+nodePageSize < m.nodes.Total &&
				m.nodesOffset+nodePageSize <= maxNodeOffset {
				return m, m.requestNodes(m.nodesOffset + nodePageSize)
			}
		case "p":
			if m.page == nodesPage && m.nodesOffset > 0 {
				previous := m.nodesOffset - nodePageSize
				if previous < 0 {
					previous = 0
				}
				return m, m.requestNodes(previous)
			}
		}
	}
	return m, nil
}

func (m *Model) selectedProfileID() string {
	if m.selected >= 0 && m.selected < len(m.profiles) {
		return m.profiles[m.selected].ProfileID
	}
	return ""
}

func (m *Model) switchPage(to page) tea.Cmd {
	m.overlayConfirm = nil
	m.overlayNotice = ""
	if m.page != to {
		if (m.page == routingInspectPage || m.page == dnsInspectPage) &&
			to != routingInspectPage && to != dnsInspectPage {
			m.inspection.discardAndForget()
		}
		if m.page == selectionPage {
			m.selection.discardAndForget()
		}
		if m.page == connectionsPage {
			m.connections.discardAndForget()
		}
	}
	if m.page == routePage || to == routePage {
		m.route.discard = true
		m.route.editing = false
		m.route.ready = false
		m.route.failed = false
		m.route.invalid = false
		m.route.scroll = 0
	}
	m.page = to
	if to == routingInspectPage || to == dnsInspectPage {
		m.inspection.scroll = 0
		if m.inspection.ready || m.inspection.active {
			return nil
		}
		return m.requestConfigInspection()
	}
	switch to {
	case selectionPage:
		return m.requestSelectionObservation()
	case connectionsPage:
		return m.requestConnectionsObservation()
	}
	if to == nodesPage && m.selectedProfileID() != "" &&
		(m.nodesProfile != m.selectedProfileID() || !m.nodesReady) {
		return m.requestNodes(0)
	}
	return nil
}

func (m *Model) requestNodes(offset int) tea.Cmd {
	m.nodesRequest++
	m.nodesReady, m.nodesError = false, false
	m.nodes = apiv1.ProfileNodeListResponse{}
	m.nodesRestoreID = ""
	m.overlayConfirm = nil
	m.nodesProfile = m.selectedProfileID()
	m.nodesOffset = offset
	m.nodesScroll = 0
	if m.nodesProfile == "" {
		return nil
	}
	return loadNodes(m.ctx, m.api, m.nodesRequest, m.nodesProfile, offset)
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}
	width, height := m.width, m.height
	if width < 32 || height < 7 {
		return safeText("too small: resize to 32x7; q quits", max(1, width)) + "\n"
	}
	body := m.pageLines()
	limit := height - 5
	if limit < 0 {
		limit = 0
	}
	if len(body) > limit {
		switch m.page {
		case profilesPage:
			headings := 1
			if m.profilesTruncated {
				headings = 2
			}
			if m.profilesReady && headings < limit && len(body) > headings {
				visible := limit - headings
				start := max(0, m.selected-visible/2)
				start = min(start, max(0, len(body)-headings-visible))
				sliced := append([]string(nil), body[:headings]...)
				body = append(sliced, body[headings+start:min(len(body), headings+start+visible)]...)
			} else {
				body = body[:limit]
			}
		case nodesPage:
			if m.nodesReady && limit > 1 && len(body) > 1 {
				start := min(m.nodesScroll, len(body)-2)
				body = append([]string{body[0]}, body[1+start:min(len(body), 1+start+limit-1)]...)
			} else {
				body = body[:limit]
			}
		case routePage:
			start := min(m.route.scroll, len(body)-limit)
			body = body[start:min(len(body), start+limit)]
		case selectionPage:
			start := 0
			if m.selection.ready && len(m.selection.result.candidates) > 0 {
				// Eight fixed summary lines precede the candidate list.
				selectedLine := 8 + m.selection.selected
				start = max(0, selectedLine-limit+1)
				start = min(start, len(body)-limit)
			}
			body = body[start:min(len(body), start+limit)]
		case connectionsPage:
			start := min(m.connections.scroll, len(body)-limit)
			body = body[start:min(len(body), start+limit)]
		case routingInspectPage, dnsInspectPage:
			start := min(m.inspection.scroll, len(body)-limit)
			body = body[start:min(len(body), start+limit)]
		default:
			body = body[:limit]
		}
	}
	lines := []string{
		"karing-tui v2 | TUI client | daemon/core run independently",
		"[1] Status  [2] Profiles  [3] Nodes  [4] Probe  [5] Select  [6] Conn  [7] Routing  [8] DNS",
		"",
	}
	for _, line := range body {
		lines = append(lines, safeText(line, width))
	}
	lines = append(lines, "")
	help := "Tab: page  j/k: select  n/p: page  f: favorite  d: disable  r: reload  q: quit"
	if m.overlayConfirm != nil {
		help = "y: CONFIRM " + m.overlayConfirm.action + "  Esc: cancel  (daemon only; no core apply)"
	} else if m.page == selectionPage {
		help = "j/k: choose  Enter: propose  r: reload  Tab: page  q: quit"
		if m.selection.pending != nil {
			help = "y: CONFIRM checked selection write  Esc: cancel  q: exit without write"
		} else if m.selection.writing {
			help = "Saving selection: q exits TUI; daemon-accepted writes may finish."
		} else if m.selection.active {
			help = "Reading selection; q exits TUI (no writes by read)."
		} else if m.selection.failed || !m.selection.result.editable {
			help = "Selection unavailable/read-only; r: reload  Tab: page  q: quit"
		}
	} else if m.page == connectionsPage {
		help = "Snapshot only (no polling); r: reload  j/k: scroll  Tab: page  q: quit"
	} else if m.page == routingInspectPage || m.page == dnsInspectPage {
		help = "Read-only bound declaration; j/k: scroll  r: reload  Tab: page  q: quit"
	} else if m.page == routePage {
		help = "e: edit address  t: entry  r: simulate  j/k: scroll  Tab: page  q: quit"
		if m.route.editing {
			help = "Enter: simulate  Esc: cancel edit  Ctrl+U: clear  Ctrl+C: quit"
		} else if m.route.active {
			help = "Simulation request in progress; exit TUI with q if needed."
		}
	} else if m.overlayInFlight {
		help = "Saving node overlay; q exits TUI but a daemon-accepted write may finish."
	} else if m.overlayNotice != "" {
		help = m.overlayNotice
	}
	lines = append(lines, help)
	for i, line := range lines {
		lines[i] = safeText(line, width)
	}
	return strings.Join(lines, "\n") + "\n"
}

func (m Model) pageLines() []string {
	switch m.page {
	case routePage:
		return m.routeProbeLines()
	case selectionPage:
		return m.selectionObservationLines()
	case connectionsPage:
		return m.connectionsObservationLines()
	case routingInspectPage, dnsInspectPage:
		return m.configInspectionLines()
	case dashboardPage:
		if !m.statusReady {
			if m.statusError {
				return []string{"Dashboard: daemon status unavailable.", "Press r to retry. No configuration or core state was changed."}
			}
			return []string{"Dashboard: loading local daemon status..."}
		}
		s := m.status
		result := []string{
			"Dashboard (observed daemon state)",
			fmt.Sprintf("API: %s  daemon: %s  uptime: %ds", s.APIVersion, s.DaemonVersion, s.UptimeSeconds),
			fmt.Sprintf("Core: %s  configured: %t  desired: %s", s.CoreState, s.CoreConfigured, s.CoreDesiredState),
			fmt.Sprintf("Core PID: %d  failure count: %d  circuit open: %t", s.CorePID, s.CoreConsecutiveFailures, s.CoreCircuitOpen),
			fmt.Sprintf("Config revision: %d  declaration revision: %d", s.ConfigRevision, s.DeclarationRevision),
			fmt.Sprintf("Applied generation: %s  last known good: %s", generationLabel(s.AppliedGenerationID), generationLabel(s.LastKnownGoodGenerationID)),
			fmt.Sprintf("Recovery required: %t  routing mode: %s  private direct: %t", s.RecoveryRequired, s.RoutingMode, s.PrivateDirect),
		}
		if s.ActiveOperation != "" {
			result = append(result, "Active operation: "+s.ActiveOperation)
		}
		if m.hasCoreError {
			// Core errors can include upstream URLs and credentials. Never render them.
			result = append(result, "Core reports an error (details suppressed; use controlled diagnostics).")
		}
		return result
	case profilesPage:
		if !m.profilesReady {
			if m.profilesError {
				return []string{"Profiles: local daemon unavailable. Press r to retry."}
			}
			return []string{"Profiles: loading..."}
		}
		result := []string{fmt.Sprintf("Profiles (%d shown; read-only)", len(m.profiles))}
		if len(m.profiles) == 0 {
			return append(result, "No configured profiles.")
		}
		if m.profilesTruncated {
			result = append(result, "List capped at 200 entries; use CLI for full listing.")
		}
		for i, item := range m.profiles {
			prefix := "  "
			if m.selected == i {
				prefix = "> "
			}
			snapshot := generationLabel(item.CurrentSnapshotID)
			result = append(result, fmt.Sprintf("%s%s  [%s] enabled=%t rev=%d snapshot=%s failures=%d",
				prefix, item.ProfileID, item.Format, item.Enabled,
				item.Revision, snapshot, item.ConsecutiveFailures))
		}
		return result
	case nodesPage:
		id := m.selectedProfileID()
		if id == "" {
			return []string{"Nodes: select a profile on the Profiles page first."}
		}
		if !m.nodesReady {
			if m.nodesError {
				return []string{"Nodes: page unavailable. Press r to retry, Esc to return."}
			}
			return []string{"Nodes for " + id, "Loading node page..."}
		}
		result := []string{fmt.Sprintf("Nodes for %s  total=%d  offset=%d  snapshot=%s",
			id, m.nodes.Total, m.nodesOffset, generationLabel(m.nodes.SnapshotID))}
		for i, item := range m.nodes.Nodes {
			mark := " "
			if item.Favorite {
				mark = "*"
			}
			cursor := "  "
			if i == m.nodesScroll {
				cursor = "> "
			}
			result = append(result, fmt.Sprintf("%s%s %s [%s] disabled=%t",
				cursor, mark, item.DisplayName, item.NodeID, item.Disabled))
		}
		if len(m.nodes.Nodes) == 0 {
			result = append(result, "No nodes in this page.")
		}
		return result
	}
	return nil
}

func generationLabel(id *int64) string {
	if id == nil {
		return "none"
	}
	return fmt.Sprint(*id)
}

// safeText is applied to EVERY rendered line, including imported profile names.
// Strip C0/C1 controls, ANSI ESC, bidi formatting, and line separators before
// truncation. This is a display boundary; it must not change stored user data.
func safeText(value string, columns int) string {
	if columns <= 0 {
		return ""
	}
	var out strings.Builder
	used := 0
	for _, r := range value {
		if r == '\n' || r == '\r' || r == '\t' {
			r = ' '
		}
		if !unicode.IsPrint(r) || unicode.Is(unicode.Cf, r) ||
			r == 0x2028 || r == 0x2029 || r == 0xFEFF {
			continue
		}
		width := runeColumns(r)
		if used+width > columns {
			if columns > 1 {
				// Truncation itself may not exceed the terminal width.
				if used >= columns {
					break
				}
				out.WriteRune('…')
			}
			break
		}
		out.WriteRune(r)
		used += width
	}
	return out.String()
}

func runeColumns(r rune) int {
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) {
		return 0
	}
	if (r >= 0x1100 && r <= 0x11ff) ||
		(r >= 0x2e80 && r <= 0xa4cf) ||
		(r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe10 && r <= 0xfe6f) ||
		(r >= 0xff01 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1faff) {
		return 2
	}
	return 1
}
