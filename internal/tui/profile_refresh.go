package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

const (
	minProfileRefreshWidth  = 52
	minProfileRefreshHeight = 9
)

type profileRefreshProposal struct {
	profileID string
	revision  uint64
}

// Persist only allowlisted identifiers, CAS revisions, and numeric readback.
// Remote source URLs, HTTP errors, credentials and import diagnostics must
// never be stored in the model or printed to the terminal.
type profileRefreshState struct {
	pending          *profileRefreshProposal
	writing          bool
	awaitingReadback bool
	sequence         uint64
	profileID        string
	revision         uint64
	snapshotID       int64
	nodeCount        int
	notModified      bool
	notice           string
}

type profileRefreshLoaded struct {
	sequence    uint64
	profileID   string
	revision    uint64
	snapshotID  int64
	nodeCount   int
	notModified bool
	failed      bool
}

func (m *Model) proposeProfileRefresh() {
	if m.page != profilesPage || m.profileRefresh.writing ||
		m.profileRefresh.awaitingReadback || !m.profilesReady ||
		m.profilesError || m.profilesTruncated ||
		m.width < minProfileRefreshWidth || m.height < minProfileRefreshHeight ||
		m.selected < 0 || m.selected >= len(m.profiles) {
		m.profileRefresh.notice = "Refresh unavailable: need a complete source list and terminal >=52x9."
		return
	}
	current := m.profiles[m.selected]
	if !current.Enabled || current.Revision == 0 ||
		profile.ValidateProfileID(current.ProfileID) != nil {
		m.profileRefresh.notice = "Refresh unavailable: source is disabled or untrusted."
		return
	}
	switch current.Format {
	case "sing-box", "clash-yaml", "uri-list", "uri-list-base64":
	default:
		m.profileRefresh.notice = "Refresh unavailable: unsupported source format."
		return
	}
	m.profileRefresh.pending = &profileRefreshProposal{
		profileID: current.ProfileID,
		revision:  current.Revision,
	}
	m.profileRefresh.notice = ""
}

func (m *Model) confirmProfileRefresh() tea.Cmd {
	if m.page != profilesPage || m.profileRefresh.pending == nil ||
		m.profileRefresh.writing || m.profileRefresh.awaitingReadback ||
		m.width < minProfileRefreshWidth || m.height < minProfileRefreshHeight {
		return nil
	}
	proposal := *m.profileRefresh.pending
	m.profileRefresh.pending = nil
	m.profileRefresh.writing = true
	m.profileRefresh.sequence++
	m.profileRefresh.profileID = proposal.profileID
	m.profileRefresh.revision = proposal.revision
	m.profileRefresh.notice = ""
	return loadManualProfileRefresh(m.ctx, m.api, m.profileRefresh.sequence, proposal)
}

func loadManualProfileRefresh(
	ctx context.Context, api API, sequence uint64, proposal profileRefreshProposal,
) tea.Cmd {
	return func() tea.Msg {
		result := profileRefreshLoaded{
			sequence: sequence, profileID: proposal.profileID,
			revision: proposal.revision, failed: true,
		}
		if api == nil {
			return result
		}
		// The daemon caps manual GET refresh at 60s. Allow bounded transport
		// overhead but never silently resubmit a possibly committed update.
		bounded, cancel := context.WithTimeout(ctx, 65*time.Second)
		defer cancel()
		raw, err := api.RefreshProfileSource(bounded, proposal.profileID,
			apiv1.ProfileRefreshRequest{ExpectedSourceRevision: proposal.revision})
		if err != nil || bounded.Err() != nil || raw.ProfileID != proposal.profileID ||
			raw.SourceRevision != proposal.revision || raw.CurrentSnapshotID == nil ||
			*raw.CurrentSnapshotID <= 0 || raw.NodeCount <= 0 || raw.NodeCount > 10000 {
			return result
		}
		result.failed = false
		result.snapshotID = *raw.CurrentSnapshotID
		result.nodeCount = raw.NodeCount
		result.notModified = raw.NotModified
		return result
	}
}

func (m *Model) acceptProfileRefresh(msg profileRefreshLoaded) tea.Cmd {
	if !m.profileRefresh.writing || msg.sequence != m.profileRefresh.sequence ||
		msg.profileID != m.profileRefresh.profileID ||
		msg.revision != m.profileRefresh.revision {
		return nil
	}
	m.profileRefresh.writing = false
	m.profileRefresh.pending = nil
	m.profileRefresh.awaitingReadback = !msg.failed
	if msg.failed {
		m.profileRefresh.notice = "Refresh outcome rejected/uncertain; reload source before any retry. Applied/LKG untouched by this UI."
	} else {
		m.profileRefresh.snapshotID = msg.snapshotID
		m.profileRefresh.nodeCount = msg.nodeCount
		m.profileRefresh.notModified = msg.notModified
		m.profileRefresh.notice = "Refresh acknowledged; checking daemon snapshot (not staged/applied)."
	}
	// The next visit to Nodes must read its new snapshot; do not use a
	// possibly stale previously cached list after a source refresh.
	m.nodesReady = false
	m.nodesProfile = ""
	m.nodes = apiv1.ProfileNodeListResponse{}
	m.profilesRequest++
	m.profilesReady, m.profilesError = false, false
	return loadProfiles(m.ctx, m.api, m.profilesRequest)
}

// Called only for the current profilesLoaded request, including failures.
// Treat a successful refresh response as provisional until the daemon's
// updated snapshot is read back. A 409, timeout, or inconsistent reply never
// causes a blind reattempt or an automatic declaration/Core change.
func (m *Model) acceptProfileRefreshReadback() {
	if !m.profileRefresh.awaitingReadback {
		return
	}
	m.profileRefresh.awaitingReadback = false
	if m.profilesError || m.profilesTruncated {
		m.profileRefresh.notice = "Refresh readback unavailable; inspect source state. Do not auto-retry."
		return
	}
	matches := 0
	for _, p := range m.profiles {
		if p.ProfileID == m.profileRefresh.profileID {
			matches++
			if p.Revision != m.profileRefresh.revision ||
				p.CurrentSnapshotID == nil ||
				*p.CurrentSnapshotID != m.profileRefresh.snapshotID {
				m.profileRefresh.notice = "Refresh snapshot mismatch; inspect source state. Do not auto-retry."
				return
			}
		}
	}
	if matches != 1 {
		m.profileRefresh.notice = "Refresh source readback inconsistent; inspect before retry."
		return
	}
	if m.profileRefresh.notModified {
		m.profileRefresh.notice = "Source unchanged; verified retained snapshot. No stage or Core apply."
		return
	}
	m.profileRefresh.notice = fmt.Sprintf(
		"Verified snapshot %d (%d nodes). Staging and Core Apply remain separate.",
		m.profileRefresh.snapshotID, m.profileRefresh.nodeCount,
	)
}
