package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

const (
	minLocalSourceWidth  = 68
	minLocalSourceHeight = 16
	maxLocalSourceID     = 64
	maxLocalSourcePath   = 1024
)

var localSourceFormats = [...]string{
	"sing-box", "clash-yaml", "uri-list", "uri-list-base64",
}

type localSourceProposal struct {
	id     string
	path   string
	format string
}

type localSourceState struct {
	sequence         uint64
	editing          bool
	pathStep         bool
	pending          *localSourceProposal
	writing          bool
	awaitingReadback bool
	putVerified      bool
	id               string
	path             string
	formatIndex      int
	createdID        string
	notice           string
}

type localSourceSaved struct {
	sequence uint64
	id       string
	verified bool
}

func (s *localSourceState) discard() {
	s.sequence++
	s.editing, s.pathStep = false, false
	s.pending = nil
	s.id, s.path, s.createdID = "", "", ""
	s.formatIndex = 0
	s.notice = ""
	// A previously accepted write cannot be undone on TUI cancellation.
}

func (m *Model) beginLocalSource() {
	if m.page != profilesPage || m.localSource.editing ||
		m.localSource.pending != nil || m.localSource.writing ||
		m.localSource.awaitingReadback ||
		m.profileRefresh.pending != nil || m.profileRefresh.writing ||
		m.profileRefresh.awaitingReadback {
		return
	}
	if m.api == nil || !m.profilesReady || m.profilesError ||
		m.profilesTruncated || m.width < minLocalSourceWidth ||
		m.height < minLocalSourceHeight {
		m.localSource.notice = "Local create requires a complete list, local daemon and terminal >=68x16."
		return
	}
	m.localSource.discard()
	m.profileRefresh.notice = ""
	m.localSource.editing = true
	m.localSource.notice = "Choose a new ID, then enter an absolute file path (never echoed)."
}

func localSourceIDValid(id string) bool {
	if id == "" || len(id) > maxLocalSourceID || !utf8.ValidString(id) ||
		profile.ValidateProfileID(id) != nil {
		return false
	}
	for i := 0; i < len(id); i++ {
		b := id[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
			(b >= '0' && b <= '9') {
			continue
		}
		if i > 0 && (b == '-' || b == '_' || b == '.') {
			continue
		}
		return false
	}
	return true
}

func localSourceRequest(proposal localSourceProposal) (apiv1.ProfileSourcePutRequest, bool) {
	if !localSourceIDValid(proposal.id) || proposal.path == "" ||
		len(proposal.path) > maxLocalSourcePath {
		return apiv1.ProfileSourcePutRequest{}, false
	}
	source := profile.SourceSpec{
		ProfileID:    proposal.id,
		Format:       profile.SourceFormat(proposal.format),
		LocationKind: profile.SourceLocationFile,
		Location:     proposal.path,
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	}
	if err := source.Validate(); err != nil || !filepath.IsAbs(proposal.path) ||
		strings.Contains(proposal.path, "\x00") {
		return apiv1.ProfileSourcePutRequest{}, false
	}
	return apiv1.ProfileSourcePutRequest{
		ExpectedRevision: 0,
		Source: apiv1.ProfileSourceSpec{
			Format:                proposal.format,
			LocationKind:          "file",
			Location:              proposal.path,
			Fetch:                 apiv1.ProfileSourceFetchPolicy{Mode: "direct"},
			UpdateIntervalSeconds: 0,
			Enabled:               true,
		},
	}, true
}

func (m *Model) localSourceKey(msg tea.KeyMsg) tea.Cmd {
	if !m.localSource.editing || m.page != profilesPage {
		return nil
	}
	s := &m.localSource
	switch msg.String() {
	case "esc":
		s.discard()
		s.notice = "Local source wizard cancelled; no write sent."
		return nil
	case "backspace":
		if s.pathStep {
			if len(s.path) > 0 {
				_, size := utf8.DecodeLastRuneInString(s.path)
				s.path = s.path[:len(s.path)-size]
			}
		} else if len(s.id) > 0 {
			s.id = s.id[:len(s.id)-1]
		}
		return nil
	case "ctrl+u":
		if s.pathStep {
			s.path = ""
		} else {
			s.id = ""
		}
		return nil
	case "tab":
		if s.pathStep {
			s.formatIndex = (s.formatIndex + 1) % len(localSourceFormats)
		}
		return nil
	case "enter":
		if !s.pathStep {
			if !localSourceIDValid(s.id) || m.localSourceIDExists(s.id) {
				s.notice = "Invalid or existing source ID; use a new 1-64 byte ASCII ID."
				return nil
			}
			s.pathStep = true
			s.notice = "Enter the absolute file path on the DAEMON host. Path is hidden."
			return nil
		}
		candidate := localSourceProposal{
			id: s.id, path: s.path, format: localSourceFormats[s.formatIndex],
		}
		if _, ok := localSourceRequest(candidate); !ok ||
			!m.profilesReady || m.profilesTruncated ||
			m.localSourceIDExists(candidate.id) {
			s.notice = "Invalid/unsafe local path or stale source list. Check path, then retry."
			return nil
		}
		s.pending = &candidate
		s.editing = false
		s.id, s.path = "", ""
		s.notice = "Review format and hidden path length; confirm explicitly to create."
		return nil
	}
	if msg.Type != tea.KeyRunes {
		return nil
	}
	for _, r := range msg.Runes {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == utf8.RuneError {
			s.notice = "Control or invalid input refused."
			return nil
		}
		if s.pathStep {
			if len(s.path)+utf8.RuneLen(r) > maxLocalSourcePath {
				s.notice = "Local source path exceeds private input limit."
				return nil
			}
			s.path += string(r)
		} else {
			if r > 0x7f || len(s.id) >= maxLocalSourceID {
				s.notice = "Source ID must be at most 64 ASCII bytes."
				return nil
			}
			s.id += string(r)
		}
	}
	return nil
}

func (m *Model) localSourceIDExists(id string) bool {
	for _, p := range m.profiles {
		if p.ProfileID == id {
			return true
		}
	}
	return false
}

func (m *Model) confirmLocalSource() tea.Cmd {
	s := &m.localSource
	if s.pending == nil || s.writing || s.awaitingReadback ||
		m.page != profilesPage || m.api == nil ||
		!m.profilesReady || m.profilesError || m.profilesTruncated ||
		m.width < minLocalSourceWidth || m.height < minLocalSourceHeight ||
		m.localSourceIDExists(s.pending.id) {
		return nil
	}
	proposal := *s.pending
	if _, ok := localSourceRequest(proposal); !ok {
		return nil
	}
	s.sequence++
	s.pending = nil
	s.writing = true
	s.id, s.path = "", ""
	s.createdID = proposal.id
	s.notice = "Creating source; no automatic import, stage or Core apply."
	// Ignore an older, possibly in-flight inventory response.
	m.profilesRequest++
	return createLocalSource(m.ctx, m.api, s.sequence, proposal)
}

// One single-shot PUT and one independent GET in bounded commands. Never
// auto-repeat even when an HTTP failure makes the mutation outcome unclear.
func createLocalSource(ctx context.Context, api API, sequence uint64, proposal localSourceProposal) tea.Cmd {
	return func() tea.Msg {
		message := localSourceSaved{sequence: sequence, id: proposal.id}
		request, ok := localSourceRequest(proposal)
		if api == nil || !ok {
			return message
		}
		writeCtx, stopWrite := context.WithTimeout(ctx, 10*time.Second)
		created, err := api.PutProfileSource(writeCtx, proposal.id, request)
		complete := writeCtx.Err() == nil
		stopWrite()
		if err != nil || !complete || !validLocalSourceResponse(created, proposal, request) {
			return message
		}
		readCtx, stopRead := context.WithTimeout(ctx, 3*time.Second)
		readback, err := api.ProfileSource(readCtx, proposal.id)
		complete = readCtx.Err() == nil
		stopRead()
		message.verified = err == nil && complete && validLocalSourceResponse(readback, proposal, request)
		return message
	}
}

func validLocalSourceResponse(raw apiv1.ProfileSourceResponse, proposal localSourceProposal, request apiv1.ProfileSourcePutRequest) bool {
	if raw.ProfileID != proposal.id || raw.Revision != 1 {
		return false
	}
	// Compare the complete source, not only the displayed format or ID.
	// In particular, refuse daemon responses which change the file path,
	// fetch route, update interval, or enabled status.
	return raw.Source == request.Source
}

func (m *Model) acceptLocalSourceSaved(msg localSourceSaved) tea.Cmd {
	s := &m.localSource
	if !s.writing || msg.sequence != s.sequence || msg.id != s.createdID {
		return nil
	}
	s.writing = false
	s.putVerified = msg.verified
	s.awaitingReadback = true
	if msg.verified {
		s.notice = "Source PUT and detail readback matched; checking profile inventory."
	} else {
		s.notice = "Source creation uncertain/rejected; inspect before retry. No Core change."
	}
	m.profilesRequest++
	m.profilesReady, m.profilesError = false, false
	return loadProfiles(m.ctx, m.api, m.profilesRequest)
}

func (m *Model) acceptLocalSourceListReadback() {
	s := &m.localSource
	if !s.awaitingReadback {
		return
	}
	s.awaitingReadback = false
	if !s.putVerified || !m.profilesReady || m.profilesError || m.profilesTruncated {
		s.notice = "Source create/readback uncertain; inspect source before retry. No Core apply."
		s.createdID = ""
		return
	}
	matches := 0
	for i, p := range m.profiles {
		if p.ProfileID == s.createdID {
			matches++
			if p.Revision == 1 && p.Enabled && p.Format != "" {
				m.selected = i
			}
		}
	}
	if matches != 1 || m.selectedProfileID() != s.createdID ||
		m.profiles[m.selected].Revision != 1 ||
		!m.profiles[m.selected].Enabled {
		s.notice = "Source list mismatched; inspect before retry. No Core apply."
	} else {
		s.notice = fmt.Sprintf("Created %s at rev 1. Press u to refresh; later stage/apply separately.", s.createdID)
	}
	s.createdID = ""
	s.putVerified = false
}

func (m Model) localSourceLines() []string {
	s := m.localSource
	result := []string{
		"New local FILE source (no URLs, secrets or automatic Core changes)",
		"Source is only registered; use u afterward to explicitly refresh/import.",
		"File must exist on daemon host and be readable by daemon UID.",
	}
	if s.pending != nil {
		return append(result,
			fmt.Sprintf("ID: %s  format: %s", s.pending.id, s.pending.format),
			fmt.Sprintf("File path: [private, %d bytes; never echoed]", len(s.pending.path)),
			"CONFIRM source creation at ExpectedRevision=0?",
			"No nodes imported or applied on this screen. y: confirm / Esc: cancel",
		)
	}
	if s.pathStep {
		return append(result,
			"ID: "+s.id,
			"Format (Tab cycles): "+localSourceFormats[s.formatIndex],
			fmt.Sprintf("File path: [private, %d bytes entered]", len(s.path)),
			"Enter validates the complete absolute path and opens confirmation.",
		)
	}
	return append(result,
		"Enter a unique ID: "+s.id,
		"Allowed: ASCII letters/digits, then letters/digits/._- (up to 64).",
		"Enter: next (file path is never shown).",
	)
}
