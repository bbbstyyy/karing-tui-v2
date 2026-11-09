package tui

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
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
	kind   profile.SourceLocationKind
}

type localSourceState struct {
	sequence          uint64
	editing           bool
	pathStep          bool
	pending           *localSourceProposal
	writing           bool
	awaitingReadback  bool
	putVerified       bool
	sourceFingerprint [32]byte
	id                string
	path              string
	formatIndex       int
	kind              profile.SourceLocationKind
	createdID         string
	notice            string
}

type localSourceSaved struct {
	sequence          uint64
	id                string
	verified          bool
	sourceFingerprint [32]byte
}

func (s *localSourceState) discard() {
	s.sequence++
	s.editing, s.pathStep = false, false
	s.pending = nil
	s.id, s.path, s.createdID = "", "", ""
	s.sourceFingerprint = [32]byte{}
	s.putVerified = false
	s.formatIndex = 0
	s.kind = ""
	s.notice = ""
	// A previously accepted write cannot be undone on TUI cancellation.
}

func (m *Model) beginLocalSource() {
	m.beginNewSource(profile.SourceLocationFile)
}

func (m *Model) beginRemoteSource() {
	m.beginNewSource(profile.SourceLocationURL)
}

// Remote subscriptions default to explicit direct fetch with no background
// schedule. Their URL (including query tokens) is private input; creation
// only registers a source and never fetches it or applies Core.
func (m *Model) beginNewSource(kind profile.SourceLocationKind) {
	if kind != profile.SourceLocationFile && kind != profile.SourceLocationURL {
		return
	}
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
		m.localSource.notice = "Source create requires a complete list, local daemon and terminal >=68x16."
		return
	}
	m.localSource.discard()
	m.profileRefresh.notice = ""
	m.localSource.editing = true
	m.localSource.kind = kind
	if kind == profile.SourceLocationURL {
		m.localSource.notice = "Choose a new ID, then enter a private HTTPS subscription URL."
	} else {
		m.localSource.notice = "Choose a new ID, then enter an absolute file path (never echoed)."
	}
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
		LocationKind: proposal.kind,
		Location:     proposal.path,
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	}
	if err := source.Validate(); err != nil {
		return apiv1.ProfileSourcePutRequest{}, false
	}
	switch proposal.kind {
	case profile.SourceLocationFile:
		if !filepath.IsAbs(proposal.path) || strings.Contains(proposal.path, "\x00") {
			return apiv1.ProfileSourcePutRequest{}, false
		}
	case profile.SourceLocationURL:
		parsed, err := url.Parse(proposal.path)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
			parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
			return apiv1.ProfileSourcePutRequest{}, false
		}
	default:
		return apiv1.ProfileSourcePutRequest{}, false
	}
	return apiv1.ProfileSourcePutRequest{
		ExpectedRevision: 0,
		Source: apiv1.ProfileSourceSpec{
			Format:                proposal.format,
			LocationKind:          string(proposal.kind),
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
		s.notice = "Source creation cancelled; no write sent."
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
			if s.kind == profile.SourceLocationURL {
				s.notice = "Enter a complete HTTPS subscription URL. It will remain hidden."
			} else {
				s.notice = "Enter the absolute file path on the DAEMON host. Path is hidden."
			}
			return nil
		}
		candidate := localSourceProposal{
			id: s.id, path: s.path, format: localSourceFormats[s.formatIndex], kind: s.kind,
		}
		if _, ok := localSourceRequest(candidate); !ok ||
			!m.profilesReady || m.profilesTruncated ||
			m.localSourceIDExists(candidate.id) {
			s.notice = "Invalid/unsafe source location or stale list. Inspect privately, then retry."
			return nil
		}
		s.pending = &candidate
		s.editing = false
		s.id, s.path = "", ""
		s.notice = "Review source type, format and hidden location length before confirming."
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
				s.notice = "Source location exceeds private input limit."
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
		if message.verified {
			// Keep an immutable commitment to the complete source; the private
			// URL/path itself must not survive into TUI state after the write.
			message.sourceFingerprint, err = localSourceFingerprint(request.Source)
			message.verified = err == nil
		}
		return message
	}
}

func validLocalSourceResponse(raw apiv1.ProfileSourceResponse, proposal localSourceProposal, request apiv1.ProfileSourcePutRequest) bool {
	if raw.ProfileID != proposal.id || raw.Revision != 1 {
		return false
	}
	// Compare the complete source, not only the displayed format or ID.
	// In particular, refuse daemon responses which change the source location,
	// fetch route, update interval, or enabled status.
	return raw.Source == request.Source
}

// The source spec consists of bounded strings, enums and integers only.
// JSON's deterministic encoding of this concrete struct gives a safe
// fingerprint without storing, showing or logging URL query credentials.
func localSourceFingerprint(source apiv1.ProfileSourceSpec) ([32]byte, error) {
	encoded, err := json.Marshal(source)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func (m *Model) acceptLocalSourceSaved(msg localSourceSaved) tea.Cmd {
	s := &m.localSource
	if !s.writing || msg.sequence != s.sequence || msg.id != s.createdID {
		return nil
	}
	s.writing = false
	s.putVerified = msg.verified
	s.sourceFingerprint = msg.sourceFingerprint
	s.awaitingReadback = true
	if msg.verified {
		s.notice = "Source PUT and detail readback matched; checking full profile inventory."
	} else {
		s.notice = "Source creation uncertain/rejected; inspect before retry. No Core change."
	}
	m.profilesRequest++
	m.profilesReady, m.profilesError = false, false
	return loadProfiles(m.ctx, m.api, m.profilesRequest)
}

// Compare the complete source in the independent list readback against the
// private commitment from the already verified PUT+GET. A matching ID and
// revision alone cannot prove that the daemon retained the same location,
// format, fetch route, filter or update interval. Reject any concurrent or
// forged refresh snapshot rather than claiming source-only registration.
func (m *Model) acceptLocalSourceListReadback(raw []apiv1.ProfileSourceResponse) {
	s := &m.localSource
	if !s.awaitingReadback {
		return
	}
	s.awaitingReadback = false
	defer func() {
		s.createdID = ""
		s.putVerified = false
		s.sourceFingerprint = [32]byte{}
	}()
	if !s.putVerified || !m.profilesReady || m.profilesError || m.profilesTruncated {
		s.notice = "Source create/readback uncertain; inspect source before retry. No Core apply."
		return
	}
	matches := 0
	fullMatch := false
	for _, p := range raw {
		if p.ProfileID != s.createdID {
			continue
		}
		matches++
		digest, err := localSourceFingerprint(p.Source)
		if err == nil && digest == s.sourceFingerprint &&
			p.Revision == 1 && p.CurrentSnapshotID == nil &&
			p.LastSuccessAt == "" && p.ActiveUpdateID == "" {
			fullMatch = true
		}
	}
	selectedIndex := -1
	for i, p := range m.profiles {
		if p.ProfileID == s.createdID && p.Revision == 1 &&
			p.Enabled && p.CurrentSnapshotID == nil {
			selectedIndex = i
		}
	}
	if matches != 1 || !fullMatch || selectedIndex < 0 {
		s.notice = "Source list mismatched; inspect before retry. No Core apply."
		return
	}
	m.selected = selectedIndex
	s.notice = fmt.Sprintf("Created %s at rev 1. Press u to refresh; later stage/apply separately.", s.createdID)
}

func (m Model) localSourceLines() []string {
	s := m.localSource
	kindName := "local FILE"
	locationLabel := "File path"
	headline := "File must exist on daemon host and be readable by daemon UID."
	if s.kind == profile.SourceLocationURL {
		kindName = "remote HTTPS"
		locationLabel = "HTTPS URL"
		headline = "HTTPS only; credentials in query remain in private daemon state."
	}
	result := []string{
		"New " + kindName + " source (private input; no automatic Core changes)",
		"Source is only registered; press u later to explicitly refresh/import.",
		headline,
	}
	if s.pending != nil {
		return append(result,
			fmt.Sprintf("ID: %s  format: %s", s.pending.id, s.pending.format),
			fmt.Sprintf("%s: [private, %d bytes; never echoed]", locationLabel, len(s.pending.path)),
			"CONFIRM source creation at ExpectedRevision=0?",
			"No nodes imported or applied on this screen. y: confirm / Esc: cancel",
		)
	}
	if s.pathStep {
		return append(result,
			"ID: "+s.id,
			"Format (Tab cycles): "+localSourceFormats[s.formatIndex],
			fmt.Sprintf("%s: [private, %d bytes entered]", locationLabel, len(s.path)),
			"Enter validates this location and opens confirmation.",
		)
	}
	return append(result,
		"Enter a unique ID: "+s.id,
		"Allowed: ASCII letters/digits, then letters/digits/._- (up to 64).",
		"Enter: next (source location is never shown).",
	)
}
