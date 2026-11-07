package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

type fakeAPI struct {
	status           apiv1.StatusResponse
	profiles         []apiv1.ProfileSourceResponse
	nodes            map[string]apiv1.ProfileNodeListResponse
	statusErr        error
	profilesErr      error
	nodesErr         error
	statusCalls      int
	profileCalls     int
	nodeCalls        int
	observedDeadline bool
	overlayCalls     int
	overlayErr       error
	lastOverlay      apiv1.ProfileNodeOverlayPutRequest
}

func (f *fakeAPI) Status(ctx context.Context) (apiv1.StatusResponse, error) {
	f.statusCalls++
	f.checkDeadline(ctx)
	return f.status, f.statusErr
}

func (f *fakeAPI) ProfileSources(ctx context.Context) (apiv1.ProfileSourceListResponse, error) {
	f.profileCalls++
	f.checkDeadline(ctx)
	return apiv1.ProfileSourceListResponse{Profiles: f.profiles}, f.profilesErr
}

func (f *fakeAPI) ProfileNodes(ctx context.Context, id string, offset, limit int) (apiv1.ProfileNodeListResponse, error) {
	f.nodeCalls++
	f.checkDeadline(ctx)
	data, ok := f.nodes[id]
	if !ok {
		return apiv1.ProfileNodeListResponse{}, errors.New("not found")
	}
	data.Offset, data.Limit = offset, limit
	if offset < len(data.Nodes) {
		data.Nodes = data.Nodes[offset:min(len(data.Nodes), offset+limit)]
	} else {
		data.Nodes = nil
	}
	return data, f.nodesErr
}

func (f *fakeAPI) checkDeadline(ctx context.Context) {
	deadline, ok := ctx.Deadline()
	if ok && time.Until(deadline) <= 3*time.Second && time.Until(deadline) > 0 {
		f.observedDeadline = true
	}
}

func updated(t *testing.T, m Model, msg tea.Msg) (Model, tea.Cmd) {
	t.Helper()
	next, cmd := m.Update(msg)
	typed, ok := next.(Model)
	if !ok {
		t.Fatalf("unexpected model type %T", next)
	}
	return typed, cmd
}

func TestReadOnlyDashboardAndQuitNeverMutatesDaemon(t *testing.T) {
	api := &fakeAPI{status: apiv1.StatusResponse{
		APIVersion: "v1", DaemonVersion: "development", CoreState: "running",
		CoreDesiredState: "running", ConfigRevision: 7, DeclarationRevision: 9,
		CoreLastError: "token=SECRET_AND_ANSI\x1b[31m",
	}}
	m := NewModel(context.Background(), api)
	statusMsg, ok := loadStatus(context.Background(), api, 1)().(statusLoaded)
	if !ok {
		t.Fatal("status command did not return its message")
	}
	m, _ = updated(t, m, statusMsg)
	view := m.View()
	for _, expected := range []string{"Dashboard", "running", "Config revision: 7", "declaration revision: 9", "details suppressed"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("dashboard missing %q: %s", expected, view)
		}
	}
	if strings.Contains(view, "SECRET_AND_ANSI") || strings.Contains(view, "\x1b") {
		t.Fatalf("dashboard leaked control/error payload: %q", view)
	}
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if cmd == nil || !m.quitting || m.View() != "" {
		t.Fatalf("quit did not close only the UI: %+v", m)
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatalf("q did not issue Bubble Tea QuitMsg")
	}
	if api.statusCalls != 1 || api.profileCalls != 0 || api.nodeCalls != 0 {
		t.Fatalf("unexpected API calls: status=%d profiles=%d nodes=%d", api.statusCalls, api.profileCalls, api.nodeCalls)
	}
}

func TestProfileSelectionNodePagingAndTerminalSanitization(t *testing.T) {
	api := &fakeAPI{
		profiles: []apiv1.ProfileSourceResponse{
			{ProfileID: "alpha", Revision: 1},
			{ProfileID: "bravo", Revision: 2},
		},
		nodes: map[string]apiv1.ProfileNodeListResponse{
			"bravo": {ProfileID: "bravo", Total: 25, Nodes: func() []apiv1.ProfileNodeSummary {
				nodes := make([]apiv1.ProfileNodeSummary, 25)
				for i := range nodes {
					nodes[i] = apiv1.ProfileNodeSummary{
						NodeID: "stable-id", DisplayName: "中文节点\x1b[2J\nPASS\u202eHidden",
					}
				}
				return nodes
			}()},
		},
	}
	m := NewModel(context.Background(), api)
	m, _ = updated(t, m, profilesLoaded{request: 1, value: apiv1.ProfileSourceListResponse{Profiles: api.profiles}})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if m.selectedProfileID() != "bravo" {
		t.Fatal("profile selection failed")
	}
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil || m.page != nodesPage || m.nodesProfile != "bravo" {
		t.Fatalf("enter did not schedule node page: %+v", m)
	}
	msg, ok := cmd().(nodesLoaded)
	if !ok || msg.err != nil {
		t.Fatalf("node command failed: %+v", msg)
	}
	m, _ = updated(t, m, msg)
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 44, Height: 10})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyDown})
	view := m.View()
	if !strings.Contains(view, "中文节点") || !strings.Contains(view, "PASS") {
		t.Fatalf("node name not displayed: %q", view)
	}
	if strings.Contains(view, "\x1b") || strings.Contains(view, "\u202e") {
		t.Fatalf("terminal escape or bidi control survived: %q", view)
	}
	rows := strings.Split(strings.TrimSuffix(view, "\n"), "\n")
	if len(rows) > 10 {
		t.Fatalf("node list overflowed small terminal: %d lines", len(rows))
	}
	for _, line := range rows {
		if runeWidthOfLine(line) > 44 {
			t.Fatalf("node line overflowed terminal: %q", line)
		}
	}
	m, cmd = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
	if cmd == nil || m.nodesOffset != nodePageSize {
		t.Fatalf("next page failed: %+v", m)
	}
	m, _ = updated(t, m, cmd())
	if m.nodes.Offset != nodePageSize || len(m.nodes.Nodes) != 5 {
		t.Fatalf("unexpected second node page: %+v", m.nodes)
	}
	m, cmd = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'p'}})
	if cmd == nil || m.nodesOffset != 0 {
		t.Fatal("previous node page failed")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.page != profilesPage {
		t.Fatal("escape did not return to profile list")
	}
	if !api.observedDeadline {
		t.Fatal("API command did not enforce bounded request deadlines")
	}
}

func TestRefreshTokensRejectLateMessagesAndHideErrors(t *testing.T) {
	api := &fakeAPI{}
	m := NewModel(context.Background(), api)
	m, _ = updated(t, m, statusLoaded{request: 1, value: apiv1.StatusResponse{CoreState: "healthy"}})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	m, _ = updated(t, m, statusLoaded{request: 1, value: apiv1.StatusResponse{CoreState: "stale"}})
	if m.statusReady {
		t.Fatal("stale request was accepted after a refresh")
	}
	m, _ = updated(t, m, statusLoaded{request: 2, err: errors.New("secret subscription?token=DO_NOT_SHOW")})
	if !m.statusError || strings.Contains(m.View(), "DO_NOT_SHOW") {
		t.Fatalf("daemon failure was not safely summarized: %q", m.View())
	}
	m, _ = updated(t, m, profilesLoaded{request: 1, value: apiv1.ProfileSourceListResponse{
		Profiles: []apiv1.ProfileSourceResponse{{ProfileID: "outdated"}},
	}})
	if len(m.profiles) != 0 {
		t.Fatal("stale profile listing was accepted")
	}
	m, _ = updated(t, m, profilesLoaded{request: 2, value: apiv1.ProfileSourceListResponse{
		Profiles: []apiv1.ProfileSourceResponse{{ProfileID: "current"}},
	}})
	if m.selectedProfileID() != "current" {
		t.Fatal("newer profile response not accepted")
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 20, Height: 4})
	if !strings.Contains(m.View(), "too small") {
		t.Fatalf("missing narrow-terminal safe mode: %q", m.View())
	}
}

func TestProfileListScrollTracksSelectionAndCapsMemory(t *testing.T) {
	api := &fakeAPI{}
	profiles := make([]apiv1.ProfileSourceResponse, 220)
	for i := range profiles {
		profiles[i].ProfileID = "profile-" + strings.Repeat("x", i%20)
	}
	m := NewModel(context.Background(), api)
	m, _ = updated(t, m, profilesLoaded{request: 1, value: apiv1.ProfileSourceListResponse{Profiles: profiles}})
	if len(m.profiles) != maxProfilesShown || !m.profilesTruncated {
		t.Fatalf("profiles not capped: %+v", m)
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 48, Height: 9})
	for i := 0; i < 70; i++ {
		m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	if m.selected != 70 {
		t.Fatalf("selected profile=%d", m.selected)
	}
	view := m.View()
	if !strings.Contains(view, "> ") || !strings.Contains(view, "capped at 200") {
		t.Fatalf("selected profile not visible in bounded window: %q", view)
	}
	if len(strings.Split(strings.TrimSuffix(view, "\n"), "\n")) > m.height {
		t.Fatal("profile list overflowed viewport")
	}
}

func TestSafeTextControlAndChineseWidth(t *testing.T) {
	input := "你好\x1b[31m\r\n世界\u202e\u200b"
	got := safeText(input, 9)
	if strings.ContainsAny(got, "\x1b\r\n") || strings.Contains(got, "\u202e") || strings.Contains(got, "\u200b") {
		t.Fatalf("unsafe terminal output: %q", got)
	}
	if runeWidthOfLine(got) > 9 || !strings.Contains(got, "你好") {
		t.Fatalf("width truncation incorrect: %q", got)
	}
}

func TestProfileModelStoresOnlyAllowlistedMetadata(t *testing.T) {
	input := apiv1.ProfileSourceResponse{
		ProfileID: "work", Revision: 4,
		Source: apiv1.ProfileSourceSpec{
			Format: "sing-box", Location: "https://host.invalid/path?token=SECRET_TEST_TOKEN",
			UserAgent: "Bearer SECRET_TEST_TOKEN", Enabled: true,
		},
		LastError:          "SECRET_TEST_TOKEN",
		LastSourceRevision: "SECRET_TEST_TOKEN",
	}
	m := NewModel(context.Background(), &fakeAPI{})
	m, _ = updated(t, m, profilesLoaded{request: 1, value: apiv1.ProfileSourceListResponse{
		Profiles: []apiv1.ProfileSourceResponse{input},
	}})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'2'}})
	if len(m.profiles) != 1 || m.profiles[0].Revision != 4 ||
		!m.profiles[0].Enabled || m.profiles[0].Format != "sing-box" {
		t.Fatalf("profile state projection incorrect: %+v", m.profiles)
	}
	if strings.Contains(fmt.Sprintf("%+v", m.profiles), "SECRET_TEST_TOKEN") ||
		strings.Contains(m.View(), "SECRET_TEST_TOKEN") {
		t.Fatal("TUI retained subscription secrets or untrusted error contents")
	}
}

func runeWidthOfLine(s string) int {
	width := 0
	for _, r := range s {
		width += runeColumns(r)
	}
	return width
}
