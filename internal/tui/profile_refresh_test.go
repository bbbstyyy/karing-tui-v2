package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

type manualRefreshFake struct {
	*fakeAPI
	calls           int
	receivedID      string
	receivedRequest apiv1.ProfileRefreshRequest
	deadlineOK      bool
	response        apiv1.ProfileRefreshResponse
	err             error
}

func (f *manualRefreshFake) RefreshProfileSource(
	ctx context.Context, profileID string, request apiv1.ProfileRefreshRequest,
) (apiv1.ProfileRefreshResponse, error) {
	f.calls++
	f.receivedID, f.receivedRequest = profileID, request
	if deadline, ok := ctx.Deadline(); ok &&
		time.Until(deadline) > 0 && time.Until(deadline) <= 65*time.Second {
		f.deadlineOK = true
	}
	return f.response, f.err
}

func manualRefreshFixture() *manualRefreshFake {
	id := int64(7)
	return &manualRefreshFake{
		fakeAPI: &fakeAPI{
			profiles: []apiv1.ProfileSourceResponse{{
				ProfileID: "source-1", Revision: 4,
				Source: apiv1.ProfileSourceSpec{
					Format: "uri-list-base64", Enabled: true,
					Location: "https://private.invalid/sub?token=PRIVATE_TOKEN",
				},
				CurrentSnapshotID: &id,
				LastError:         "PRIVATE_TOKEN",
			}},
		},
		response: apiv1.ProfileRefreshResponse{
			ProfileID: "source-1", SourceRevision: 4, CurrentSnapshotID: &id,
			NodeCount: 2, AcceptedRevision: "SECRET_DO_NOT_RENDER",
			Diagnostics: []apiv1.ProfileDiagnosticResponse{{
				Message: "SECRET_DO_NOT_RENDER",
			}},
		},
	}
}

func manualKey(key rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}}
}

func readyManualRefreshPage(t *testing.T, api *manualRefreshFake) Model {
	t.Helper()
	m := NewModel(context.Background(), api)
	var cmd tea.Cmd
	m, cmd = updated(t, m, manualKey('2'))
	if cmd != nil {
		t.Fatal("opening Profiles should not write to daemon")
	}
	m, _ = updated(t, m, profilesLoaded{
		request: 1, value: apiv1.ProfileSourceListResponse{Profiles: api.profiles},
	})
	return m
}

func TestManualTUIRefreshConfirmedCASAndVerifiedReadback(t *testing.T) {
	api := manualRefreshFixture()
	m := readyManualRefreshPage(t, api)
	m, cmd := updated(t, m, manualKey('u'))
	if cmd != nil || m.profileRefresh.pending == nil || api.calls != 0 {
		t.Fatal("proposal must be read-only")
	}
	if strings.Contains(m.View(), "PRIVATE_TOKEN") || strings.Contains(m.View(), "SECRET_DO_NOT_RENDER") {
		t.Fatal("private source credentials reached terminal")
	}
	m, cmd = updated(t, m, manualKey('y'))
	if cmd == nil || !m.profileRefresh.writing || api.calls != 0 {
		t.Fatal("explicit confirmation did not defer one refresh")
	}
	m, duplicate := updated(t, m, manualKey('y'))
	if duplicate != nil || api.calls != 0 {
		t.Fatal("in-flight refresh admitted duplicate")
	}
	msg := cmd()
	if api.calls != 1 || !api.deadlineOK || api.receivedID != "source-1" ||
		api.receivedRequest.ExpectedSourceRevision != 4 || api.receivedRequest.AllowEmpty {
		t.Fatalf("TUI refresh did not preserve safe source CAS: %+v", api)
	}
	m, cmd = updated(t, m, msg)
	if cmd == nil || m.profileRefresh.writing || !m.profileRefresh.awaitingReadback {
		t.Fatal("successful refresh was falsely considered verified")
	}
	m, _ = updated(t, m, cmd())
	if api.profileCalls != 1 || m.profileRefresh.awaitingReadback ||
		!strings.Contains(m.profileRefresh.notice, "Verified snapshot 7 (2 nodes)") ||
		!strings.Contains(m.profileRefresh.notice, "separate") {
		t.Fatalf("daemon readback not verified: %+v", m.profileRefresh)
	}
	view := m.View()
	if strings.Contains(view, "PRIVATE_TOKEN") || strings.Contains(view, "SECRET_DO_NOT_RENDER") ||
		!strings.Contains(view, "Core Apply remain separate") {
		t.Fatalf("unsafe or incomplete refresh view: %q", view)
	}
	if m.nodesReady || m.nodesProfile != "" {
		t.Fatal("source refresh did not invalidate cached nodes")
	}
}

func TestManualTUIRefreshCancelResizeAndRejectUntrustedSourceList(t *testing.T) {
	api := manualRefreshFixture()
	m := readyManualRefreshPage(t, api)
	m, _ = updated(t, m, manualKey('u'))
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.profileRefresh.pending != nil || api.calls != 0 {
		t.Fatal("cancel sent refresh")
	}
	m, _ = updated(t, m, manualKey('u'))
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 32, Height: 7})
	if m.profileRefresh.pending != nil || api.calls != 0 {
		t.Fatal("tiny terminal retained write confirmation")
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 80, Height: 24})
	m.profilesTruncated = true
	m, _ = updated(t, m, manualKey('u'))
	if m.profileRefresh.pending != nil {
		t.Fatal("partial profile listing permitted source refresh")
	}
	m.profilesTruncated = false
	m.profiles[0].Enabled = false
	m, _ = updated(t, m, manualKey('u'))
	if m.profileRefresh.pending != nil {
		t.Fatal("disabled source permitted manual refresh")
	}
	m.profiles[0].Enabled = true
	m.profiles[0].ProfileID = "bad\nprofile"
	m, _ = updated(t, m, manualKey('u'))
	if m.profileRefresh.pending != nil {
		t.Fatal("untrusted profile ID permitted refresh")
	}
}

func TestManualTUIRefreshTimeoutOrMalformedReplyNeverRetriesOrLeaks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*manualRefreshFake)
	}{
		{"timeout with secret", func(f *manualRefreshFake) {
			f.err = errors.New("secret from URL https://private.invalid/?token=LEAK")
		}},
		{"spoofed profile", func(f *manualRefreshFake) {
			f.response.ProfileID = "other-profile"
		}},
		{"unexpected source CAS", func(f *manualRefreshFake) {
			f.response.SourceRevision++
		}},
		{"impossible empty snapshot", func(f *manualRefreshFake) {
			f.response.CurrentSnapshotID = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := manualRefreshFixture()
			tc.mutate(api)
			m := readyManualRefreshPage(t, api)
			m, _ = updated(t, m, manualKey('u'))
			m, cmd := updated(t, m, manualKey('y'))
			msg := cmd()
			m, cmd = updated(t, m, msg)
			if cmd == nil || !strings.Contains(m.profileRefresh.notice, "uncertain") {
				t.Fatalf("uncertain refresh not flagged: %+v", m.profileRefresh)
			}
			m, _ = updated(t, m, cmd())
			if api.calls != 1 || m.profileRefresh.pending != nil ||
				strings.Contains(m.View(), "LEAK") || strings.Contains(m.View(), "private.invalid") {
				t.Fatalf("failed update leaked secret or retried automatically: %+v", m.profileRefresh)
			}
		})
	}
}

func TestManualTUIRefreshReadbackMismatchAndStaleCompletion(t *testing.T) {
	api := manualRefreshFixture()
	m := readyManualRefreshPage(t, api)
	m, _ = updated(t, m, manualKey('u'))
	m, cmd := updated(t, m, manualKey('y'))
	result := cmd().(profileRefreshLoaded)
	stale := result
	stale.sequence++
	m, ignored := updated(t, m, stale)
	if ignored != nil || !m.profileRefresh.writing {
		t.Fatal("late/mismatched refresh completion changed active transaction")
	}
	m, cmd = updated(t, m, result)
	if cmd == nil || !m.profileRefresh.awaitingReadback {
		t.Fatal("refresh should require independent source readback")
	}
	api.profiles[0].Revision++
	m, _ = updated(t, m, cmd())
	if !strings.Contains(m.profileRefresh.notice, "mismatch") ||
		strings.Contains(m.profileRefresh.notice, "Verified snapshot") {
		t.Fatalf("invalid source readback was marked verified: %+v", m.profileRefresh)
	}
	m, ignored = updated(t, m, result)
	if ignored != nil || m.profileRefresh.writing {
		t.Fatal("replayed completion was accepted")
	}
}
