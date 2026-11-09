package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

func TestRemoteHTTPSWizardRegistersOnlyAfterConfirmationAndReadback(t *testing.T) {
	fake := &localSourceFake{fakeAPI: &fakeAPI{}}
	m := localSourceEmptyPage(t, fake)
	m, cmd := updated(t, m, localSourceKey('s'))
	if cmd != nil || !m.localSource.editing || m.localSource.kind != profile.SourceLocationURL ||
		fake.putCalls != 0 {
		t.Fatal("remote wizard did not open without a write")
	}
	m = writeLocalSourceText(t, m, "remote-one")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if !m.localSource.pathStep {
		t.Fatal("new remote ID was rejected")
	}
	// Deliberately choose the common Base64 URI-list subscription subset.
	for i := 0; i < 3; i++ {
		m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyTab})
	}
	secretURL := "https://subscriptions.example.test/api/v1?token=SECRET_URL_TOKEN"
	m = writeLocalSourceText(t, m, secretURL)
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.localSource.pending == nil || m.localSource.pending.kind != profile.SourceLocationURL ||
		m.localSource.pending.format != "uri-list-base64" || !strings.Contains(m.View(), "CONFIRM") {
		t.Fatalf("HTTPS source proposal invalid: %+v", m.localSource)
	}
	if strings.Contains(m.View(), secretURL) || strings.Contains(m.View(), "SECRET_URL_TOKEN") {
		t.Fatal("remote source URL leaked in confirmation")
	}
	m, write := updated(t, m, localSourceKey('y'))
	if write == nil || fake.putCalls != 0 || m.localSource.pending != nil ||
		m.localSource.path != "" || !m.localSource.writing {
		t.Fatal("confirmation was not a single deferred write")
	}
	m, duplicate := updated(t, m, localSourceKey('y'))
	if duplicate != nil {
		t.Fatal("duplicate write was scheduled")
	}
	msg := write()
	if fake.putCalls != 1 || fake.detailCalls != 1 ||
		!fake.putDeadline || !fake.detailDeadline ||
		fake.request.ExpectedRevision != 0 ||
		fake.request.Source.LocationKind != "url" ||
		fake.request.Source.Location != secretURL ||
		fake.request.Source.Format != "uri-list-base64" ||
		fake.request.Source.Fetch.Mode != "direct" ||
		!fake.request.Source.Enabled || fake.request.Source.UpdateIntervalSeconds != 0 {
		t.Fatalf("unsafe remote source creation: %+v", fake.request)
	}
	m, read := updated(t, m, msg)
	if read == nil || !m.localSource.awaitingReadback {
		t.Fatal("independent source-list readback not scheduled")
	}
	m, _ = updated(t, m, read())
	if fake.profileCalls != 1 || m.selectedProfileID() != "remote-one" ||
		!strings.Contains(m.localSource.notice, "Created remote-one at rev 1") ||
		m.localSource.awaitingReadback || m.profileRefresh.writing ||
		m.statusRequest != 1 || m.checkedApply.pending != nil {
		t.Fatalf("remote wizard auto-applied or failed readback: %+v", m.localSource)
	}
	if strings.Contains(m.View(), "SECRET_URL_TOKEN") ||
		strings.Contains(m.View(), secretURL) {
		t.Fatal("private HTTPS URL leaked after creation")
	}
}

func TestRemoteHTTPSWizardRejectsUnsafeURLsWithoutNetworkOrWrites(t *testing.T) {
	for _, candidate := range []string{
		"http://subscriptions.example.test/api?token=INSECURE",
		"https://user:pass@subscriptions.example.test/api",
		"https://subscriptions.example.test/api#private-fragment",
		"https:/missing-host",
		"file:///tmp/subscription.json",
		"https://",
	} {
		t.Run(candidate[:min(12, len(candidate))], func(t *testing.T) {
			fake := &localSourceFake{fakeAPI: &fakeAPI{}}
			m := localSourceEmptyPage(t, fake)
			m, _ = updated(t, m, localSourceKey('s'))
			m = writeLocalSourceText(t, m, "remote")
			m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
			m = writeLocalSourceText(t, m, candidate)
			m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
			if m.localSource.pending != nil || fake.putCalls != 0 {
				t.Fatal("unsafe HTTPS URL unexpectedly accepted")
			}
			if strings.Contains(m.View(), candidate) ||
				strings.Contains(m.View(), "INSECURE") ||
				strings.Contains(m.View(), "pass@") {
				t.Fatal("unsafe HTTPS URL echoed to TUI")
			}
			m, cmd := updated(t, m, localSourceKey('y'))
			if cmd != nil || fake.putCalls != 0 {
				t.Fatal("non-confirmable URL sent a write")
			}
		})
	}
}

func TestRemoteHTTPSWizardCancelResizeAndSourceListSafety(t *testing.T) {
	fake := &localSourceFake{fakeAPI: &fakeAPI{}}
	m := localSourceEmptyPage(t, fake)
	m, _ = updated(t, m, localSourceKey('s'))
	m = writeLocalSourceText(t, m, "private")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m = writeLocalSourceText(t, m, "https://subscriptions.example.test/?token=SECRET")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 40, Height: 7})
	if m.localSource.pending != nil || m.localSource.editing ||
		m.localSource.path != "" || fake.putCalls != 0 {
		t.Fatal("resize did not discard unconfirmed private URL")
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 80, Height: 24})
	m, _ = updated(t, m, localSourceKey('s'))
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.localSource.editing || strings.Contains(m.View(), "SECRET") {
		t.Fatal("Esc failed to cancel remote wizard")
	}
	m.profilesTruncated = true
	m, _ = updated(t, m, localSourceKey('s'))
	if m.localSource.editing || fake.putCalls != 0 {
		t.Fatal("truncated source list admitted remote source creation")
	}
}
