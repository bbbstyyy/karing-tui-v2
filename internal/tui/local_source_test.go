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

type localSourceFake struct {
	*fakeAPI
	putCalls       int
	detailCalls    int
	request        apiv1.ProfileSourcePutRequest
	detail         apiv1.ProfileSourceResponse
	putErr         error
	detailErr      error
	poisonDetail   bool
	putDeadline    bool
	detailDeadline bool
}

func (f *localSourceFake) PutProfileSource(ctx context.Context, id string, request apiv1.ProfileSourcePutRequest) (apiv1.ProfileSourceResponse, error) {
	f.putCalls++
	f.request = request
	if due, ok := ctx.Deadline(); ok && time.Until(due) > 0 && time.Until(due) <= 10*time.Second {
		f.putDeadline = true
	}
	if f.putErr != nil {
		return apiv1.ProfileSourceResponse{}, f.putErr
	}
	f.detail = apiv1.ProfileSourceResponse{
		ProfileID: id, Revision: 1, Source: request.Source,
	}
	f.profiles = append(f.profiles, f.detail)
	return f.detail, nil
}

func (f *localSourceFake) ProfileSource(ctx context.Context, _ string) (apiv1.ProfileSourceResponse, error) {
	f.detailCalls++
	if due, ok := ctx.Deadline(); ok && time.Until(due) > 0 && time.Until(due) <= 3*time.Second {
		f.detailDeadline = true
	}
	if f.detailErr != nil {
		return apiv1.ProfileSourceResponse{}, f.detailErr
	}
	response := f.detail
	if f.poisonDetail {
		response.Source.Location = "https://secret.invalid?token=LEAK"
	}
	return response, nil
}

func localSourceKey(r rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
}

func writeLocalSourceText(t *testing.T, m Model, text string) Model {
	t.Helper()
	for _, r := range text {
		var cmd tea.Cmd
		m, cmd = updated(t, m, localSourceKey(r))
		if cmd != nil {
			t.Fatalf("plain text %q started I/O", r)
		}
	}
	return m
}

func localSourceEmptyPage(t *testing.T, fake *localSourceFake) Model {
	t.Helper()
	m := NewModel(context.Background(), fake)
	m, _ = updated(t, m, localSourceKey('2'))
	m, _ = updated(t, m, profilesLoaded{
		request: 1,
		value:   apiv1.ProfileSourceListResponse{Profiles: fake.profiles},
	})
	return m
}

func localSourceProposed(t *testing.T, m Model, id, path string) Model {
	t.Helper()
	m, _ = updated(t, m, localSourceKey('c'))
	if !m.localSource.editing || m.localSource.pathStep {
		t.Fatal("local source wizard did not start with a profile ID")
	}
	m = writeLocalSourceText(t, m, id)
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if !m.localSource.pathStep || !m.localSource.editing {
		t.Fatal("valid profile ID did not advance to private file path")
	}
	m = writeLocalSourceText(t, m, path)
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.localSource.pending == nil || m.localSource.editing {
		t.Fatalf("valid source did not enter explicit confirmation: %+v", m.localSource)
	}
	return m
}

func TestLocalSourceWizardRegistersOnlyAfterConfirmationAndReadback(t *testing.T) {
	fake := &localSourceFake{fakeAPI: &fakeAPI{}}
	m := localSourceEmptyPage(t, fake)
	privatePath := "/tmp/subscription-SECRET_TOKEN.yaml"
	m = localSourceProposed(t, m, "new-profile", privatePath)
	for _, marker := range []string{"CONFIRM source creation", "ExpectedRevision=0"} {
		if !strings.Contains(m.View(), marker) {
			t.Fatalf("missing explicit confirmation %q: %q", marker, m.View())
		}
	}
	if strings.Contains(m.View(), privatePath) || strings.Contains(m.View(), "SECRET_TOKEN") {
		t.Fatal("TUI echoed private source path")
	}
	m, cmd := updated(t, m, localSourceKey('y'))
	if cmd == nil || fake.putCalls != 0 || !m.localSource.writing ||
		m.localSource.path != "" || m.localSource.pending != nil {
		t.Fatalf("confirmation not single-shot/deferred: %+v", m.localSource)
	}
	m, duplicate := updated(t, m, localSourceKey('y'))
	if duplicate != nil || fake.putCalls != 0 {
		t.Fatal("duplicate confirmation issued a second write")
	}
	result := cmd()
	if fake.putCalls != 1 || fake.detailCalls != 1 ||
		!fake.putDeadline || !fake.detailDeadline || fake.request.ExpectedRevision != 0 ||
		fake.request.Source.Format != "sing-box" ||
		fake.request.Source.LocationKind != "file" ||
		fake.request.Source.Location != privatePath ||
		fake.request.Source.Fetch.Mode != "direct" ||
		!fake.request.Source.Enabled ||
		fake.request.Source.UpdateIntervalSeconds != 0 {
		t.Fatalf("unsafe source create request: %+v", fake.request)
	}
	m, cmd = updated(t, m, result)
	if cmd == nil || !m.localSource.awaitingReadback || m.localSource.writing {
		t.Fatal("source create skipped independent list readback")
	}
	m, _ = updated(t, m, cmd())
	if m.localSource.awaitingReadback || !strings.Contains(m.localSource.notice, "Created new-profile at rev 1") ||
		!strings.Contains(m.localSource.notice, "stage/apply separately") ||
		fake.profileCalls != 1 || len(m.profiles) != 1 || m.selectedProfileID() != "new-profile" {
		t.Fatalf("source create not verified: %+v profiles=%+v", m.localSource, m.profiles)
	}
	if strings.Contains(m.View(), "SECRET_TOKEN") || strings.Contains(m.View(), privatePath) {
		t.Fatal("private path was leaked after creation")
	}
	if m.statusRequest != 1 || m.checkedApply.pending != nil ||
		m.initial.pending != nil || m.profileRefresh.writing {
		t.Fatal("source creation unexpectedly staged, refreshed or applied")
	}
}

func TestLocalSourceWizardChoosesStrictFormatAndRejectsBadOrDuplicatePaths(t *testing.T) {
	fake := &localSourceFake{fakeAPI: &fakeAPI{}}
	m := localSourceEmptyPage(t, fake)
	m, _ = updated(t, m, localSourceKey('c'))
	m = writeLocalSourceText(t, m, "fresh")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyTab})
	if localSourceFormats[m.localSource.formatIndex] != "clash-yaml" {
		t.Fatal("format chooser failed")
	}
	m = writeLocalSourceText(t, m, "/tmp/../token.yaml")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.localSource.pending != nil {
		t.Fatal("noncanonical source path accepted")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyCtrlU})
	m = writeLocalSourceText(t, m, "/tmp/token.yaml")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.localSource.pending == nil || m.localSource.pending.format != "clash-yaml" {
		t.Fatal("format choice not included in proposal")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.localSource.pending != nil || fake.putCalls != 0 {
		t.Fatal("cancel issued source create")
	}
	fake.profiles = append(fake.profiles, apiv1.ProfileSourceResponse{ProfileID: "taken", Revision: 2})
	m = localSourceEmptyPage(t, fake)
	m, _ = updated(t, m, localSourceKey('c'))
	m = writeLocalSourceText(t, m, "taken")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.localSource.pathStep {
		t.Fatal("existing ID allowed overwrite proposal")
	}
	if fake.putCalls != 0 {
		t.Fatal("duplicate ID triggered source PUT")
	}
}

func TestLocalSourceWizardResizeAndSecretInputNeverBecomeWritable(t *testing.T) {
	fake := &localSourceFake{fakeAPI: &fakeAPI{}}
	m := localSourceEmptyPage(t, fake)
	m = localSourceProposed(t, m, "fresh", "/tmp/SECRET.yaml")
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 40, Height: 7})
	if m.localSource.pending != nil || m.localSource.editing || fake.putCalls != 0 {
		t.Fatal("resize did not discard private pending write")
	}
	m, _ = updated(t, m, localSourceKey('y'))
	if fake.putCalls != 0 {
		t.Fatal("small terminal confirmed discarded source")
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 80, Height: 24})
	m.profilesTruncated = true
	m, _ = updated(t, m, localSourceKey('c'))
	if m.localSource.editing {
		t.Fatal("truncated source inventory enabled create")
	}
	m.profilesTruncated = false
	m, _ = updated(t, m, localSourceKey('c'))
	m = writeLocalSourceText(t, m, "../bad")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.localSource.pathStep {
		t.Fatal("unsafe ID was accepted")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if strings.Contains(m.View(), "SECRET") {
		t.Fatal("cancelled wizard leaked stored path")
	}
}

func TestLocalSourceWizardFailedOrForgedWriteNeverAutoRetriesOrLeaks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(*localSourceFake)
	}{
		{"ambiguous PUT", func(f *localSourceFake) {
			f.putErr = errors.New("https://source.invalid/?token=VERYSECRET")
		}},
		{"forged detail", func(f *localSourceFake) {
			f.poisonDetail = true
		}},
		{"failed detail", func(f *localSourceFake) {
			f.detailErr = errors.New("GET response with private path")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &localSourceFake{fakeAPI: &fakeAPI{}}
			tc.modify(fake)
			m := localSourceEmptyPage(t, fake)
			m = localSourceProposed(t, m, "fresh", "/tmp/VERYSECRET.yml")
			m, write := updated(t, m, localSourceKey('y'))
			m, read := updated(t, m, write())
			if read == nil {
				t.Fatal("failure did not offer safe read-only inventory")
			}
			m, _ = updated(t, m, read())
			if fake.putCalls != 1 || !strings.Contains(m.localSource.notice, "uncertain") ||
				strings.Contains(m.View(), "VERYSECRET") ||
				strings.Contains(m.View(), "source.invalid") {
				t.Fatalf("create failure leaked secret or retried: %+v", m.localSource)
			}
		})
	}
}

func TestLocalSourceWizardStaleResultCannotClaimCreation(t *testing.T) {
	fake := &localSourceFake{fakeAPI: &fakeAPI{}}
	m := localSourceEmptyPage(t, fake)
	m = localSourceProposed(t, m, "fresh", "/tmp/example.json")
	m, write := updated(t, m, localSourceKey('y'))
	msg := write().(localSourceSaved)
	stale := msg
	stale.sequence++
	m, cmd := updated(t, m, stale)
	if cmd != nil || !m.localSource.writing {
		t.Fatal("stale completion was accepted")
	}
	m, cmd = updated(t, m, msg)
	if cmd == nil || !m.localSource.awaitingReadback {
		t.Fatal("verified write did not require list check")
	}
	fake.profiles[0].Revision = 7
	m, _ = updated(t, m, cmd())
	if strings.Contains(m.localSource.notice, "Created fresh") ||
		!strings.Contains(m.localSource.notice, "mismatched") {
		t.Fatalf("stale source revision accepted as new creation: %q", m.localSource.notice)
	}
	m, ignored := updated(t, m, msg)
	if ignored != nil || m.localSource.writing {
		t.Fatal("replayed completion was accepted")
	}
}

func TestLocalSourceWizardRejectsTamperedListAtSameRevision(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*localSourceFake)
	}{
		{"different path", func(f *localSourceFake) {
			f.profiles[0].Source.Location = "/tmp/other-PRIVATE_TOKEN.json"
		}},
		{"different format", func(f *localSourceFake) {
			f.profiles[0].Source.Format = "clash-yaml"
		}},
		{"different fetch", func(f *localSourceFake) {
			f.profiles[0].Source.Fetch.Mode = "selected"
		}},
		{"different filter", func(f *localSourceFake) {
			f.profiles[0].Source.Filter.KeywordOrRegex = "hostile"
		}},
		{"unexpected automatic refresh", func(f *localSourceFake) {
			id := int64(77)
			f.profiles[0].CurrentSnapshotID = &id
		}},
		{"duplicate ID", func(f *localSourceFake) {
			f.profiles = append(f.profiles, f.profiles[0])
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &localSourceFake{fakeAPI: &fakeAPI{}}
			m := localSourceEmptyPage(t, fake)
			m = localSourceProposed(t, m, "new-profile", "/tmp/PRIVATE_TOKEN.json")
			m, write := updated(t, m, localSourceKey('y'))
			m, read := updated(t, m, write())
			if read == nil || !m.localSource.awaitingReadback ||
				m.localSource.sourceFingerprint == ([32]byte{}) {
				t.Fatal("creation did not reach committed fingerprint readback")
			}
			tc.mutate(fake)
			m, _ = updated(t, m, read())
			if !strings.Contains(m.localSource.notice, "mismatched") ||
				strings.Contains(m.localSource.notice, "Created") ||
				strings.Contains(m.View(), "PRIVATE_TOKEN") ||
				m.localSource.sourceFingerprint != ([32]byte{}) ||
				m.localSource.createdID != "" {
				t.Fatalf("unsafe source list accepted or private token leaked: %+v", m.localSource)
			}
			if fake.putCalls != 1 {
				t.Fatal("readback mismatch caused automatic retry")
			}
		})
	}
}
