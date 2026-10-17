package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	tea "github.com/charmbracelet/bubbletea"
)

func (f *fakeAPI) RecoveryAudit(context.Context) (apiv1.RecoveryAuditResponse, error) {
	return apiv1.RecoveryAuditResponse{}, errors.New("recovery audit unavailable")
}

type historyFakeAPI struct {
	*fakeAPI
	value          apiv1.RecoveryAuditResponse
	err            error
	calls          int
	canceled       bool
	missingTimeout bool
}

func (f *historyFakeAPI) RecoveryAudit(ctx context.Context) (apiv1.RecoveryAuditResponse, error) {
	f.calls++
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > 30*time.Second {
		f.missingTimeout = true
	}
	if ctx.Err() != nil {
		f.canceled = true
		return apiv1.RecoveryAuditResponse{}, ctx.Err()
	}
	return f.value, f.err
}
func historyFixture() apiv1.RecoveryAuditResponse {
	applied, fallback := int64(21), int64(18)
	return apiv1.RecoveryAuditResponse{
		APIVersion: apiv1.Version, Evidence: "committed_generation_history_and_retained_storage",
		ConfigRevision: 7, CurrentDeclarationRevision: 11, AppliedGenerationID: &applied, LastKnownGoodGenerationID: &fallback, Truncated: true,
		Generations: []apiv1.RecoveryGenerationAudit{
			{GenerationID: 21, CommittedConfigRevision: 7, Applied: true, PayloadRetained: true, StoredIntegrityVerified: true, RuleSetResourcesVerified: true, DeclarationRevision: 11, RuleSetCount: 3, Status: "stored_integrity_verified_only", PreflightStatus: "bound_state_consistent_only"},
			{GenerationID: 18, CommittedConfigRevision: 6, LastKnownGood: true, PayloadRetained: false, Status: "payload_pruned"},
		},
	}
}
func historyKey(r rune) tea.KeyMsg { return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}} }
func TestHistoryTUIReadOnlyOnDemandAndScrollable(t *testing.T) {
	api := &historyFakeAPI{fakeAPI: &fakeAPI{}, value: historyFixture()}
	m := NewModel(context.Background(), api)
	m, cmd := updated(t, m, historyKey('9'))
	if m.page != historyPage || cmd == nil || api.calls != 0 || !m.history.active {
		t.Fatal("history must defer read")
	}
	m, another := updated(t, m, historyKey('r'))
	if another != nil {
		t.Fatal("active history admitted duplicate request")
	}
	m, _ = updated(t, m, cmd())
	if api.calls != 1 || api.missingTimeout || !m.history.ready || m.history.failed {
		t.Fatalf("history invalid: %+v", m.history)
	}
	view := m.View()
	for _, want := range []string{"[9]History", "RESTORE DISABLED", "Config revision: 7", "Applied: 21"} {
		if !strings.Contains(view, want) {
			t.Fatalf("missing %q: %q", want, view)
		}
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 80, Height: 9})
	m, _ = updated(t, m, historyKey('j'))
	if m.history.scroll != 1 {
		t.Fatal("history scroll down failed")
	}
	m, _ = updated(t, m, historyKey('k'))
	if m.history.scroll != 0 {
		t.Fatal("history scroll up failed")
	}
	m, cmd = updated(t, m, historyKey('r'))
	if cmd == nil || api.calls != 1 {
		t.Fatal("refresh not deferred")
	}
	m, _ = updated(t, m, cmd())
	if api.calls != 2 || !m.history.ready {
		t.Fatal("refresh failed")
	}
}
func TestHistoryTUIRejectsForgedStatusAndSecretErrors(t *testing.T) {
	cases := []struct {
		name  string
		alter func(*apiv1.RecoveryAuditResponse)
	}{
		{"restore support", func(r *apiv1.RecoveryAuditResponse) { r.RestoreSupported = true }},
		{"restore ready", func(r *apiv1.RecoveryAuditResponse) { r.Generations[0].RestoreReady = true }},
		{"unknown status", func(r *apiv1.RecoveryAuditResponse) { r.Generations[0].Status = "password=NEVER_RENDER" }},
		{"too many entries", func(r *apiv1.RecoveryAuditResponse) {
			r.Generations = append(r.Generations, make([]apiv1.RecoveryGenerationAudit, 12)...)
		}},
		{"contradictory integrity", func(r *apiv1.RecoveryAuditResponse) { r.Generations[0].PayloadRetained = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &historyFakeAPI{fakeAPI: &fakeAPI{}, value: historyFixture()}
			tc.alter(&api.value)
			m := NewModel(context.Background(), api)
			m, cmd := updated(t, m, historyKey('9'))
			m, _ = updated(t, m, cmd())
			if !m.history.failed || m.history.ready || len(m.history.rows) != 0 || !strings.Contains(m.View(), "untrusted") || strings.Contains(m.View(), "NEVER_RENDER") {
				t.Fatalf("unsafe audit accepted: %q", m.View())
			}
		})
	}
	api := &historyFakeAPI{fakeAPI: &fakeAPI{}, err: errors.New("password=PRIVATE_DB_TOKEN /run/secret")}
	m := NewModel(context.Background(), api)
	m, cmd := updated(t, m, historyKey('9'))
	m, _ = updated(t, m, cmd())
	if !m.history.failed || strings.Contains(m.View(), "PRIVATE_DB_TOKEN") || strings.Contains(m.View(), "/run/secret") {
		t.Fatal("leaked backend error")
	}
}
func TestHistoryTUIPageExitCancelsPendingReadAndRejectsLateResponse(t *testing.T) {
	api := &historyFakeAPI{fakeAPI: &fakeAPI{}, value: historyFixture()}
	m := NewModel(context.Background(), api)
	m, old := updated(t, m, historyKey('9'))
	sequence := m.history.sequence
	m, _ = updated(t, m, historyKey('1'))
	if m.page != dashboardPage || m.history.active || len(m.history.rows) != 0 {
		t.Fatal("page exit failed to clear")
	}
	m, _ = updated(t, m, old())
	if !api.canceled || m.history.ready {
		t.Fatal("canceled read was accepted")
	}
	m, next := updated(t, m, historyKey('9'))
	if next == nil || m.history.sequence == sequence {
		t.Fatal("reentry did not increment sequence")
	}
	m, _ = updated(t, m, historyLoaded{sequence: sequence, rows: []string{"STALE_PRIVATE_VALUE"}})
	if m.history.ready || strings.Contains(m.View(), "STALE_PRIVATE_VALUE") {
		t.Fatal("accepted stale result")
	}
	m, _ = updated(t, m, next())
	if !m.history.ready {
		t.Fatal("fresh reply rejected")
	}
	m, _ = updated(t, m, historyKey('q'))
	if !m.quitting || m.View() != "" {
		t.Fatal("quit did not exit UI")
	}
}
