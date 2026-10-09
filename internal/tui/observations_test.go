package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

type observationsTestAPI struct {
	*fakeAPI
	selection apiv1.CurrentSelectionResponse
	selectionError error
	selectionCalls int
	connections apiv1.ObservedConnectionsResponse
	connectionsError error
	connectionCalls int
}

func (f *observationsTestAPI) CurrentSelection(ctx context.Context) (apiv1.CurrentSelectionResponse, error) {
	f.selectionCalls++
	f.checkDeadline(ctx)
	return f.selection, f.selectionError
}

func (f *observationsTestAPI) ObservedConnections(ctx context.Context) (apiv1.ObservedConnectionsResponse, error) {
	f.connectionCalls++
	f.checkDeadline(ctx)
	return f.connections, f.connectionsError
}

// Keep the existing TUI fixtures compatible with the expanded read-only API.
func (f *fakeAPI) CurrentSelection(context.Context) (apiv1.CurrentSelectionResponse, error) {
	return apiv1.CurrentSelectionResponse{}, errors.New("selection not configured")
}
func (f *fakeAPI) ObservedConnections(context.Context) (apiv1.ObservedConnectionsResponse, error) {
	return apiv1.ObservedConnectionsResponse{}, errors.New("connections not configured")
}

func TestSelectionReadOnlyDistinguishesIntentAndLiveState(t *testing.T) {
	target := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-abc", NodeID: "stable-a"}
	api := &observationsTestAPI{
		fakeAPI: &fakeAPI{},
		selection: apiv1.CurrentSelectionResponse{
			Target: target, Persisted: true, RuntimeTag: "internal-tag-a",
			LiveRuntimeTag: "internal-tag-b", Applied: false,
		},
	}
	m := NewModel(context.Background(), api)
	m, command := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'5'}})
	if command == nil || api.selectionCalls != 0 {
		t.Fatal("selection request did not remain asynchronous")
	}
	m, _ = updated(t, m, command())
	view := m.View()
	for _, expected := range []string{"read-only", "profile-abc/stable-a", "persisted", "MISMATCH"} {
		if !strings.Contains(view, expected) {
			t.Fatalf("selection missing %q: %q", expected, view)
		}
	}
	if strings.Contains(view, "internal-tag-a") || strings.Contains(view, "internal-tag-b") ||
		!api.observedDeadline {
		t.Fatal("selector leaked native tags or missed request deadline")
	}
	api.selection.Persisted = false
	api.selection.LiveRuntimeTag = ""
	api.selection.Applied = false
	m, command = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if command == nil {
		t.Fatal("selector refresh command missing")
	}
	m, _ = updated(t, m, command())
	view = m.View()
	if !strings.Contains(view, "declaration default") || !strings.Contains(view, "not observed") {
		t.Fatalf("stopped/default state mislabeled: %q", view)
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if !m.quitting {
		t.Fatal("TUI quit did not close client")
	}
}

func TestConnectionsPreserveIndependentEvidenceAndCapSensitivePayload(t *testing.T) {
	raw := apiv1.ObservedConnectionsResponse{
		Evidence: "observed", GenerationID: 19, ConfigRevision: 7,
		DownloadTotal: 100, UploadTotal: 25,
	}
	for i := 0; i < 45; i++ {
		row := apiv1.ObservedConnectionResponse{
			Evidence: "observed", Host: "example.com", DestinationPort: "443",
			Network: "tcp", Inbound: "mixed/in-rule", Upload: 12, Download: 15,
			ProcessPath: "token=PROCESS_SECRET", User: "USER_SECRET",
			RulePayload: "PASSWORD_SECRET", SourceIP: "192.0.2.123",
			Rule: "rule=RULE_SECRET", Chains: []string{"chain=CHAIN_SECRET"},
			ID: "CONNECTION_SECRET",
			SourceEvidence: "simulated", SourceDecision: "route",
			SourceLayer: domain.LayerGeoSite, SourceGroupID: "g-cn",
			SourceTarget: &domain.TargetRef{Kind: domain.TargetDirect},
			SourceDNSProfileID: "dns-cn",
		}
		if i == 0 {
			row.Host = "https://untrusted.invalid?token=HOST_SECRET"
			row.DestinationIP = "203.0.113.8"
			row.SourceEvidence = "unknown"
			row.SourceDecision = "unknown"
			row.SourceUnknownConditions = []string{"rule_set:opaque", "process_name"}
		}
		raw.Connections = append(raw.Connections, row)
	}
	api := &observationsTestAPI{fakeAPI: &fakeAPI{}, connections: raw}
	m := NewModel(context.Background(), api)
	m, command := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'6'}})
	if command == nil || api.connectionCalls != 0 {
		t.Fatal("connections request was not asynchronous")
	}
	m, _ = updated(t, m, command())
	if !m.connections.ready || len(m.connections.result.rows) != maxObservedRows ||
		m.connections.result.total != 45 {
		t.Fatalf("connection cap/summary incorrect: %+v", m.connections)
	}
	view := strings.Join(m.connectionsObservationLines(), "\n")
	for _, expected := range []string{
		"OBSERVED core", "Source attribution: SIMULATED or UNKNOWN",
		"Showing 30 of 45", "203.0.113.8:443", "source[UNKNOWN]",
		"rule_set (opaque)", "source[SIMULATED]", "geosite/g-cn",
		"target=direct", "dns=dns-cn (binding only)",
	} {
		if !strings.Contains(view, expected) {
			t.Fatalf("missing %q in connections: %s", expected, view)
		}
	}
	for _, secret := range []string{"PROCESS_SECRET", "USER_SECRET", "PASSWORD_SECRET", "HOST_SECRET",
		"RULE_SECRET", "CHAIN_SECRET", "CONNECTION_SECRET", "192.0.2.123"} {
		if strings.Contains(fmt.Sprintf("%+v", m.connections.result), secret) ||
			strings.Contains(view, secret) {
			t.Fatalf("sensitive untrusted metadata retained: %q", secret)
		}
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 38, Height: 9})
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if m.connections.scroll != 1 {
		t.Fatal("connection snapshot cannot scroll")
	}
	rows := strings.Split(strings.TrimSuffix(m.View(), "\n"), "\n")
	if len(rows) > 9 {
		t.Fatalf("connections exceeded viewport: %d lines", len(rows))
	}
	for _, line := range rows {
		if runeWidthOfLine(line) > 38 {
			t.Fatalf("connection line too wide: %q", line)
		}
	}
	if !api.observedDeadline {
		t.Fatal("connection read missed bounded timeout")
	}
}

func TestObservationsIgnoreStaleAndFailedResponsesWithoutLeakingErrors(t *testing.T) {
	api := &observationsTestAPI{
		fakeAPI: &fakeAPI{},
		selection: apiv1.CurrentSelectionResponse{
			Target: domain.TargetRef{Kind: domain.TargetDirect},
		},
		connections: apiv1.ObservedConnectionsResponse{
			Evidence: "observed", GenerationID: 3,
			Connections: []apiv1.ObservedConnectionResponse{{Evidence:"observed",SourceEvidence:"unknown"}},
		},
	}
	m := NewModel(context.Background(), api)
	m, pending := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'5'}})
	m, again := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if again != nil || api.selectionCalls != 0 {
		t.Fatal("reentrant selection request enqueued")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'6'}})
	m, _ = updated(t, m, pending())
	if m.selection.ready || m.selection.active {
		t.Fatal("selection result applied after page switch")
	}
	api.connectionsError = errors.New("secret=TOKEN_SECRET\x1b[0m")
	m, _ = updated(t, m, connectionsObservationLoaded{sequence: m.connections.sequence+1})
	if !m.connections.active {
		t.Fatal("unexpected stale completion accepted")
	}
	// Entry request is queued but not executed; complete it with a bounded failure.
	m, _ = updated(t, m, connectionsObservationLoaded{sequence: m.connections.sequence, failed: true})
	if !m.connections.failed || strings.Contains(m.View(), "TOKEN_SECRET") {
		t.Fatalf("error not redacted: %q", m.View())
	}
	m, refresh := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if refresh == nil {
		t.Fatal("refresh was not scheduled")
	}
	m, _ = updated(t, m, refresh())
	if !m.connections.failed || strings.Contains(m.View(), "TOKEN_SECRET") {
		t.Fatalf("raw errors leaked: %q", m.View())
	}
	api.connectionsError = nil
	m, refresh = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if refresh == nil {
		t.Fatal("retry missing")
	}
	m, _ = updated(t, m, refresh())
	if !m.connections.ready {
		t.Fatal("retry did not reconcile")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'1'}})
	if m.connections.ready || len(m.connections.result.rows) != 0 {
		t.Fatal("leaving page retained connection snapshot")
	}
}

func TestConnectionsRejectUnsupportedEvidenceAndBadSelectorReadback(t *testing.T) {
	for _, tc := range []struct{
		evidence string
		decision string
	}{
		{"observed", "route"}, {"simulated", "unknown"}, {"", ""},
	}{
		_, err := projectObservedConnections(apiv1.ObservedConnectionsResponse{
			Connections: []apiv1.ObservedConnectionResponse{{
				Evidence: "observed", SourceEvidence: tc.evidence, SourceDecision: tc.decision,
			}},
		})
		if err == nil {
			t.Fatalf("invalid attribution accepted: %+v", tc)
		}
	}
	api := &observationsTestAPI{
		fakeAPI: &fakeAPI{},
		selection: apiv1.CurrentSelectionResponse{
			Target: domain.TargetRef{Kind: domain.TargetDirect},
			RuntimeTag: "native", LiveRuntimeTag:"other", Applied:true,
		},
	}
	m := NewModel(context.Background(), api)
	m, cmd := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'5'}})
	m, _ = updated(t, m, cmd())
	if !m.selection.failed || m.selection.ready {
		t.Fatal("inconsistent selector readback accepted")
	}
}
