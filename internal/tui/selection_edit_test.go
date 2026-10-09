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

func (f *fakeAPI) SetCurrentSelectionChecked(context.Context, apiv1.CurrentSelectionCheckedRequest) (apiv1.CurrentSelectionResponse, error) {
	return apiv1.CurrentSelectionResponse{}, errors.New("checked selection not configured")
}

type selectionSwitchAPI struct {
	*observationsTestAPI
	writes         int
	last           apiv1.CurrentSelectionCheckedRequest
	err            error
	commitOnError  bool
	spoofResponse  bool
}

func (f *selectionSwitchAPI) SetCurrentSelectionChecked(ctx context.Context, req apiv1.CurrentSelectionCheckedRequest) (apiv1.CurrentSelectionResponse, error) {
	f.checkDeadline(ctx)
	f.writes++
	f.last = req
	if req.ExpectedSelectionRevision != f.selection.SelectionRevision ||
		req.ExpectedConfigRevision != f.selection.ConfigRevision ||
		!sameSelectionGeneration(req.ExpectedGenerationID, f.selection.AppliedGenerationID) ||
		req.ExpectedDeclarationRevision != f.selection.DeclarationRevision ||
		req.ExpectedDeclarationSHA256 != f.selection.DeclarationSHA256 {
		return apiv1.CurrentSelectionResponse{}, errors.New("409: CONFLICT_SECRET")
	}
	if f.err != nil && !f.commitOnError {
		return apiv1.CurrentSelectionResponse{}, f.err
	}
	f.selection.Target = req.Target
	f.selection.SelectionRevision++
	f.selection.Persisted = true
	if f.err != nil && f.commitOnError {
		f.selection.Applied = false
		// Persisted intent is different from the observed selector.
		f.selection.RuntimeTag = "future-selector"
		return apiv1.CurrentSelectionResponse{}, f.err
	}
	f.selection.RuntimeTag = "future-selector"
	f.selection.LiveRuntimeTag = "future-selector"
	f.selection.Applied = true
	response := f.selection
	if f.spoofResponse {
		response.SelectionRevision++
	}
	return response, nil
}

func selectorFixture() apiv1.CurrentSelectionResponse {
	id := int64(14)
	return apiv1.CurrentSelectionResponse{
		Target: domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-1", NodeID: "node-a"},
		SelectionRevision: 7, ConfigRevision: 9, AppliedGenerationID: &id,
		DeclarationRevision: 11, DeclarationSHA256: strings.Repeat("a", 64),
		RuntimeTag: "native-secret-a", LiveRuntimeTag: "native-secret-a",
		Applied: true, Persisted: true,
		Candidates: []domain.TargetRef{
			{Kind: domain.TargetSpecificNode, ProfileID: "profile-1", NodeID: "node-a"},
			{Kind: domain.TargetSpecificNode, ProfileID: "profile-1", NodeID: "node-b"},
			{Kind: domain.TargetGlobalURLTest},
			{Kind: domain.TargetCustomURLTest, GroupID: "cn-fast"},
		},
		CandidateCount: 4,
	}
}

func enterSelectionTest(t *testing.T, api *selectionSwitchAPI) Model {
	t.Helper()
	m := NewModel(context.Background(), api)
	m, command := updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'5'}})
	if command == nil || api.selectionCalls != 0 {
		t.Fatal("selector GET was not scheduled asynchronously")
	}
	m, _ = updated(t, m, command())
	if !m.selection.ready || !m.selection.result.editable ||
		m.selection.selected != 0 {
		t.Fatalf("bound candidate snapshot not loaded: %+v", m.selection)
	}
	return m
}

func selectionKey(t *testing.T, m Model, key string) (Model, tea.Cmd) {
	t.Helper()
	return updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
}

func TestSelectorRequiresConfirmationAndReconcilesSuccessfulWrite(t *testing.T) {
	api := &selectionSwitchAPI{observationsTestAPI: &observationsTestAPI{
		fakeAPI: &fakeAPI{}, selection: selectorFixture(),
	}}
	m := enterSelectionTest(t, api)
	m, _ = selectionKey(t, m, "j")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.selection.pending == nil || api.writes != 0 ||
		!strings.Contains(m.View(), "CONFIRM") {
		t.Fatal("Enter should propose a write, not commit it")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.selection.pending != nil || api.writes != 0 {
		t.Fatal("Esc did not discard the selection proposal")
	}
	// A global URLTest target is a first-class CurrentSelected member.
	m, _ = selectionKey(t, m, "j")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.selection.pending == nil ||
		m.selection.pending.target.Kind != domain.TargetGlobalURLTest {
		t.Fatal("global URLTest candidate not proposed")
	}
	m, _ = selectionKey(t, m, "r")
	if m.selection.pending == nil || api.selectionCalls != 1 {
		t.Fatal("unconfirmed change must not be silently refreshed")
	}
	m, command := selectionKey(t, m, "y")
	if command == nil || !m.selection.writing || m.selection.pending != nil ||
		api.writes != 0 {
		t.Fatal("confirmation did not schedule a single async CAS write")
	}
	m, duplicate := selectionKey(t, m, "y")
	if duplicate != nil || api.writes != 0 {
		t.Fatal("second y enqueued a concurrent mutation")
	}
	m, readback := updated(t, m, command())
	if readback == nil || api.writes != 1 || !m.selection.active ||
		m.selection.ready || api.last.ExpectedSelectionRevision != 7 ||
		api.last.ExpectedConfigRevision != 9 || api.last.ExpectedGenerationID == nil ||
		*api.last.ExpectedGenerationID != 14 ||
		api.last.ExpectedDeclarationSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("CAS proposal lost identity or did not re-read: %+v", m.selection)
	}
	m, _ = updated(t, m, readback())
	if !m.selection.ready || m.selection.result.targetRef.Kind != domain.TargetGlobalURLTest ||
		m.selection.result.expected.ExpectedSelectionRevision != 8 ||
		m.selection.result.live != "matches durable intent" || api.writes != 1 {
		t.Fatalf("selector readback not reconciled: %+v", m.selection)
	}
	view := m.View()
	if strings.Contains(view, "native-secret-a") || strings.Contains(view, "future-selector") {
		t.Fatal("runtime selector tags reached terminal")
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.selection.pending != nil || api.writes != 1 ||
		!strings.Contains(m.View(), "Already selected") {
		t.Fatal("selecting current candidate attempted a duplicate write")
	}
}

func TestSelectorConflictAndPostCommitErrorAlwaysReloadWithoutRetry(t *testing.T) {
	api := &selectionSwitchAPI{observationsTestAPI: &observationsTestAPI{
		fakeAPI: &fakeAPI{}, selection: selectorFixture(),
	}}
	m := enterSelectionTest(t, api)
	m, _ = selectionKey(t, m, "j")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m, write := selectionKey(t, m, "y")
	// Another client commits while this UI's user is confirming.
	api.selection.SelectionRevision++
	api.selection.Target = domain.TargetRef{Kind: domain.TargetSpecificNode,ProfileID:"profile-1",NodeID:"node-b"}
	m, reread := updated(t, m, write())
	if api.writes != 1 || reread == nil {
		t.Fatal("conflicted CAS did not issue a readback")
	}
	m, _ = updated(t, m, reread())
	if !m.selection.ready || m.selection.result.expected.ExpectedSelectionRevision != 8 ||
		!strings.Contains(m.View(), "No auto-retry") || api.writes != 1 {
		t.Fatal("409 did not discard proposal and update observed selection")
	}
	m, _ = selectionKey(t, m, "j")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	api.err = errors.New("token=ULTRA_SECRET")
	api.commitOnError = true
	m, write = selectionKey(t, m, "y")
	if write == nil {
		t.Fatal("expected second checked write")
	}
	m, reread = updated(t, m, write())
	if reread == nil {
		t.Fatal("post-commit uncertain result did not schedule readback")
	}
	m, _ = updated(t, m, reread())
	if api.writes != 2 || m.selection.result.expected.ExpectedSelectionRevision != 9 ||
		m.selection.result.live != "MISMATCH (durable intent not live)" ||
		!strings.Contains(m.View(), "No auto-retry") ||
		strings.Contains(fmt.Sprintf("%+v", m.selection), "ULTRA_SECRET") {
		t.Fatalf("post-commit uncertainty hidden: %+v", m.selection)
	}
}

func TestSelectorInvalidAndTruncatedSnapshotsFailClosed(t *testing.T) {
	snapshot := selectorFixture()
	snapshot.Candidates[1].Kind = domain.TargetDirect
	if _, err := projectSelectionObservation(snapshot); err == nil {
		t.Fatal("unsupported selector kind was treated as a valid candidate")
	}
	snapshot = selectorFixture()
	snapshot.Candidates = append(snapshot.Candidates, snapshot.Candidates[0])
	snapshot.CandidateCount++
	if _, err := projectSelectionObservation(snapshot); err == nil {
		t.Fatal("duplicate candidate accepted")
	}
	snapshot = selectorFixture()
	snapshot.CandidateCount = 3
	if _, err := projectSelectionObservation(snapshot); err == nil {
		t.Fatal("mismatched total accepted")
	}
	snapshot = selectorFixture()
	snapshot.CandidatesTruncated = true
	snapshot.CandidateCount = 160
	projected, err := projectSelectionObservation(snapshot)
	if err != nil || projected.editable || !projected.truncated {
		t.Fatalf("truncated candidates should be display-only: %+v %v", projected, err)
	}
	snapshot = selectorFixture()
	snapshot.AppliedGenerationID = nil
	projected, err = projectSelectionObservation(snapshot)
	if err != nil || projected.editable {
		t.Fatal("selection without applied generation was editable")
	}
	snapshot = selectorFixture()
	snapshot.DeclarationSHA256 = "not-a-digest"
	projected, err = projectSelectionObservation(snapshot)
	if err != nil || projected.editable {
		t.Fatal("unbound selector was editable")
	}
	snapshot = selectorFixture()
	snapshot.Candidates[1].NodeID = strings.Repeat("x", maxSelectionIDBytes+1)
	if _, err := projectSelectionObservation(snapshot); err == nil {
		t.Fatal("oversized stable ID reached interactive picker")
	}
}

func TestSelectorStaleResponseAndNarrowScreenSafety(t *testing.T) {
	api := &selectionSwitchAPI{observationsTestAPI: &observationsTestAPI{
		fakeAPI: &fakeAPI{}, selection: selectorFixture(),
	}}
	m := NewModel(context.Background(), api)
	m, stale := selectionKey(t, m, "5")
	m, _ = selectionKey(t, m, "1")
	m, fresh := selectionKey(t, m, "5")
	if fresh == nil {
		t.Fatal("reentry did not schedule a new selection read")
	}
	m, _ = updated(t, m, stale())
	if m.selection.ready {
		t.Fatal("out-of-page stale response resurrected a proposal")
	}
	m, _ = updated(t, m, fresh())
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 38, Height: 9})
	for i := 0; i < 3; i++ {
		m, _ = selectionKey(t, m, "j")
	}
	if m.selection.selected != 3 {
		t.Fatal("candidate cursor did not advance")
	}
	lines := strings.Split(strings.TrimSuffix(m.View(), "\n"), "\n")
	if len(lines) > 9 {
		t.Fatalf("narrow terminal height overflow: %d", len(lines))
	}
	found := false
	for _, line := range lines {
		if runeWidthOfLine(line) > 38 {
			t.Fatalf("narrow terminal width overflow: %q", line)
		}
		if strings.Contains(line, "custom_urltest") {
			found = true
		}
	}
	if !found {
		t.Fatalf("focused candidate scrolled out of view: %q", m.View())
	}
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m, _ = selectionKey(t, m, "q")
	if !m.quitting || api.writes != 0 {
		t.Fatal("quitting with an unconfirmed proposal sent a write")
	}
}

func TestSelectorMalformedSuccessfulWriteTriggersReconciliation(t *testing.T) {
	api := &selectionSwitchAPI{
		observationsTestAPI: &observationsTestAPI{fakeAPI: &fakeAPI{}, selection: selectorFixture()},
		spoofResponse: true,
	}
	m := enterSelectionTest(t, api)
	m, _ = selectionKey(t, m, "j")
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m, write := selectionKey(t, m, "y")
	m, reread := updated(t, m, write())
	m, _ = updated(t, m, reread())
	if api.writes != 1 || !strings.Contains(m.View(), "No auto-retry") ||
		m.selection.result.expected.ExpectedSelectionRevision != 8 {
		t.Fatalf("malformed success failed to trigger readback: %+v", m.selection)
	}
}
