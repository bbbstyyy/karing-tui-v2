//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
	"github.com/bbbstyyy/karing-tui-v2/internal/tui"
)

// Exercises the real local Unix API rather than a TUI fake. The test uses a
// safe in-process daemon with a real SQLite declaration, no Core executable,
// no TUN and no external subscription network calls. The existing pinned-Core
// integration test separately proves authenticated traffic after Apply.
func mvpTUIUnixServer(t *testing.T, store *storage.Store) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "daemon.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{
		Handler:           (&Server{started: time.Now().UTC()}).handler(store, nil),
		ReadHeaderTimeout: 3 * time.Second,
	}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		if err := <-done; err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("Unix API server shutdown: %v", err)
		}
	})
	return socket
}

func mvpTUIKey(ch rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{ch}}
}

func mvpTUIUpdate(t *testing.T, m tui.Model, message tea.Msg) (tui.Model, tea.Cmd) {
	t.Helper()
	updated, cmd := m.Update(message)
	next, ok := updated.(tui.Model)
	if !ok {
		t.Fatal("TUI Update did not return its model")
	}
	return next, cmd
}

// A Bubble Tea command can return a BatchMsg, e.g. the real TUI Init
// concurrently requests status and profiles. Drive the batch to completion
// without creating a mock API or bypassing the real Unix client transport.
func mvpTUIRun(t *testing.T, m tui.Model, cmd tea.Cmd) tui.Model {
	t.Helper()
	if cmd == nil {
		return m
	}
	switch msg := cmd().(type) {
	case tea.BatchMsg:
		for _, sub := range msg {
			m = mvpTUIRun(t, m, sub)
		}
		return m
	default:
		next, follow := mvpTUIUpdate(t, m, msg)
		return mvpTUIRun(t, next, follow)
	}
}

func mvpTUIOpenAcceptedNodes(t *testing.T, socket string, nodeID string) tui.Model {
	t.Helper()
	m := tui.NewModel(context.Background(), client.New(socket))
	m = mvpTUIRun(t, m, m.Init())
	if !strings.Contains(m.View(), "Dashboard") {
		t.Fatal("TUI did not load actual daemon status")
	}
	var cmd tea.Cmd
	m, cmd = mvpTUIUpdate(t, m, mvpTUIKey('3'))
	m = mvpTUIRun(t, m, cmd)
	view := m.View()
	if !strings.Contains(view, "Nodes for source-a") || !strings.Contains(view, nodeID) {
		t.Fatalf("current accepted node was not read from Unix daemon: %q", view)
	}
	return m
}

func TestMVPRealUnixTUIExplicitSelectedRebindStagesOnly(t *testing.T) {
	store, oldID, selectedID, snapshotID, baseRevision, _ := selectedRebindAPIFixture(t)
	defer store.Close()
	socket := mvpTUIUnixServer(t, store)
	m := mvpTUIOpenAcceptedNodes(t, socket, selectedID)
	ctx := context.Background()
	base, err := store.CurrentDeclaration(ctx)
	if err != nil || base.Revision != baseRevision {
		t.Fatalf("initial durable declaration: %+v %v", base, err)
	}
	// A removed selected node cannot be silently accepted by ordinary 'b'.
	var cmd tea.Cmd
	m, cmd = mvpTUIUpdate(t, m, mvpTUIKey('2'))
	if cmd != nil {
		t.Fatal("unexpected source navigation I/O")
	}
	m, cmd = mvpTUIUpdate(t, m, mvpTUIKey('b'))
	if cmd == nil {
		t.Fatal("ordinary staging should attempt a read-only preview")
	}
	m = mvpTUIRun(t, m, cmd)
	if !strings.Contains(m.View(), "no write sent") {
		t.Fatal("removed selected node was silently accepted without explicit choice")
	}
	if now, err := store.CurrentDeclaration(ctx); err != nil || now.Revision != baseRevision {
		t.Fatalf("failed ordinary preview mutated declaration: %+v %v", now, err)
	}
	// Return to the accepted Nodes page and explicitly select the replacement
	// via 'm'. The TUI must bind the exact source and node to the preview.
	m, cmd = mvpTUIUpdate(t, m, mvpTUIKey('3'))
	m = mvpTUIRun(t, m, cmd)
	m, cmd = mvpTUIUpdate(t, m, mvpTUIKey('m'))
	if cmd == nil {
		t.Fatal("explicit Nodes selection failed to schedule preview")
	}
	if now, err := store.CurrentDeclaration(ctx); err != nil || now.Revision != baseRevision {
		t.Fatalf("read-only selected preview staged a revision: %+v %v", now, err)
	}
	m = mvpTUIRun(t, m, cmd)
	view := m.View()
	for _, required := range []string{
		"EXPLICIT replacement CurrentSelected ID:",
		selectedID,
		"Node diff: +1 added  -1 removed",
		"CONFIRM Stage only",
		"NOT Core Check/Apply",
	} {
		if !strings.Contains(view, required) {
			t.Fatalf("TUI refused or hid explicit approval evidence %q: %q", required, view)
		}
	}
	if strings.Contains(view, oldID) || strings.Contains(view, "password") {
		t.Fatal("untrusted or retired identity leaked in TUI approval")
	}
	m, cmd = mvpTUIUpdate(t, m, mvpTUIKey('y'))
	if cmd == nil {
		t.Fatal("operator approval did not issue a single CAS Stage")
	}
	m = mvpTUIRun(t, m, cmd)
	if !strings.Contains(m.View(), "Verified staged declaration rev") ||
		!strings.Contains(m.View(), "Applied/LKG unchanged") {
		t.Fatalf("TUI did not verify stage-only durable readback: %q", m.View())
	}
	committed, err := store.CurrentDeclaration(ctx)
	if err != nil || committed.Revision != baseRevision+1 || committed.SHA256 == base.SHA256 {
		t.Fatalf("explicit UI stage did not commit exact new declaration: %+v %v", committed, err)
	}
	if !strings.Contains(string(committed.DocumentJSON), selectedID) ||
		strings.Contains(string(committed.DocumentJSON), oldID) {
		t.Fatal("explicit replacement declaration retained the removed selected node")
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil || snapshot.Revision != 0 ||
		snapshot.AppliedGenerationID != nil || snapshot.LastKnownGoodGenerationID != nil {
		t.Fatalf("TUI declaration stage implicitly applied Core: %+v %v", snapshot, err)
	}
	source, err := store.ProfileSource(ctx, "source-a")
	if err != nil || source.CurrentSnapshotID == nil || *source.CurrentSnapshotID != snapshotID {
		t.Fatalf("TUI stage changed accepted source snapshot: %+v %v", source, err)
	}
	m, cmd = mvpTUIUpdate(t, m, mvpTUIKey('y'))
	if cmd != nil {
		t.Fatal("repeated y bypassed one-shot stage confirmation")
	}
}

func TestMVPRealUnixTUISelectionIntentRaceFailsClosed(t *testing.T) {
	store, oldID, selectedID, _, baseRevision, _ := selectedRebindAPIFixture(t)
	defer store.Close()
	socket := mvpTUIUnixServer(t, store)
	m := mvpTUIOpenAcceptedNodes(t, socket, selectedID)
	m, previewCmd := mvpTUIUpdate(t, m, mvpTUIKey('m'))
	if previewCmd == nil {
		t.Fatal("missing real API preview for selected node")
	}
	m = mvpTUIRun(t, m, previewCmd)
	if !strings.Contains(m.View(), "EXPLICIT replacement CurrentSelected ID:") {
		t.Fatal("real API preview not admitted")
	}
	// A legacy or another operator may create a persisted current selector
	// AFTER the preview but BEFORE user confirmation. The SQLite guard must
	// reject the exact old preview digest, never overwrite that intent.
	intentJSON, err := json.Marshal(domain.TargetRef{
		Kind: domain.TargetSpecificNode, ProfileID: "source-a", NodeID: oldID,
	})
	if err != nil {
		t.Fatal(err)
	}
	original, err := store.SetCurrentSelectionIntent(context.Background(), intentJSON)
	if err != nil {
		t.Fatal(err)
	}
	m, stageCmd := mvpTUIUpdate(t, m, mvpTUIKey('y'))
	if stageCmd == nil {
		t.Fatal("test did not exercise guarded stage after selection race")
	}
	m = mvpTUIRun(t, m, stageCmd)
	if !strings.Contains(m.View(), "NEVER auto-retry") ||
		strings.Contains(m.View(), "Verified staged") {
		t.Fatalf("selection race reported staged success: %q", m.View())
	}
	current, err := store.CurrentDeclaration(context.Background())
	if err != nil || current.Revision != baseRevision {
		t.Fatalf("rejected selection race changed declaration: %+v %v", current, err)
	}
	intent, present, err := store.CurrentSelectionIntent(context.Background())
	if err != nil || !present || intent.Revision != original.Revision ||
		string(intent.TargetJSON) != string(intentJSON) {
		t.Fatalf("selection intent overwritten by stale TUI stage: %+v %t %v", intent, present, err)
	}
	for i := 0; i < 2; i++ {
		m, again := mvpTUIUpdate(t, m, mvpTUIKey('y'))
		if again != nil {
			t.Fatal("failed/uncertain selected Stage automatically repeated")
		}
	}
}
