package profileupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestCommitBasicSingBoxProfilePreservesNodeIDAcrossPayloadUpdate(t *testing.T) {
	ctx := context.Background()
	store, path := newProfileUpdateStore(t, ctx)

	firstData := []byte(`{
  "outbounds":[
    {"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}
  ],
  "route":{"rules":[{"domain_suffix":["example.com"],"outbound":"proxy-a"}]}
}`)
	first, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "etag-1", firstData, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Nodes) != 1 || first.Nodes[0].Port != 8080 {
		t.Fatalf("first nodes = %+v", first.Nodes)
	}
	firstNodeID := first.Nodes[0].NodeID
	if firstNodeID == "" {
		t.Fatal("first node ID is empty")
	}

	secondData := []byte(`{
  "outbounds":[
    {"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":9090}
  ]
}`)
	second, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "etag-2", secondData, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Nodes) != 1 || second.Nodes[0].Port != 9090 {
		t.Fatalf("second nodes = %+v", second.Nodes)
	}
	if second.Nodes[0].NodeID != firstNodeID {
		t.Fatalf("payload update changed stable NodeID: first=%q second=%q", firstNodeID, second.Nodes[0].NodeID)
	}

	previous, ok, err := store.PreviousProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || previous.ID != first.Commit.Snapshot.ID {
		t.Fatalf("previous snapshot = %+v ok=%v", previous, ok)
	}
	previousNodes, err := MaterializeBasicSingBoxSnapshot(previous)
	if err != nil {
		t.Fatal(err)
	}
	if len(previousNodes) != 1 || previousNodes[0].Port != 8080 || previousNodes[0].NodeID != firstNodeID {
		t.Fatalf("previous materialized nodes = %+v", previousNodes)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	current, ok, err := reopened.CurrentProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("current profile snapshot disappeared after reopen")
	}
	reloadedNodes, err := MaterializeBasicSingBoxSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloadedNodes) != 1 || reloadedNodes[0].Port != 9090 || reloadedNodes[0].NodeID != firstNodeID {
		t.Fatalf("reloaded nodes = %+v", reloadedNodes)
	}
}

func TestCommitBasicSingBoxProfileBlocksUnsupportedProtocolWithoutAdvancingSnapshot(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	valid, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "v1", []byte(`{
  "outbounds":[{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}]
}`), Options{})
	if err != nil {
		t.Fatal(err)
	}

	blocked, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "v2", []byte(`{
  "outbounds":[
    {"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":9090},
    {"type":"vmess","tag":"unsupported","server":"example.com","server_port":443,"uuid":"00000000-0000-0000-0000-000000000000"}
  ]
}`), Options{})
	if !errors.Is(err, ErrImportBlocked) {
		t.Fatalf("blocked import error = %v", err)
	}
	if !blocked.Analysis.HasBlockingDiagnostics() {
		t.Fatalf("blocked import lost diagnostics: %+v", blocked.Analysis.Diagnostics)
	}

	current, ok, err := store.CurrentProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current.ID != valid.Commit.Snapshot.ID || current.SourceRevision != "v1" {
		t.Fatalf("blocked import advanced snapshot: %+v ok=%v", current, ok)
	}
}

func TestCommitBasicSingBoxProfileRequiresExplicitEmptyConfirmation(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	data := []byte(`{
  "outbounds":[{"type":"direct","tag":"direct"}]
}`)
	_, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "empty-1", data, Options{})
	if !errors.Is(err, storage.ErrEmptyProfileSnapshot) {
		t.Fatalf("implicit empty import error = %v", err)
	}
	result, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "empty-2", data, Options{AllowEmpty: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 0 || len(result.Commit.Snapshot.Nodes) != 0 {
		t.Fatalf("explicit empty snapshot unexpectedly materialized nodes: %+v", result)
	}
}

func newProfileUpdateStore(t *testing.T, ctx context.Context) (*storage.Store, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	store, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	return store, path
}
