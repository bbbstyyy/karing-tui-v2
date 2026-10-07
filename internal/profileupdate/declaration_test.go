package profileupdate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestCommitSingBoxSnapshotToDeclarationUpdatesExactProfileRevision(t *testing.T) {
	ctx := context.Background()
	store, _ := newDeclarationUpdateStore(t, ctx)
	defer store.Close()

	first, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "source-1", []byte(`{
  "outbounds":[{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}]
}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Nodes) != 1 {
		t.Fatalf("first nodes = %+v", first.Nodes)
	}
	nodeID := first.Nodes[0].NodeID

	baseDocument := declarationForProfileNode("profile-a", nodeID, 8080)
	base, err := store.CommitDeclaration(ctx, 0, baseDocument, "test")
	if err != nil {
		t.Fatal(err)
	}
	if base.Revision != 1 {
		t.Fatalf("base declaration revision = %d", base.Revision)
	}

	second, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "source-2", []byte(`{
  "outbounds":[{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":9090}]
}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Nodes[0].NodeID != nodeID {
		t.Fatalf("profile update changed node ID: %q -> %q", nodeID, second.Nodes[0].NodeID)
	}

	updated, err := CommitSingBoxSnapshotToDeclaration(
		ctx,
		store,
		"profile-a",
		second.Commit.Snapshot.ID,
		base.Revision,
	)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision.Revision != 2 {
		t.Fatalf("updated declaration revision = %d", updated.Revision.Revision)
	}
	wantSource := fmt.Sprintf("profile-snapshot/%d", second.Commit.Snapshot.ID)
	if updated.Revision.Source != wantSource {
		t.Fatalf("declaration source = %q, want %q", updated.Revision.Source, wantSource)
	}
	if len(updated.Replacement.Impact.RetainedNodeIDs) != 1 ||
		updated.Replacement.Impact.RetainedNodeIDs[0] != nodeID ||
		len(updated.Replacement.Impact.AddedNodeIDs) != 0 ||
		len(updated.Replacement.Impact.RemovedNodeIDs) != 0 {
		t.Fatalf("replacement impact = %+v", updated.Replacement.Impact)
	}
	model, err := declaration.ParseV1(updated.Revision.DocumentJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 1 || model.Nodes[0].NodeID != nodeID || model.Nodes[0].Port != 9090 {
		t.Fatalf("updated declaration nodes = %+v", model.Nodes)
	}
}

func TestCommitSingBoxSnapshotToDeclarationRefusesRemovedReferencedNode(t *testing.T) {
	ctx := context.Background()
	store, _ := newDeclarationUpdateStore(t, ctx)
	defer store.Close()

	first, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "source-1", []byte(`{
  "outbounds":[{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}]
}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	nodeID := first.Nodes[0].NodeID
	base, err := store.CommitDeclaration(ctx, 0, declarationForProfileNode("profile-a", nodeID, 8080), "test")
	if err != nil {
		t.Fatal(err)
	}

	replacedSource, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "source-2", []byte(`{
  "outbounds":[{"type":"http","tag":"proxy-b","server":"127.0.0.1","server_port":9090}]
}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if replacedSource.Nodes[0].NodeID == nodeID {
		t.Fatalf("changed source tag reused removed node ID %q", nodeID)
	}

	result, err := CommitSingBoxSnapshotToDeclaration(
		ctx,
		store,
		"profile-a",
		replacedSource.Commit.Snapshot.ID,
		base.Revision,
	)
	if !errors.Is(err, declaration.ErrProfileNodeReplacementInvalid) {
		t.Fatalf("removed referenced node error = %v", err)
	}
	if len(result.Replacement.Impact.RemovedNodeIDs) != 1 ||
		result.Replacement.Impact.RemovedNodeIDs[0] != nodeID ||
		len(result.Replacement.Impact.AddedNodeIDs) != 1 {
		t.Fatalf("blocked replacement impact = %+v", result.Replacement.Impact)
	}

	current, err := store.CurrentDeclaration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != base.Revision || current.SHA256 != base.SHA256 {
		t.Fatalf("blocked profile replacement advanced declaration: %+v", current)
	}
}

func TestCommitSingBoxSnapshotToDeclarationRequiresExistingBase(t *testing.T) {
	ctx := context.Background()
	store, _ := newDeclarationUpdateStore(t, ctx)
	defer store.Close()

	imported, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "source-1", []byte(`{
  "outbounds":[{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}]
}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = CommitSingBoxSnapshotToDeclaration(
		ctx,
		store,
		"profile-a",
		imported.Commit.Snapshot.ID,
		0,
	)
	if !errors.Is(err, ErrNoBaseDeclaration) {
		t.Fatalf("zero-revision declaration update error = %v", err)
	}
}

func declarationForProfileNode(profileID, nodeID string, port uint16) []byte {
	return []byte(fmt.Sprintf(`{
  "schema_version":1,
  "log_level":"warn",
  "nodes":[{
    "profile_id":%q,
    "node_id":%q,
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{"kind":"specific_node","profile_id":%q,"node_id":%q}],
      "default":{"kind":"specific_node","profile_id":%q,"node_id":%q}
    },
    "custom":[]
  },
  "routing":{
    "custom":[],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":{"kind":"direct"}
  },
  "dns":{
    "profiles":[{
      "id":"outbound",
      "role":"outbound",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":53
    }],
    "outbound_profile_id":"outbound"
  }
}`, profileID, nodeID, port, profileID, nodeID, profileID, nodeID))
}

func newDeclarationUpdateStore(t *testing.T, ctx context.Context) (*storage.Store, string) {
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

func TestDeclarationProfileSourceIsStorageSafe(t *testing.T) {
	source := fmt.Sprintf("profile-snapshot/%d", int64(42))
	if strings.ContainsAny(source, " 	
") {
		t.Fatalf("unexpected unsafe declaration source %q", source)
	}
}
