//go:build linux

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func previewFixture(t *testing.T, bindSelection bool) (*storage.Store, int64, uint64, string) {
	t.Helper()
	ctx := context.Background()
	store := newDaemonProfileMetadataStore(t, ctx)
	_, err := store.CommitProfileSource(ctx, 0, profile.SourceSpec{
		ProfileID: "profile-a", Format: profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationFile, Location: "/tmp/profile-preview.json",
		Fetch: profile.FetchPolicy{Mode: profile.FetchDirect}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.CommitProfileSnapshot(ctx, storage.ProfileSnapshotCandidate{
		ProfileID: "profile-a", SourceKind: "sing-box", SourceSHA256: strings.Repeat("a", 64),
		Nodes: []profile.SourceNode{{
			SourceKey: "proxy-a", SourceName: "Alpha",
			PayloadJSON: []byte("{\"type\":\"http\",\"tag\":\"proxy-a\",\"server\":\"127.0.0.1\",\"server_port\":9080,\"username\":\"privateuser\",\"password\":\"SUPER_PRIVATE_PASSWORD\"}"),
		}},
	}, storage.ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	nodeID := snapshot.Snapshot.Nodes[0].Identity.NodeID
	declarationJSON := declarationAPIMinimalDocument()
	if bindSelection {
		// Use exact quoted JSON tokens to avoid changing unrelated fields.
		declarationJSON = bytes.ReplaceAll(declarationAPIMinimalDocument(), []byte("\"p1\""), []byte("\"profile-a\""))
		declarationJSON = bytes.ReplaceAll(declarationJSON, []byte("\"n1\""), []byte("\""+nodeID+"\""))
	}
	base, err := store.CommitDeclaration(ctx, 0, declarationJSON, "test:preview")
	if err != nil {
		t.Fatal(err)
	}
	return store, snapshot.Snapshot.ID, base.Revision, nodeID
}

func TestProfileDeclarationPreviewHasNoWritesOrCredentialDisclosure(t *testing.T) {
	store, snapshotID, rev, nodeID := previewFixture(t, false)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()
	path := "/v1/profiles/profile-a/declaration/preview"
	status, body := requestProfileAPI(t, api.URL, http.MethodPost, path, apiv1.ProfileDeclarationPreviewRequest{
		SnapshotID: snapshotID, ExpectedDeclarationRevision: rev,
	})
	if status != 200 || bytes.Contains(body, []byte("SUPER_PRIVATE_PASSWORD")) || bytes.Contains(body, []byte("privateuser")) {
		t.Fatalf("unsafe profile preview: %d %s", status, body)
	}
	var result apiv1.ProfileDeclarationPreviewResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.ProfileID != "profile-a" || result.SnapshotID != snapshotID || result.BaseDeclarationRevision != rev ||
		result.SnapshotNodeCount != 1 || result.EffectiveNodeCount != 1 || result.AddedNodeCount != 1 ||
		result.RemovedNodeCount != 0 || result.RetainedNodeCount != 0 || len(result.CandidateSHA256) != 64 ||
		len(result.RuntimeOverlaySHA256) != 64 || result.CoreValidated || result.Applied {
		t.Fatalf("unexpected preview result: %+v", result)
	}
	before, err := store.CurrentDeclaration(context.Background())
	if err != nil || before.Revision != rev {
		t.Fatalf("preview changed declaration: %+v %v", before, err)
	}
	runtime, err := store.Snapshot(context.Background())
	if err != nil || runtime.Revision != 0 {
		t.Fatalf("preview advanced runtime generation: %+v %v", runtime, err)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path, apiv1.ProfileDeclarationPreviewRequest{
		SnapshotID: snapshotID, ExpectedDeclarationRevision: rev + 1,
	})
	if status != http.StatusConflict {
		t.Fatalf("stale declaration preview status = %d", status)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path, map[string]any{
		"snapshot_id": snapshotID, "expected_declaration_revision": rev, "unknown": true,
	})
	if status != http.StatusBadRequest {
		t.Fatalf("unknown field preview status=%d", status)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path, apiv1.ProfileDeclarationPreviewRequest{})
	if status != http.StatusBadRequest {
		t.Fatalf("missing IDs preview status=%d", status)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, "/v1/profiles/absent/declaration/preview",
		apiv1.ProfileDeclarationPreviewRequest{SnapshotID: snapshotID, ExpectedDeclarationRevision: rev})
	if status != http.StatusNotFound {
		t.Fatalf("missing profile preview status=%d", status)
	}
	// Replacing the accepted snapshot invalidates the previously previewable ID.
	next, err := store.CommitProfileSnapshot(context.Background(), storage.ProfileSnapshotCandidate{
		ProfileID: "profile-a", SourceKind: "sing-box", SourceSHA256: strings.Repeat("b", 64),
		Nodes: []profile.SourceNode{{SourceKey: "proxy-a", SourceName: "New Name",
			PayloadJSON: []byte("{\"type\":\"http\",\"tag\":\"proxy-a\",\"server\":\"127.0.0.1\",\"server_port\":9090}")}},
	}, storage.ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if next.Snapshot.Nodes[0].Identity.NodeID != nodeID {
		t.Fatal("refresh lost stable identity")
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path, apiv1.ProfileDeclarationPreviewRequest{
		SnapshotID: snapshotID, ExpectedDeclarationRevision: rev,
	})
	if status != http.StatusConflict {
		t.Fatalf("stale snapshot preview status=%d", status)
	}
}

func TestProfileDeclarationPreviewRejectsDisabledRequiredNode(t *testing.T) {
	store, snapshotID, rev, nodeID := previewFixture(t, true)
	defer store.Close()
	_, err := store.CommitProfileNodeOverlay(context.Background(), 0, profile.NodeOverlay{
		ProfileID: "profile-a", NodeID: nodeID, Disabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()
	status, body := requestProfileAPI(t, api.URL, http.MethodPost, "/v1/profiles/profile-a/declaration/preview",
		apiv1.ProfileDeclarationPreviewRequest{SnapshotID: snapshotID, ExpectedDeclarationRevision: rev})
	if status != http.StatusUnprocessableEntity || bytes.Contains(body, []byte("SUPER_PRIVATE_PASSWORD")) {
		t.Fatalf("invalid selected node preview: %d %s", status, body)
	}
	current, err := store.CurrentDeclaration(context.Background())
	if err != nil || current.Revision != rev {
		t.Fatalf("failed preview advanced declaration: %+v %v", current, err)
	}
}
