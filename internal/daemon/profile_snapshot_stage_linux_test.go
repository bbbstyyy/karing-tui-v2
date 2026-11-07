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

func TestProfileDeclarationStageRequiresAcknowledgedPreviewAndNeverApplies(t *testing.T) {
	store, snapshotID, rev, _ := previewFixture(t, false)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()
	path := "/v1/profiles/profile-a/declaration/"
	status, body := requestProfileAPI(t, api.URL, http.MethodPost, path+"preview",
		apiv1.ProfileDeclarationPreviewRequest{SnapshotID: snapshotID, ExpectedDeclarationRevision: rev})
	if status != 200 {
		t.Fatalf("preview status=%d %s", status, body)
	}
	var preview apiv1.ProfileDeclarationPreviewResponse
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.SourceRevision == 0 {
		t.Fatal("preview omitted source revision guard")
	}
	req := apiv1.ProfileDeclarationStageRequest{SnapshotID: snapshotID, ExpectedSourceRevision: preview.SourceRevision, ExpectedDeclarationRevision: rev,
		CandidateSHA256: preview.CandidateSHA256, RuntimeOverlaySHA256: preview.RuntimeOverlaySHA256}
	bad := req
	bad.CandidateSHA256 = strings.Repeat("0", 64)
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", bad)
	if status != http.StatusConflict {
		t.Fatalf("wrong candidate stage status=%d", status)
	}
	current, err := store.CurrentDeclaration(context.Background())
	if err != nil || current.Revision != rev {
		t.Fatalf("invalid hash staged declaration: %+v %v", current, err)
	}
	status, body = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", req)
	if status != http.StatusCreated || bytes.Contains(body, []byte("SUPER_PRIVATE_PASSWORD")) {
		t.Fatalf("stage status=%d response=%s", status, body)
	}
	var result apiv1.ProfileDeclarationStageResponse
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.DeclarationRevision != rev+1 || result.DeclarationSHA256 != preview.CandidateSHA256 || result.Applied || result.CoreValidated {
		t.Fatalf("unexpected staged declaration: %+v", result)
	}
	runtime, err := store.Snapshot(context.Background())
	if err != nil || runtime.Revision != 0 {
		t.Fatalf("stage modified runtime: %+v %v", runtime, err)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", req)
	if status != http.StatusConflict {
		t.Fatalf("duplicate stage status=%d", status)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", map[string]any{
		"snapshot_id": snapshotID, "expected_source_revision": preview.SourceRevision, "expected_declaration_revision": rev,
		"candidate_sha256": req.CandidateSHA256, "runtime_overlay_sha256": req.RuntimeOverlaySHA256, "extra": true,
	})
	if status != http.StatusBadRequest {
		t.Fatalf("extra stage field status=%d", status)
	}
	missingRevision := req
	missingRevision.ExpectedSourceRevision = 0
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", missingRevision)
	if status != http.StatusBadRequest {
		t.Fatalf("missing source revision stage status=%d", status)
	}
}

func TestProfileDeclarationStageRejectsChangedOverlayAndSnapshot(t *testing.T) {
	store, snapshotID, rev, nodeID := previewFixture(t, false)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()
	path := "/v1/profiles/profile-a/declaration/"
	status, body := requestProfileAPI(t, api.URL, http.MethodPost, path+"preview",
		apiv1.ProfileDeclarationPreviewRequest{SnapshotID: snapshotID, ExpectedDeclarationRevision: rev})
	if status != 200 {
		t.Fatal(status, string(body))
	}
	var preview apiv1.ProfileDeclarationPreviewResponse
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	req := apiv1.ProfileDeclarationStageRequest{SnapshotID: snapshotID, ExpectedSourceRevision: preview.SourceRevision, ExpectedDeclarationRevision: rev,
		CandidateSHA256: preview.CandidateSHA256, RuntimeOverlaySHA256: preview.RuntimeOverlaySHA256}
	if _, err := store.CommitProfileNodeOverlay(context.Background(), 0, profile.NodeOverlay{
		ProfileID: "profile-a", NodeID: nodeID, Disabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", req)
	if status != http.StatusConflict {
		t.Fatalf("stale overlay stage status=%d", status)
	}
	current, err := store.CurrentDeclaration(context.Background())
	if err != nil || current.Revision != rev {
		t.Fatalf("stale overlay advanced declaration: %+v %v", current, err)
	}
	_, err = store.CommitProfileSnapshot(context.Background(), storage.ProfileSnapshotCandidate{
		ProfileID: "profile-a", SourceKind: "sing-box", SourceSHA256: strings.Repeat("e", 64),
		Nodes: []profile.SourceNode{{SourceKey: "proxy-a", SourceName: "Updated", PayloadJSON: []byte(`{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":9082}`)}},
	}, storage.ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", req)
	if status != http.StatusConflict {
		t.Fatalf("stale snapshot stage status=%d", status)
	}
}

func TestProfileDeclarationStageRejectsDisabledSourceAndMalformedDigest(t *testing.T) {
	store, snapshotID, rev, _ := previewFixture(t, false)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()
	path := "/v1/profiles/profile-a/declaration/"
	status, body := requestProfileAPI(t, api.URL, http.MethodPost, path+"preview",
		apiv1.ProfileDeclarationPreviewRequest{SnapshotID: snapshotID, ExpectedDeclarationRevision: rev})
	if status != http.StatusOK {
		t.Fatalf("preview status=%d %s", status, body)
	}
	var preview apiv1.ProfileDeclarationPreviewResponse
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	request := apiv1.ProfileDeclarationStageRequest{
		SnapshotID: snapshotID, ExpectedSourceRevision: preview.SourceRevision, ExpectedDeclarationRevision: rev,
		CandidateSHA256: preview.CandidateSHA256, RuntimeOverlaySHA256: preview.RuntimeOverlaySHA256,
	}
	request.CandidateSHA256 = strings.ToUpper(request.CandidateSHA256)
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", request)
	if status != http.StatusBadRequest {
		t.Fatalf("uppercase digest should be bad request; got %d", status)
	}
	request.CandidateSHA256 = preview.CandidateSHA256
	source, err := store.ProfileSource(context.Background(), "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	updated := source.Spec
	updated.Enabled = false
	if _, err := store.CommitProfileSource(context.Background(), source.Revision, updated); err != nil {
		t.Fatal(err)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"preview",
		apiv1.ProfileDeclarationPreviewRequest{SnapshotID: snapshotID, ExpectedDeclarationRevision: rev})
	if status != http.StatusConflict {
		t.Fatalf("disabled source preview status=%d", status)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", request)
	if status != http.StatusConflict {
		t.Fatalf("disabled source stage status=%d", status)
	}
	declaration, err := store.CurrentDeclaration(context.Background())
	if err != nil || declaration.Revision != rev {
		t.Fatalf("disabled source changed declaration: %+v %v", declaration, err)
	}
}
