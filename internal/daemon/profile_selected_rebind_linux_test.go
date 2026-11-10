//go:build linux

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func selectedRebindAPIFixture(t *testing.T) (*storage.Store, string, string, int64, uint64, uint64) {
	t.Helper()
	ctx := context.Background()
	store := newDaemonProfileMetadataStore(t, ctx)
	source, err := store.CommitProfileSource(ctx, 0, profile.SourceSpec{
		ProfileID: "source-a", Format: profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationFile, Location: "/tmp/proxy-source.json",
		Fetch: profile.FetchPolicy{Mode: profile.FetchDirect}, Enabled: true,
	})
	if err != nil { t.Fatal(err) }
	first, err := store.CommitProfileSnapshot(ctx, storage.ProfileSnapshotCandidate{
		ProfileID: "source-a", SourceKind: "sing-box", SourceSHA256: strings.Repeat("a", 64),
		Nodes: []profile.SourceNode{{
			SourceKey: "old-node", SourceName: "Old",
			PayloadJSON: []byte("{\"type\":\"http\",\"tag\":\"old-node\",\"server\":\"127.0.0.1\",\"server_port\":8101}"),
		}},
	}, storage.ProfileSnapshotCommitOptions{})
	if err != nil { t.Fatal(err) }
	oldID := first.Snapshot.Nodes[0].Identity.NodeID
	doc, err := declaration.BuildInitialProxyOnlyV1([]domain.Node{{
		ProfileID: "source-a", NodeID: oldID, Kind: domain.NodeHTTP,
		Server: "127.0.0.1", Port: 8101, HTTP: &domain.HTTPNodeOptions{},
	}}, oldID, netip.MustParseAddrPort("127.0.0.1:53"))
	if err != nil { t.Fatal(err) }
	base, err := store.CommitDeclaration(ctx, 0, doc, "test:first-run")
	if err != nil { t.Fatal(err) }
	second, err := store.CommitProfileSnapshot(ctx, storage.ProfileSnapshotCandidate{
		ProfileID: "source-a", SourceKind: "sing-box", SourceSHA256: strings.Repeat("b", 64),
		Nodes: []profile.SourceNode{{
			SourceKey: "new-node", SourceName: "New",
			PayloadJSON: []byte("{\"type\":\"http\",\"tag\":\"new-node\",\"server\":\"127.0.0.1\",\"server_port\":8201}"),
		}},
	}, storage.ProfileSnapshotCommitOptions{})
	if err != nil { t.Fatal(err) }
	return store, oldID, second.Snapshot.Nodes[0].Identity.NodeID, second.Snapshot.ID, base.Revision, source.Revision
}

func TestSelectedRebindAPIRequiresPreviewAndOneExplicitStage(t *testing.T) {
	store, oldID, selectedID, snapshotID, baseRevision, sourceRevision := selectedRebindAPIFixture(t)
	defer store.Close()
	ctx := context.Background()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()
	path := "/v1/profiles/source-a/declaration/"
	req := apiv1.ProfileDeclarationPreviewRequest{
		SnapshotID: snapshotID, ExpectedDeclarationRevision: baseRevision,
		ReplacementSelectedNodeID: selectedID,
	}
	status, response := requestProfileAPI(t, api.URL, http.MethodPost, path+"preview", req)
	if status != http.StatusOK { t.Fatalf("explicit preview: %d %s", status, response) }
	var preview apiv1.ProfileDeclarationPreviewResponse
	if err := json.Unmarshal(response, &preview); err != nil { t.Fatal(err) }
	if preview.ReplacementSelectedNodeID != selectedID || preview.AddedNodeCount != 1 ||
		preview.RemovedNodeCount != 1 || preview.RetainedNodeCount != 0 ||
		len(preview.CandidateSHA256) != 64 || preview.CoreValidated || preview.Applied {
		t.Fatalf("wrong explicit diff: %+v", preview)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"preview",
		apiv1.ProfileDeclarationPreviewRequest{SnapshotID: snapshotID, ExpectedDeclarationRevision: baseRevision})
	if status != http.StatusUnprocessableEntity { t.Fatalf("implicit selection was allowed: %d", status) }
	stage := apiv1.ProfileDeclarationStageRequest{
		SnapshotID: snapshotID, ExpectedSourceRevision: sourceRevision,
		ExpectedDeclarationRevision: baseRevision,
		CandidateSHA256: preview.CandidateSHA256, RuntimeOverlaySHA256: preview.RuntimeOverlaySHA256,
		ReplacementSelectedNodeID: selectedID,
	}
	withoutChoice := stage
	withoutChoice.ReplacementSelectedNodeID = ""
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", withoutChoice)
	if status != http.StatusUnprocessableEntity { t.Fatalf("lost choice was accepted: %d", status) }
	wrongHash := stage
	wrongHash.CandidateSHA256 = strings.Repeat("0", 64)
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", wrongHash)
	if status != http.StatusConflict { t.Fatalf("forged hash accepted: %d", status) }
	status, response = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", stage)
	if status != http.StatusCreated { t.Fatalf("selected stage rejected: %d %s", status, response) }
	var receipt apiv1.ProfileDeclarationStageResponse
	if err := json.Unmarshal(response, &receipt); err != nil { t.Fatal(err) }
	if receipt.ReplacementSelectedNodeID != selectedID ||
		receipt.DeclarationRevision != baseRevision+1 ||
		receipt.DeclarationSHA256 != preview.CandidateSHA256 || receipt.Applied || receipt.CoreValidated {
		t.Fatalf("unsafe stage receipt: %+v", receipt)
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil { t.Fatal(err) }
	model, err := declaration.ParseV1(current.DocumentJSON)
	if err != nil { t.Fatal(err) }
	if model.Selection.Current.Default.NodeID != selectedID || len(model.Nodes) != 1 ||
		model.Nodes[0].NodeID != selectedID || model.Selection.Current.Default.NodeID == oldID {
		t.Fatalf("old selected node remained after explicit stage: %+v", model.Selection.Current)
	}
	daemonState, err := store.Snapshot(ctx)
	if err != nil || daemonState.AppliedGenerationID != nil ||
		daemonState.LastKnownGoodGenerationID != nil || daemonState.Revision != 0 {
		t.Fatalf("staging inadvertently applied Core: %+v %v", daemonState, err)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", stage)
	if status != http.StatusConflict { t.Fatalf("duplicate stage accepted: %d", status) }
}

func TestSelectedRebindAPIRejectsExistingOrRacingCurrentSelectionIntent(t *testing.T) {
	store, oldID, selectedID, snapshotID, baseRevision, sourceRevision := selectedRebindAPIFixture(t)
	defer store.Close()
	ctx := context.Background()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()
	path := "/v1/profiles/source-a/declaration/"
	req := apiv1.ProfileDeclarationPreviewRequest{
		SnapshotID: snapshotID, ExpectedDeclarationRevision: baseRevision,
		ReplacementSelectedNodeID: selectedID,
	}
	status, response := requestProfileAPI(t, api.URL, http.MethodPost, path+"preview", req)
	if status != http.StatusOK { t.Fatal(status, string(response)) }
	var preview apiv1.ProfileDeclarationPreviewResponse
	if err := json.Unmarshal(response, &preview); err != nil { t.Fatal(err) }
	intent, err := json.Marshal(domain.TargetRef{
		Kind: domain.TargetSpecificNode, ProfileID: "source-a", NodeID: oldID,
	})
	if err != nil { t.Fatal(err) }
	if _, err := store.SetCurrentSelectionIntent(ctx, intent); err != nil { t.Fatal(err) }
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"preview", req)
	if status != http.StatusConflict { t.Fatalf("persisted override not refused: %d", status) }
	stage := apiv1.ProfileDeclarationStageRequest{
		SnapshotID: snapshotID, ExpectedSourceRevision: sourceRevision,
		ExpectedDeclarationRevision: baseRevision,
		CandidateSHA256: preview.CandidateSHA256, RuntimeOverlaySHA256: preview.RuntimeOverlaySHA256,
		ReplacementSelectedNodeID: selectedID,
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", stage)
	if status != http.StatusConflict { t.Fatalf("intent race after preview not refused: %d", status) }
	current, err := store.CurrentDeclaration(ctx)
	if err != nil || current.Revision != baseRevision { t.Fatalf("stale intent advanced declaration: %+v %v", current, err) }
	req.ReplacementSelectedNodeID = "bad/id?token=NEVER_LEAK"
	status, response = requestProfileAPI(t, api.URL, http.MethodPost, path+"preview", req)
	if status != http.StatusBadRequest || bytes.Contains(response, []byte("NEVER_LEAK")) {
		t.Fatalf("hostile replacement choice not safely rejected: %d", status)
	}
}
