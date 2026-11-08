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
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func firstRunProfileFixture(t *testing.T) (*storage.Store, int64, uint64, string) {
	t.Helper()
	ctx := context.Background()
	store := newDaemonProfileMetadataStore(t, ctx)
	source, err := store.CommitProfileSource(ctx, 0, profile.SourceSpec{
		ProfileID: "first-run-profile", Format: profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationFile, Location: "/tmp/first-run-profile.json",
		Fetch: profile.FetchPolicy{Mode: profile.FetchDirect}, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := store.CommitProfileSnapshot(ctx, storage.ProfileSnapshotCandidate{
		ProfileID: "first-run-profile", SourceKind: "sing-box",
		SourceSHA256: strings.Repeat("a", 64),
		Nodes: []profile.SourceNode{{
			SourceKey: "edge-http", SourceName: "Imported edge",
			PayloadJSON: []byte(`{"type":"http","tag":"edge-http","server":"127.0.0.1","server_port":9080,"username":"private","password":"SUPER_PRIVATE_PASSWORD"}`),
		}},
	}, storage.ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return store, snapshot.Snapshot.ID, source.Revision, snapshot.Snapshot.Nodes[0].Identity.NodeID
}

func TestInitialProfileDeclarationGuardedAPIFromEmptyDatabase(t *testing.T) {
	store, snapshotID, sourceRev, nodeID := firstRunProfileFixture(t)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()
	ctx := context.Background()
	path := "/v1/profiles/first-run-profile/declaration/initial/"
	request := apiv1.InitialProfileDeclarationPreviewRequest{
		SnapshotID: snapshotID, SelectedNodeID: nodeID, ResolverAddress: "127.0.0.1:5300",
	}
	code, body := requestProfileAPI(t, api.URL, http.MethodPost, path+"preview", request)
	if code != http.StatusOK || bytes.Contains(body, []byte("SUPER_PRIVATE_PASSWORD")) ||
		bytes.Contains(body, []byte("private")) {
		t.Fatalf("unsafe first-run preview HTTP status=%d", code)
	}
	var preview apiv1.InitialProfileDeclarationPreviewResponse
	if err := json.Unmarshal(body, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.SnapshotID != snapshotID || preview.SourceRevision != sourceRev ||
		preview.BaseDeclarationRevision != 0 || preview.EffectiveNodeCount != 1 ||
		preview.SelectedNodeID != nodeID || preview.ResolverAddress != request.ResolverAddress ||
		preview.RoutingMode != initialDeclarationRoutingMode || preview.CNRulesReady ||
		preview.CoreValidated || preview.Applied || len(preview.CandidateSHA256) != 64 ||
		len(preview.RuntimeOverlaySHA256) != 64 {
		t.Fatalf("invalid first-run preview: %+v", preview)
	}
	before, err := store.CurrentDeclaration(ctx)
	if err != nil || before.Revision != 0 {
		t.Fatalf("preview wrote declaration: %+v %v", before, err)
	}
	state, err := store.Snapshot(ctx)
	if err != nil || state.Revision != 0 || state.AppliedGenerationID != nil {
		t.Fatalf("preview applied Core: %+v %v", state, err)
	}

	stage := apiv1.InitialProfileDeclarationStageRequest{
		SnapshotID: snapshotID, ExpectedSourceRevision: sourceRev,
		SelectedNodeID: nodeID, ResolverAddress: request.ResolverAddress,
		CandidateSHA256:          preview.CandidateSHA256,
		RuntimeOverlaySHA256:     preview.RuntimeOverlaySHA256,
		AcknowledgeProxyOnlyNoCN: true,
	}
	unacknowledged := stage
	unacknowledged.AcknowledgeProxyOnlyNoCN = false
	code, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", unacknowledged)
	if code != http.StatusBadRequest {
		t.Fatalf("first-run stage without CN warning acknowledgement=%d", code)
	}
	stale := stage
	stale.CandidateSHA256 = strings.Repeat("0", 64)
	code, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", stale)
	if code != http.StatusConflict {
		t.Fatalf("incorrect first-run preview receipt status=%d", code)
	}
	code, body = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", stage)
	if code != http.StatusCreated || bytes.Contains(body, []byte("SUPER_PRIVATE_PASSWORD")) {
		t.Fatalf("first-run declaration stage status=%d or secret leaked", code)
	}
	var staged apiv1.InitialProfileDeclarationStageResponse
	if err := json.Unmarshal(body, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.DeclarationRevision != 1 || staged.DeclarationSHA256 != preview.CandidateSHA256 ||
		staged.RoutingMode != initialDeclarationRoutingMode || staged.CNRulesReady ||
		staged.Applied || staged.CoreValidated {
		t.Fatalf("invalid first-run declaration stage: %+v", staged)
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil || current.Revision != 1 || current.SHA256 != preview.CandidateSHA256 {
		t.Fatalf("initial declared revision not persisted: %+v %v", current, err)
	}
	model, err := declaration.ParseV1(current.DocumentJSON)
	if err != nil || len(model.Nodes) != 1 || model.Nodes[0].NodeID != nodeID ||
		model.Routing.Final.Kind != domain.TargetCurrentSelected ||
		model.CNPreset != nil || len(model.Routing.Custom) != 0 {
		t.Fatalf("initial declaration is not valid proxy-only state: %v", err)
	}
	state, err = store.Snapshot(ctx)
	if err != nil || state.Revision != 0 || state.AppliedGenerationID != nil {
		t.Fatalf("staging unexpectedly applied Core: %+v %v", state, err)
	}
	code, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", stage)
	if code != http.StatusConflict {
		t.Fatalf("replayed first-run stage was accepted: %d", code)
	}
	code, _ = requestProfileAPI(t, api.URL, http.MethodPost, path+"preview", request)
	if code != http.StatusConflict {
		t.Fatalf("first-run preview allowed overwrite of existing declaration: %d", code)
	}
}

func TestInitialProfileDeclarationRejectsChangedSourceSnapshotAndOverlays(t *testing.T) {
	for _, tc := range []string{"snapshot", "overlay", "source", "selected", "dns"} {
		t.Run(tc, func(t *testing.T) {
			store, snapshotID, sourceRev, nodeID := firstRunProfileFixture(t)
			defer store.Close()
			api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
			defer api.Close()
			ctx := context.Background()
			path := "/v1/profiles/first-run-profile/declaration/initial/"
			req := apiv1.InitialProfileDeclarationPreviewRequest{
				SnapshotID: snapshotID, SelectedNodeID: nodeID, ResolverAddress: "127.0.0.1:5300",
			}
			code, body := requestProfileAPI(t, api.URL, http.MethodPost, path+"preview", req)
			if code != http.StatusOK {
				t.Fatalf("baseline first-run preview status=%d", code)
			}
			var preview apiv1.InitialProfileDeclarationPreviewResponse
			if err := json.Unmarshal(body, &preview); err != nil {
				t.Fatal(err)
			}
			stage := apiv1.InitialProfileDeclarationStageRequest{
				SnapshotID: snapshotID, ExpectedSourceRevision: sourceRev,
				SelectedNodeID: nodeID, ResolverAddress: req.ResolverAddress,
				CandidateSHA256:          preview.CandidateSHA256,
				RuntimeOverlaySHA256:     preview.RuntimeOverlaySHA256,
				AcknowledgeProxyOnlyNoCN: true,
			}
			switch tc {
			case "snapshot":
				_, err := store.CommitProfileSnapshot(ctx, storage.ProfileSnapshotCandidate{
					ProfileID: "first-run-profile", SourceKind: "sing-box",
					SourceSHA256: strings.Repeat("b", 64),
					Nodes: []profile.SourceNode{{
						SourceKey: "edge-http", SourceName: "New snapshot",
						PayloadJSON: []byte(`{"type":"http","tag":"edge-http","server":"127.0.0.1","server_port":9081}`),
					}},
				}, storage.ProfileSnapshotCommitOptions{})
				if err != nil {
					t.Fatal(err)
				}
			case "overlay":
				// A sort rank changes runtime overlay semantics and MUST
				// invalidate the preview digest. Favorite-only metadata
				// intentionally does not affect that digest.
				rank := int64(1)
				_, err := store.CommitProfileNodeOverlay(ctx, 0, profile.NodeOverlay{
					ProfileID: "first-run-profile", NodeID: nodeID, SortRank: &rank,
				})
				if err != nil {
					t.Fatal(err)
				}
			case "source":
				old, err := store.ProfileSource(ctx, "first-run-profile")
				if err != nil {
					t.Fatal(err)
				}
				spec := old.Spec
				spec.Enabled = false
				if _, err := store.CommitProfileSource(ctx, old.Revision, spec); err != nil {
					t.Fatal(err)
				}
			case "selected":
				stage.SelectedNodeID = "missing-node"
			case "dns":
				stage.ResolverAddress = "127.0.0.1:5301"
			}
			code, body = requestProfileAPI(t, api.URL, http.MethodPost, path+"stage", stage)
			if code == http.StatusCreated || bytes.Contains(body, []byte("SUPER_PRIVATE_PASSWORD")) {
				t.Fatalf("stale/invalid first-run stage accepted or leaked credentials: status=%d", code)
			}
			if code != http.StatusConflict && code != http.StatusUnprocessableEntity {
				t.Fatalf("bad first-run stage returned unexpected status %d", code)
			}
			current, err := store.CurrentDeclaration(ctx)
			if err != nil || current.Revision != 0 {
				t.Fatalf("rejected first-run stage advanced declaration: %+v %v", current, err)
			}
		})
	}
}

func TestInitialProfileDeclarationRejectsUnsafeResolverAndUnknownFields(t *testing.T) {
	store, snapshotID, _, nodeID := firstRunProfileFixture(t)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()
	base := "/v1/profiles/first-run-profile/declaration/initial/preview"
	for _, resolver := range []string{"", "0.0.0.0:53", "224.0.0.1:53", "dns.example.com:53", "127.0.0.1:0"} {
		code, body := requestProfileAPI(t, api.URL, http.MethodPost, base, apiv1.InitialProfileDeclarationPreviewRequest{
			SnapshotID: snapshotID, SelectedNodeID: nodeID, ResolverAddress: resolver,
		})
		if code != http.StatusBadRequest && code != http.StatusUnprocessableEntity {
			t.Fatalf("invalid resolver returned %d", code)
		}
		if bytes.Contains(body, []byte("SUPER_PRIVATE_PASSWORD")) {
			t.Fatal("resolver rejection leaked snapshot credentials")
		}
	}
	code, _ := requestProfileAPI(t, api.URL, http.MethodPost, base, map[string]any{
		"snapshot_id": snapshotID, "selected_node_id": nodeID,
		"resolver_address": "127.0.0.1:53", "unexpected": true,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("unrecognized first-run preview field accepted: %d", code)
	}
}
