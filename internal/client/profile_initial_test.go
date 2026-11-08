package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

func TestInitialProfileDeclarationClientUsesProtectedRoutesAndSingleStageAttempt(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "control.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var previewCalls, stageCalls atomic.Int32
	const profileID = "work"
	shaA, shaB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "wrong method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/profiles/work/declaration/initial/preview":
			previewCalls.Add(1)
			var request apiv1.InitialProfileDeclarationPreviewRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil ||
				request.SnapshotID != 15 || request.SelectedNodeID != "node-a" ||
				request.ResolverAddress != "127.0.0.1:5300" {
				http.Error(w, "wrong preview fields", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(apiv1.InitialProfileDeclarationPreviewResponse{
				ProfileID: profileID, SnapshotID: 15,
				SourceRevision: 7, BaseDeclarationRevision: 0,
				EffectiveNodeCount: 1, SelectedNodeID: "node-a",
				ResolverAddress: "127.0.0.1:5300",
				CandidateSHA256: shaA, RuntimeOverlaySHA256: shaB,
				RoutingMode: "proxy-only-no-cn",
			})
		case "/v1/profiles/work/declaration/initial/stage":
			count := stageCalls.Add(1)
			var request apiv1.InitialProfileDeclarationStageRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil ||
				request.SnapshotID != 15 || request.ExpectedSourceRevision != 7 ||
				request.SelectedNodeID != "node-a" || request.ResolverAddress != "127.0.0.1:5300" ||
				request.CandidateSHA256 != shaA || request.RuntimeOverlaySHA256 != shaB ||
				!request.AcknowledgeProxyOnlyNoCN {
				http.Error(w, "wrong acknowledgement", http.StatusBadRequest)
				return
			}
			if count != 1 {
				w.WriteHeader(http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(apiv1.InitialProfileDeclarationStageResponse{
				ProfileID: profileID, SnapshotID: 15, SourceRevision: 7,
				DeclarationRevision: 1, DeclarationSHA256: shaA,
				RoutingMode: "proxy-only-no-cn",
			})
		default:
			http.Error(w, "unknown route", http.StatusNotFound)
		}
	}))
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()
	api := New(listener.Addr().String())
	p, err := api.PreviewInitialProfileDeclaration(context.Background(), profileID, apiv1.InitialProfileDeclarationPreviewRequest{
		SnapshotID: 15, SelectedNodeID: "node-a", ResolverAddress: "127.0.0.1:5300",
	})
	if err != nil || p.CandidateSHA256 != shaA || p.Applied || p.CoreValidated || p.CNRulesReady {
		t.Fatalf("first-run client preview status incorrect: %v", err)
	}
	request := apiv1.InitialProfileDeclarationStageRequest{
		SnapshotID: 15, ExpectedSourceRevision: 7, SelectedNodeID: "node-a",
		ResolverAddress: "127.0.0.1:5300", CandidateSHA256: shaA,
		RuntimeOverlaySHA256: shaB, AcknowledgeProxyOnlyNoCN: true,
	}
	result, err := api.StageInitialProfileDeclaration(context.Background(), profileID, request)
	if err != nil || result.DeclarationRevision != 1 ||
		result.DeclarationSHA256 != shaA || result.Applied || result.CNRulesReady {
		t.Fatalf("first-run client stage status incorrect: %v", err)
	}
	_, err = api.StageInitialProfileDeclaration(context.Background(), profileID, request)
	if err == nil || !strings.Contains(err.Error(), "409") {
		t.Fatalf("replayed stage did not surface conflict: %v", err)
	}
	if previewCalls.Load() != 1 || stageCalls.Load() != 2 {
		t.Fatalf("unexpected RPC count preview=%d stage=%d", previewCalls.Load(), stageCalls.Load())
	}
}
