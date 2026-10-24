package client

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

func TestStageProfileDeclarationClientRequiresCreatedResponse(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "control.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/profiles/work/declaration/stage" {
			http.Error(w, "unexpected route", http.StatusNotFound)
			return
		}
		var request apiv1.ProfileDeclarationStageRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil ||
			request.SnapshotID != 5 || request.ExpectedSourceRevision != 3 || request.ExpectedDeclarationRevision != 12 ||
			request.CandidateSHA256 != strings.Repeat("a", 64) ||
			request.RuntimeOverlaySHA256 != strings.Repeat("b", 64) {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if call == 2 {
			w.WriteHeader(http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(apiv1.ProfileDeclarationStageResponse{
			ProfileID: "work", SnapshotID: 5, SourceRevision: 3, DeclarationRevision: 13,
			DeclarationSHA256: strings.Repeat("a", 64), CoreValidated: false, Applied: false,
		})
	}))
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()

	client := New(listener.Addr().String())
	request := apiv1.ProfileDeclarationStageRequest{
		SnapshotID: 5, ExpectedSourceRevision: 3, ExpectedDeclarationRevision: 12,
		CandidateSHA256: strings.Repeat("a", 64), RuntimeOverlaySHA256: strings.Repeat("b", 64),
	}
	result, err := client.StageProfileDeclaration(context.Background(), "work", request)
	if err != nil || result.DeclarationRevision != 13 || result.Applied || result.CoreValidated {
		t.Fatalf("stage response: %+v %v", result, err)
	}
	_, err = client.StageProfileDeclaration(context.Background(), "work", request)
	if err == nil || !strings.Contains(err.Error(), "409") || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stale stage did not return conflict: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("RPC count = %d, want 2", calls.Load())
	}
}
