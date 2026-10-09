package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCheckedSelectionClientSendsEntireBindingAndDoesNotRetryConflict(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "selector.sock"))
	if err != nil { t.Fatal(err) }
	var calls int
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		if req.Method != http.MethodPut || req.URL.Path != "/v1/selection/current/checked" {
			http.Error(w, "wrong endpoint", http.StatusNotFound)
			return
		}
		var request apiv1.CurrentSelectionCheckedRequest
		if err := json.NewDecoder(req.Body).Decode(&request); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		if request.Target.Kind != domain.TargetSpecificNode ||
			request.Target.ProfileID != "profile-a" || request.Target.NodeID != "node-b" ||
			request.ExpectedSelectionRevision != 3 ||
			request.ExpectedConfigRevision != 7 ||
			request.ExpectedDeclarationRevision != 11 ||
			request.ExpectedDeclarationSHA256 != strings.Repeat("a", 64) ||
			request.ExpectedGenerationID == nil || *request.ExpectedGenerationID != 42 {
			http.Error(w, "bad binding", http.StatusBadRequest)
			return
		}
		if calls == 2 {
			w.WriteHeader(http.StatusConflict)
			return
		}
		_ = json.NewEncoder(w).Encode(apiv1.CurrentSelectionResponse{
			Target: request.Target, SelectionRevision: 4,
			ConfigRevision: 7, AppliedGenerationID: request.ExpectedGenerationID,
			DeclarationRevision: 11, DeclarationSHA256: request.ExpectedDeclarationSHA256,
			Persisted: true, Applied: true,
		})
	}))
	if err := server.Listener.Close(); err != nil { t.Fatal(err) }
	server.Listener = listener
	server.Start()
	defer server.Close()

	api := New(listener.Addr().String())
	generation := int64(42)
	request := apiv1.CurrentSelectionCheckedRequest{
		Target: domain.TargetRef{Kind: domain.TargetSpecificNode,ProfileID:"profile-a",NodeID:"node-b"},
		ExpectedSelectionRevision: 3, ExpectedConfigRevision: 7,
		ExpectedGenerationID: &generation, ExpectedDeclarationRevision: 11,
		ExpectedDeclarationSHA256: strings.Repeat("a", 64),
	}
	result, err := api.SetCurrentSelectionChecked(context.Background(), request)
	if err != nil || !result.Persisted || !result.Applied || result.SelectionRevision != 4 {
		t.Fatalf("checked client response = %+v error=%v", result, err)
	}
	_, err = api.SetCurrentSelectionChecked(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "409") || calls != 2 {
		t.Fatalf("stale checked request retried/hidden: calls=%d err=%v", calls, err)
	}
}
