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

func TestObservedConnectionsClientEnforcesResponseSizeBound(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "connections.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/connections" {
			http.Error(w, "bad request", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			_ = json.NewEncoder(w).Encode(apiv1.ObservedConnectionsResponse{
				Evidence: "observed", GenerationID: 4,
			})
			return
		}
		// The client rejects bytes before attempting an unbounded JSON decode.
		_, _ = w.Write([]byte(strings.Repeat("x", maxObservedConnectionsResponseBytes+1)))
	}))
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()

	api := New(listener.Addr().String())
	got, err := api.ObservedConnections(context.Background())
	if err != nil || got.GenerationID != 4 {
		t.Fatalf("expected small observed snapshot: %+v, %v", got, err)
	}
	_, err = api.ObservedConnections(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response not rejected: %v", err)
	}
}
