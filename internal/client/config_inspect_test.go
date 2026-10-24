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

func TestConfigInspectionClientLimitsResponseBytesAndUsesReadOnlyMethod(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "inspect.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet || req.URL.Path != "/v1/config/inspection" {
			http.Error(w, "wrong endpoint", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			_ = json.NewEncoder(w).Encode(apiv1.ConfigInspectionResponse{
				APIVersion: "v1", Evidence: "applied_declaration",
				GenerationID: 12, AppliedDeclarationRevision: 9,
			})
			return
		}
		_, _ = w.Write([]byte(strings.Repeat("x", maxInspectionResponseBytes+1)))
	}))
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()

	client := New(listener.Addr().String())
	first, err := client.InspectConfig(context.Background())
	if err != nil || first.GenerationID != 12 {
		t.Fatalf("small inspection not decoded: %+v %v", first, err)
	}
	_, err = client.InspectConfig(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exceeds") || calls.Load() != 2 {
		t.Fatalf("oversized inspection was accepted or retried: calls=%d err=%v", calls.Load(), err)
	}
}
