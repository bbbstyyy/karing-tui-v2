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

func TestCNReadinessClientReadOnlyBoundedAndNoRawErrorEcho(t *testing.T) {
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "cn-readiness.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/cn/resources/readiness" || req.Method != http.MethodGet {
			http.Error(w, "wrong CN readiness path or write attempt", http.StatusMethodNotAllowed)
			return
		}
		switch calls.Add(1) {
		case 1:
			_ = json.NewEncoder(w).Encode(apiv1.CNResourceReadinessResponse{
				Evidence:            "pinned_source_inventory_only",
				TotalGroupCount:     28,
				KnownUpstreamAbsent: []string{"geoip:bing"},
				DistributionReady:   false,
			})
		case 2:
			_, _ = w.Write([]byte(strings.Repeat("z", maxCNReadinessResponseBytes+1)))
		case 3:
			_, _ = w.Write([]byte(`{"bad": SECRET_TOKEN_HIDDEN_IN_SOURCE}`))
		default:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("secret external URL https://internal.invalid/?token=SECRET_HTTP_BODY"))
		}
	}))
	if err := server.Listener.Close(); err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()

	api := New(listener.Addr().String())
	valid, err := api.CNReadiness(context.Background())
	if err != nil || valid.TotalGroupCount != 28 || valid.DistributionReady {
		t.Fatalf("bounded CN client did not read small source-only inventory: %+v %v", valid, err)
	}
	_, err = api.CNReadiness(context.Background())
	if err == nil || !strings.Contains(err.Error(), "byte limit") {
		t.Fatalf("oversized CN readiness response accepted: %v", err)
	}
	_, err = api.CNReadiness(context.Background())
	if err == nil || strings.Contains(err.Error(), "SECRET_TOKEN_HIDDEN_IN_SOURCE") ||
		!strings.Contains(err.Error(), "invalid") {
		t.Fatalf("malformed source readiness response echoed raw input: %v", err)
	}
	_, err = api.CNReadiness(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 502") ||
		strings.Contains(err.Error(), "SECRET_HTTP_BODY") ||
		strings.Contains(err.Error(), "internal.invalid") {
		t.Fatalf("CN readiness HTTP error leaked an untrusted body: %v", err)
	}
	if calls.Load() != 4 {
		t.Fatalf("client retried read-only audit unexpectedly: %d", calls.Load())
	}
}
