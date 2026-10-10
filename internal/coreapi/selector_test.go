package coreapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestSelectorClientUpdatesAndReadsBack(t *testing.T) {
	const secret = "test-secret"
	var (
		mu      sync.Mutex
		current = "out-a"
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/proxies/out-current" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPut:
			var body struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if body.Name != "out-b" {
				http.Error(w, "unknown outbound", http.StatusBadRequest)
				return
			}
			mu.Lock()
			current = body.Name
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			mu.Lock()
			now := current
			mu.Unlock()
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"name": "out-current",
				"now":  now,
				"all":  []string{"out-a", "out-b"},
			})
		default:
			http.Error(w, "method", http.StatusMethodNotAllowed)
		}
	})
	server := httptest.NewUnstartedServer(handler)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()

	client, err := NewSelectorClient(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Select(context.Background(), "out-current", "out-b"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := client.Current(context.Background(), "out-current")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Now != "out-b" || len(snapshot.All) != 2 {
		t.Fatalf("selector snapshot = %+v", snapshot)
	}
}

func TestSelectorClientRejectsNonLoopbackEndpoint(t *testing.T) {
	if _, err := NewSelectorClient("http://192.0.2.1:9090", "secret"); err == nil {
		t.Fatal("non-loopback selector endpoint unexpectedly accepted")
	}
}
