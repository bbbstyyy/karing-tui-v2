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

func TestModeClientUpdatesAndReadsBack(t *testing.T) {
	const secret = "test-secret"
	var (
		mu   sync.Mutex
		mode = "Rule"
	)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/configs" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			current := mode
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"mode":      current,
				"mode-list": []string{"Rule", "RuleNoPrivate", "Global", "GlobalNoPrivate", "Direct"},
			})
		case http.MethodPatch:
			var body struct {
				Mode string `json:"mode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			mode = body.Mode
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
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

	client, err := NewModeClient(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Set(context.Background(), "Global"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := client.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Mode != "Global" || len(snapshot.ModeList) != 5 {
		t.Fatalf("mode snapshot = %+v", snapshot)
	}
}

func TestModeClientAllowsAdvertisedInternalPolicyMode(t *testing.T) {
	const secret = "test-secret"
	mode := "Rule"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"mode":      mode,
				"mode-list": []string{"Rule", "RuleNoPrivate", "Global", "GlobalNoPrivate", "Direct"},
			})
		case http.MethodPatch:
			var body struct {
				Mode string `json:"mode"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mode = body.Mode
			w.WriteHeader(http.StatusNoContent)
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

	client, err := NewModeClient(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Set(context.Background(), "GlobalNoPrivate"); err != nil {
		t.Fatal(err)
	}
	if mode != "GlobalNoPrivate" {
		t.Fatalf("core mode = %q, want GlobalNoPrivate", mode)
	}
}

func TestModeClientRejectsUnadvertisedAndNonLoopbackModes(t *testing.T) {
	if _, err := NewModeClient("http://192.0.2.1:9090", "secret"); err == nil {
		t.Fatal("non-loopback mode endpoint unexpectedly accepted")
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"mode":      "Rule",
			"mode-list": []string{"Rule"},
		})
	})
	server := httptest.NewUnstartedServer(handler)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()

	client, err := NewModeClient(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Set(context.Background(), "Global"); err == nil {
		t.Fatal("unadvertised Global mode unexpectedly accepted")
	}
}
