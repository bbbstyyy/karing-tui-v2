package coreapi

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestConnectionsClientReadsAuthenticatedSnapshot(t *testing.T) {
	const secret = "test-secret"
	start := time.Date(2026, 10, 7, 7, 0, 0, 0, time.UTC)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/connections" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(`{
		  "downloadTotal":12,
		  "uploadTotal":34,
		  "connections":[{
		    "id":"connection-1",
		    "metadata":{
		      "network":"tcp",
		      "type":"mixed/in-rule",
		      "sourceIP":"127.0.0.1",
		      "destinationIP":"127.0.0.1",
		      "sourcePort":"40000",
		      "destinationPort":"443",
		      "host":"example.test",
		      "dnsMode":"normal",
		      "processPath":"",
		      "packageName":"",
		      "user":"",
		      "protocol":""
		    },
		    "upload":1,
		    "download":2,
		    "start":"` + start.Format(time.RFC3339) + `",
		    "chains":["out-direct"],
		    "rule":"final",
		    "rulePayload":""
		  }]
		}`))
	})
	server := httptest.NewUnstartedServer(handler)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()

	client, err := NewConnectionsClient(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := client.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.UploadTotal != 34 || snapshot.DownloadTotal != 12 || len(snapshot.Connections) != 1 {
		t.Fatalf("connections snapshot = %+v", snapshot)
	}
	connection := snapshot.Connections[0]
	if connection.ID != "connection-1" ||
		connection.Metadata.Type != "mixed/in-rule" ||
		connection.Metadata.Host != "example.test" ||
		connection.Metadata.DestinationPort != "443" ||
		len(connection.Chains) != 1 || connection.Chains[0] != "out-direct" ||
		!connection.Start.Equal(start) {
		t.Fatalf("connection = %+v", connection)
	}
}

func TestConnectionsClientRejectsNonLoopbackEndpoint(t *testing.T) {
	if _, err := NewConnectionsClient("http://192.0.2.1:9090", "secret"); err == nil {
		t.Fatal("non-loopback connections endpoint unexpectedly accepted")
	}
}

func TestConnectionsClientRejectsOversizedResponse(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"connections":[{"id":"`))
		_, _ = w.Write([]byte(strings.Repeat("x", maxConnectionsResponseBytes)))
	})
	server := httptest.NewUnstartedServer(handler)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()

	client, err := NewConnectionsClient(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Snapshot(context.Background()); err == nil {
		t.Fatal("oversized connections response unexpectedly accepted")
	}
}
