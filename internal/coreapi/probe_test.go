package coreapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClashVersionProbeAuthenticatesAndValidatesPinnedContract(t *testing.T) {
	const secret = "test-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		if got := r.Header.Get("Authorization"); got != "Bearer "+secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":"sing-box 1.14.0","premium":true,"meta":true}`)
	}))
	defer server.Close()

	probe, err := NewClashVersionProbe(server.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Ready(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestClashVersionProbeRejectsWrongSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	probe, err := NewClashVersionProbe(server.URL, "wrong")
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Ready(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("probe error = %v, want HTTP 401", err)
	}
}

func TestClashVersionProbeRejectsNonLoopbackEndpoint(t *testing.T) {
	for _, endpoint := range []string{
		"http://example.com:9090",
		"https://127.0.0.1:9090",
		"http://localhost:9090",
		"http://127.0.0.1:9090/prefix",
	} {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := NewClashVersionProbe(endpoint, "secret"); err == nil {
				t.Fatalf("expected endpoint %q to be rejected", endpoint)
			}
		})
	}
}

func TestClashVersionProbeRejectsRedirectAndOversizedResponse(t *testing.T) {
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":"sing-box 1.14.0","premium":true,"meta":true}`)
	}))
	defer redirectTarget.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL+"/version", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()

	probe, err := NewClashVersionProbe(redirector.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Ready(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("redirect probe error = %v", err)
	}

	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, strings.Repeat("x", maxVersionResponseBytes+1))
	}))
	defer large.Close()

	probe, err = NewClashVersionProbe(large.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Ready(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "size limit") {
		t.Fatalf("oversized probe error = %v", err)
	}
}

func TestClashVersionProbeRejectsLookalikeResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":"sing-box 1.14.0","premium":false,"meta":true}`)
	}))
	defer server.Close()

	probe, err := NewClashVersionProbe(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Ready(context.Background(), nil); err == nil {
		t.Fatal("expected lookalike version response to be rejected")
	}
}
