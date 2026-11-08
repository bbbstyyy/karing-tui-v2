//go:build linux

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

func TestClashYAMLManualRefreshRejectsPartiallyInvalidUpdateAndPreservesSnapshot(t *testing.T) {
	var broken atomic.Bool
	const secret = "CLASH_PASSWORD_NEVER_IN_API"
	sourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
		if broken.Load() {
			_, _ = io.WriteString(w, `proxies:
  - name: Accepted
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: CLASH_PASSWORD_NEVER_IN_API
  - name: Invalid
    type: trojan
    server: 127.0.0.1
    port: 443
    password: CLASH_PASSWORD_NEVER_IN_API
    skip-cert-verify: true
rules:
  - MATCH,DIRECT
`)
			return
		}
		_, _ = io.WriteString(w, `proxies:
  - name: Accepted
    type: ss
    server: 127.0.0.1
    port: 8388
    cipher: aes-256-gcm
    password: CLASH_PASSWORD_NEVER_IN_API
rules:
  - MATCH,DIRECT
proxy-groups:
  - name: Remote policy is ignored
    type: select
    proxies: [DIRECT]
`)
	}))
	defer sourceServer.Close()

	ctx := context.Background()
	store := newDaemonProfileMetadataStore(t, ctx)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()

	const profileID = "profile-clash"
	path := "/v1/profiles/" + profileID
	spec := apiv1.ProfileSourceSpec{
		Format: "clash-yaml", LocationKind: "url", Location: sourceServer.URL,
		Enabled: true, Fetch: apiv1.ProfileSourceFetchPolicy{Mode: "direct"},
	}
	code, body := requestProfileAPI(t, api.URL, http.MethodPut, path,
		apiv1.ProfileSourcePutRequest{Source: spec})
	if code != http.StatusOK || bytes.Contains(body, []byte(secret)) {
		t.Fatalf("Clash source creation failed or leaked credential: HTTP %d", code)
	}
	var created apiv1.ProfileSourceResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	code, body = requestProfileAPI(t, api.URL, http.MethodPost, path+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if code != http.StatusOK || bytes.Contains(body, []byte(secret)) {
		t.Fatalf("valid Clash YAML refresh failed or leaked credential: HTTP %d", code)
	}
	var accepted apiv1.ProfileRefreshResponse
	if err := json.Unmarshal(body, &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.NodeCount != 1 || accepted.CurrentSnapshotID == nil {
		t.Fatal("Clash YAML refresh did not accept exactly one basic node")
	}
	var ignored bool
	for _, diag := range accepted.Diagnostics {
		if diag.Code == "ignored_by_product_policy" && diag.Path == "rules" {
			ignored = true
		}
	}
	if !ignored {
		t.Fatal("Clash subscription routing was not explicitly reported as ignored")
	}
	acceptedID := *accepted.CurrentSnapshotID
	broken.Store(true)
	code, body = requestProfileAPI(t, api.URL, http.MethodPost, path+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if code != http.StatusUnprocessableEntity || bytes.Contains(body, []byte(secret)) {
		t.Fatalf("unsafe Clash YAML partial refresh was accepted or leaked credential: HTTP %d", code)
	}
	var failed apiv1.ProfileRefreshErrorResponse
	if err := json.Unmarshal(body, &failed); err != nil {
		t.Fatal(err)
	}
	var blocked bool
	for _, diagnostic := range failed.Diagnostics {
		if diagnostic.Code == "unsupported_or_invalid_proxy" {
			blocked = true
		}
		if bytes.Contains([]byte(diagnostic.Message), []byte(secret)) {
			t.Fatal("Clash blocking diagnostic leaked credential")
		}
	}
	if !blocked {
		t.Fatalf("unsafe Clash YAML source update did not expose blocking diagnostic: %+v", failed.Diagnostics)
	}
	source, err := store.ProfileSource(ctx, profileID)
	if err != nil || source.CurrentSnapshotID == nil ||
		*source.CurrentSnapshotID != acceptedID || source.ConsecutiveFailures == 0 {
		t.Fatalf("unsafe Clash YAML refresh replaced accepted snapshot: %+v %v", source, err)
	}
	state, err := store.Snapshot(ctx)
	if err != nil || state.Revision != 0 || state.AppliedGenerationID != nil ||
		state.LastKnownGoodGenerationID != nil {
		t.Fatalf("Clash YAML refresh modified applied generation or LKG: %+v %v", state, err)
	}
}
