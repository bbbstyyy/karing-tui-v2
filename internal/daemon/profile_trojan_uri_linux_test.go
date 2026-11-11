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

func TestTrojanURIManualRefreshKeepsLastAcceptedSnapshotOnUnsupportedTransport(t *testing.T) {
	var invalid atomic.Bool
	sourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if invalid.Load() {
			_, _ = io.WriteString(w, "trojan://TOPSECRET@relay.example.com:443?type=grpc#DoNotCommit\n")
			return
		}
		_, _ = io.WriteString(w, "trojan://TOPSECRET@relay.example.com:443?security=tls&type=tcp&sni=relay.example.com#Good\n")
	}))
	defer sourceServer.Close()

	ctx := context.Background()
	store := newDaemonProfileMetadataStore(t, ctx)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()

	const profileID = "profile-trojan"
	path := "/v1/profiles/" + profileID
	spec := apiv1.ProfileSourceSpec{
		Format: "uri-list", LocationKind: "url", Location: sourceServer.URL,
		Enabled: true, Fetch: apiv1.ProfileSourceFetchPolicy{Mode: "direct"},
	}
	code, response := requestProfileAPI(t, api.URL, http.MethodPut, path, apiv1.ProfileSourcePutRequest{
		Source: spec,
	})
	if code != http.StatusOK || bytes.Contains(response, []byte("TOPSECRET")) {
		t.Fatalf("Trojan URI source create failed or leaked credentials: status=%d", code)
	}
	var created apiv1.ProfileSourceResponse
	if err := json.Unmarshal(response, &created); err != nil {
		t.Fatal(err)
	}

	code, response = requestProfileAPI(t, api.URL, http.MethodPost, path+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if code != http.StatusOK || bytes.Contains(response, []byte("TOPSECRET")) {
		t.Fatalf("valid Trojan URI refresh failed or leaked credentials: status=%d", code)
	}
	var accepted apiv1.ProfileRefreshResponse
	if err := json.Unmarshal(response, &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.NodeCount != 1 || accepted.CurrentSnapshotID == nil {
		t.Fatalf("Trojan URI snapshot absent: %+v", accepted)
	}
	acceptedID := *accepted.CurrentSnapshotID

	invalid.Store(true)
	code, response = requestProfileAPI(t, api.URL, http.MethodPost, path+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if code != http.StatusUnprocessableEntity || bytes.Contains(response, []byte("TOPSECRET")) {
		t.Fatalf("invalid Trojan URI refresh not refused or leaked credentials: status=%d", code)
	}
	var failure apiv1.ProfileRefreshErrorResponse
	if err := json.Unmarshal(response, &failure); err != nil {
		t.Fatal(err)
	}
	if len(failure.Diagnostics) != 1 ||
		failure.Diagnostics[0].Code != "unsupported_or_invalid_uri" {
		t.Fatalf("unsupported transport did not return safe blocked diagnostic: %+v", failure.Diagnostics)
	}
	source, err := store.ProfileSource(ctx, profileID)
	if err != nil || source.CurrentSnapshotID == nil ||
		*source.CurrentSnapshotID != acceptedID || source.ConsecutiveFailures == 0 {
		t.Fatalf("blocked refresh replaced accepted snapshot: %+v %v", source, err)
	}
	state, err := store.Snapshot(ctx)
	if err != nil || state.Revision != 0 || state.AppliedGenerationID != nil {
		t.Fatalf("source-only refresh mutated applied Core generation: %+v %v", state, err)
	}
}
