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

func TestVLESSURIManualRefreshRejectsUnsafeUpdateWithoutLosingAcceptedSnapshot(t *testing.T) {
	var invalid atomic.Bool
	const uuid = "01234567-89ab-cdef-0123-456789abcdef"
	sourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if invalid.Load() {
			_, _ = io.WriteString(w, "vless://"+uuid+"@relay.example.com:443?security=reality&encryption=none&type=grpc#Bad\n")
			return
		}
		_, _ = io.WriteString(w, "vless://"+uuid+"@relay.example.com:443?security=tls&encryption=none&type=tcp&sni=relay.example.com#Good\n")
	}))
	defer sourceServer.Close()

	ctx := context.Background()
	store := newDaemonProfileMetadataStore(t, ctx)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()

	const profileID = "profile-vless"
	path := "/v1/profiles/" + profileID
	spec := apiv1.ProfileSourceSpec{
		Format: "uri-list", LocationKind: "url", Location: sourceServer.URL,
		Enabled: true, Fetch: apiv1.ProfileSourceFetchPolicy{Mode: "direct"},
	}
	code, body := requestProfileAPI(t, api.URL, http.MethodPut, path,
		apiv1.ProfileSourcePutRequest{Source: spec})
	if code != http.StatusOK || bytes.Contains(body, []byte(uuid)) {
		t.Fatalf("VLESS source creation failed or revealed secret: HTTP %d", code)
	}
	var created apiv1.ProfileSourceResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}

	code, body = requestProfileAPI(t, api.URL, http.MethodPost, path+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if code != http.StatusOK || bytes.Contains(body, []byte(uuid)) {
		t.Fatalf("verified VLESS source refresh failed or revealed secret: HTTP %d", code)
	}
	var accepted apiv1.ProfileRefreshResponse
	if err := json.Unmarshal(body, &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.NodeCount != 1 || accepted.CurrentSnapshotID == nil {
		t.Fatal("verified VLESS refresh did not create one accepted snapshot")
	}
	acceptedID := *accepted.CurrentSnapshotID

	invalid.Store(true)
	code, body = requestProfileAPI(t, api.URL, http.MethodPost, path+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if code != http.StatusUnprocessableEntity || bytes.Contains(body, []byte(uuid)) {
		t.Fatalf("unsafe VLESS update was not refused or disclosed UUID: HTTP %d", code)
	}
	var failed apiv1.ProfileRefreshErrorResponse
	if err := json.Unmarshal(body, &failed); err != nil {
		t.Fatal(err)
	}
	if len(failed.Diagnostics) != 1 ||
		failed.Diagnostics[0].Code != "unsupported_or_invalid_uri" {
		t.Fatalf("unsafe VLESS update did not expose safe blocking diagnostic: %+v", failed.Diagnostics)
	}
	source, err := store.ProfileSource(ctx, profileID)
	if err != nil || source.CurrentSnapshotID == nil ||
		*source.CurrentSnapshotID != acceptedID || source.ConsecutiveFailures == 0 {
		t.Fatalf("unsafe VLESS refresh changed previously accepted snapshot: %+v %v", source, err)
	}
	state, err := store.Snapshot(ctx)
	if err != nil || state.Revision != 0 || state.AppliedGenerationID != nil ||
		state.LastKnownGoodGenerationID != nil {
		t.Fatalf("source refresh changed applied generation or LKG: %+v %v", state, err)
	}
}
