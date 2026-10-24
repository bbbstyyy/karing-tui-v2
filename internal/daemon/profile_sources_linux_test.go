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

func TestProfileSourceAPICRUDAndManualRefreshPreservesLastGoodSnapshot(t *testing.T) {
	var blocked atomic.Bool
	var fetches atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		if r.Method != http.MethodGet {
			t.Errorf("profile refresh method = %s, want GET", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		if blocked.Load() {
			_, _ = w.Write([]byte("{\"outbounds\":[{\"type\":\"http\",\"tag\":\"proxy-a\",\"server\":\"127.0.0.1\",\"server_port\":3128,\"tls\":{\"enabled\":true}}]}"))
			return
		}
		_, _ = w.Write([]byte("{\"outbounds\":[{\"type\":\"http\",\"tag\":\"proxy-a\",\"server\":\"127.0.0.1\",\"server_port\":3128}],\"route\":{\"final\":\"direct\"}}"))
	}))
	defer upstream.Close()

	ctx := context.Background()
	store := newDaemonProfileMetadataStore(t, ctx)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()

	status, body := requestProfileAPI(t, api.URL, http.MethodGet, "/v1/profiles", nil)
	if status != http.StatusOK {
		t.Fatalf("empty profile list: %d %s", status, body)
	}
	var empty apiv1.ProfileSourceListResponse
	if err := json.Unmarshal(body, &empty); err != nil || len(empty.Profiles) != 0 {
		t.Fatalf("empty profile list = %+v err=%v", empty, err)
	}

	spec := apiv1.ProfileSourceSpec{
		Format: "sing-box", LocationKind: "url",
		Location: upstream.URL, Enabled: true,
		Fetch: apiv1.ProfileSourceFetchPolicy{Mode: "direct"},
	}
	status, body = requestProfileAPI(t, api.URL, http.MethodPut, "/v1/profiles/profile-a",
		apiv1.ProfileSourcePutRequest{ExpectedRevision: 0, Source: spec})
	if status != http.StatusOK {
		t.Fatalf("create profile source: %d %s", status, body)
	}
	var created apiv1.ProfileSourceResponse
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.ProfileID != "profile-a" || created.Revision != 1 ||
		created.Source.Location != upstream.URL ||
		created.Source.Fetch.Mode != "direct" ||
		created.CurrentSnapshotID != nil {
		t.Fatalf("created source = %+v", created)
	}

	status, body = requestProfileAPI(t, api.URL, http.MethodGet, "/v1/profiles/profile-a", nil)
	if status != http.StatusOK {
		t.Fatalf("get profile source: %d %s", status, body)
	}
	var read apiv1.ProfileSourceResponse
	if err := json.Unmarshal(body, &read); err != nil || read.Revision != created.Revision {
		t.Fatalf("read source = %+v err=%v", read, err)
	}
	status, body = requestProfileAPI(t, api.URL, http.MethodGet, "/v1/profiles", nil)
	if status != http.StatusOK {
		t.Fatalf("list profiles: %d %s", status, body)
	}
	var listed apiv1.ProfileSourceListResponse
	if err := json.Unmarshal(body, &listed); err != nil ||
		len(listed.Profiles) != 1 || listed.Profiles[0].ProfileID != "profile-a" {
		t.Fatalf("listed sources = %+v err=%v", listed, err)
	}

	status, _ = requestProfileAPI(t, api.URL, http.MethodPut, "/v1/profiles/profile-a",
		apiv1.ProfileSourcePutRequest{ExpectedRevision: 0, Source: spec})
	if status != http.StatusConflict {
		t.Fatalf("stale source update = %d, want 409", status)
	}
	invalid := spec
	invalid.UpdateIntervalSeconds = 9223372036854775807
	status, _ = requestProfileAPI(t, api.URL, http.MethodPut, "/v1/profiles/profile-a",
		apiv1.ProfileSourcePutRequest{ExpectedRevision: 1, Source: invalid})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("overflow update interval = %d, want 422", status)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPut, "/v1/profiles/profile-b",
		map[string]any{"expected_revision": 0, "source": spec, "unrecognized": true})
	if status != http.StatusBadRequest {
		t.Fatalf("unknown request field = %d, want 400", status)
	}

	status, body = requestProfileAPI(t, api.URL, http.MethodPost, "/v1/profiles/profile-a/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusOK {
		t.Fatalf("initial full refresh = %d %s", status, body)
	}
	var accepted apiv1.ProfileRefreshResponse
	if err := json.Unmarshal(body, &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.ProfileID != "profile-a" || accepted.SourceRevision != 1 ||
		accepted.CurrentSnapshotID == nil || accepted.NodeCount != 1 ||
		accepted.NotModified || len(accepted.Diagnostics) == 0 {
		t.Fatalf("successful full refresh = %+v", accepted)
	}
	snapshotID := *accepted.CurrentSnapshotID

	blocked.Store(true)
	status, body = requestProfileAPI(t, api.URL, http.MethodPost, "/v1/profiles/profile-a/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("unsupported TLS refresh = %d, want 422, body=%s", status, body)
	}
	var rejected apiv1.ProfileRefreshErrorResponse
	if err := json.Unmarshal(body, &rejected); err != nil {
		t.Fatal(err)
	}
	if len(rejected.Diagnostics) == 0 ||
		rejected.Diagnostics[0].Level != "error" {
		t.Fatalf("missing import diagnostics = %+v", rejected)
	}
	source, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if source.CurrentSnapshotID == nil ||
		*source.CurrentSnapshotID != snapshotID ||
		source.LastError == "" || source.ConsecutiveFailures == 0 {
		t.Fatalf("blocked refresh corrupted source = %+v", source)
	}
	daemonState, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if daemonState.Revision != 0 || daemonState.AppliedGenerationID != nil {
		t.Fatalf("profile refresh unexpectedly applied a runtime config: %+v", daemonState)
	}
	if fetches.Load() != 2 {
		t.Fatalf("fetch count = %d, want 2", fetches.Load())
	}
}

func TestProfileSourceAPIRejectsMalformedBase64AsInvalidImport(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("%%%invalid-base64"))
	}))
	defer upstream.Close()

	ctx := context.Background()
	store := newDaemonProfileMetadataStore(t, ctx)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()

	spec := apiv1.ProfileSourceSpec{
		Format:       "uri-list-base64",
		LocationKind: "url",
		Location:     upstream.URL,
		Enabled:      true,
		Fetch:        apiv1.ProfileSourceFetchPolicy{Mode: "direct"},
	}
	status, body := requestProfileAPI(t, api.URL, http.MethodPut, "/v1/profiles/profile-b64",
		apiv1.ProfileSourcePutRequest{Source: spec})
	if status != http.StatusOK {
		t.Fatalf("create base64 source = %d %s", status, body)
	}
	status, body = requestProfileAPI(t, api.URL, http.MethodPost,
		"/v1/profiles/profile-b64/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: 1})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("malformed base64 status = %d, want 422, body=%s", status, body)
	}
	source, err := store.ProfileSource(ctx, "profile-b64")
	if err != nil {
		t.Fatal(err)
	}
	if source.CurrentSnapshotID != nil ||
		source.ConsecutiveFailures != 1 ||
		source.LastError == "" {
		t.Fatalf("malformed base64 advanced snapshot: %+v", source)
	}
}

func TestProfileSourceAPISharesGateWithMetadataRefresh(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			started <- struct{}{}
			<-release
			_, _ = w.Write([]byte("{\"outbounds\":[{\"type\":\"http\",\"tag\":\"p1\",\"server\":\"127.0.0.1\",\"server_port\":3128}]}"))
			return
		}
		w.Header().Set("Subscription-Userinfo", "total=1024")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	ctx := context.Background()
	store := newDaemonProfileMetadataStore(t, ctx)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()

	spec := apiv1.ProfileSourceSpec{
		Format: "sing-box", LocationKind: "url", Location: upstream.URL,
		Enabled: true, Fetch: apiv1.ProfileSourceFetchPolicy{Mode: "direct"},
	}
	status, body := requestProfileAPI(t, api.URL, http.MethodPut, "/v1/profiles/profile-a",
		apiv1.ProfileSourcePutRequest{Source: spec})
	if status != http.StatusOK {
		t.Fatalf("create source = %d %s", status, body)
	}

	done := make(chan int, 1)
	go func() {
		reqBytes, _ := json.Marshal(apiv1.ProfileRefreshRequest{ExpectedSourceRevision: 1})
		resp, err := http.Post(api.URL+"/v1/profiles/profile-a/refresh",
			"application/json", bytes.NewReader(reqBytes))
		if err != nil {
			done <- 0
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		done <- resp.StatusCode
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("manual refresh did not begin")
	}

	status, _ = requestProfileAPI(t, api.URL, http.MethodPost,
		"/v1/profiles/profile-a/metadata/refresh",
		apiv1.ProfileMetadataRefreshRequest{ExpectedSourceRevision: 1})
	if status != http.StatusTooManyRequests {
		close(release)
		t.Fatalf("concurrent metadata status = %d, want 429", status)
	}
	status, _ = requestProfileAPI(t, api.URL, http.MethodPut,
		"/v1/profiles/profile-a",
		apiv1.ProfileSourcePutRequest{ExpectedRevision: 1, Source: spec})
	if status != http.StatusTooManyRequests {
		close(release)
		t.Fatalf("concurrent source edit status = %d, want 429", status)
	}

	close(release)
	select {
	case got := <-done:
		if got != http.StatusOK {
			t.Fatalf("completed manual refresh status = %d", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("manual refresh did not complete after gate release")
	}
}

func requestProfileAPI(
	t *testing.T,
	baseURL string,
	method string,
	path string,
	payload any,
) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if payload != nil {
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequest(method, baseURL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body
}
