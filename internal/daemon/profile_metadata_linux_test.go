//go:build linux

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestProfileMetadataAPIRefreshesHeadWithoutChangingProfileHealth(t *testing.T) {
	var (
		headCalls atomic.Int32
		malformed atomic.Bool
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("metadata method = %q, want HEAD", r.Method)
		}
		headCalls.Add(1)
		if malformed.Load() {
			w.Header().Set("Subscription-Userinfo", "upload=not-a-number")
		} else {
			w.Header().Set(
				"Subscription-Userinfo",
				"upload=10; download=20; total=100; expire=1798761600",
			)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	ctx := context.Background()
	store := newDaemonProfileMetadataStore(t, ctx)
	defer store.Close()

	source, err := store.CommitProfileSource(ctx, 0, profile.SourceSpec{
		ProfileID:    "profile-a",
		Format:       profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationURL,
		Location:     upstream.URL,
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	})
	if err != nil {
		t.Fatal(err)
	}

	server := &Server{started: time.Now().UTC()}
	api := httptest.NewServer(server.handler(store, nil))
	defer api.Close()

	initialResponse, err := http.Get(api.URL + "/v1/profiles/profile-a/metadata")
	if err != nil {
		t.Fatal(err)
	}
	if initialResponse.StatusCode != http.StatusOK {
		initialResponse.Body.Close()
		t.Fatalf("initial metadata status = %d", initialResponse.StatusCode)
	}
	var initial apiv1.ProfileMetadataResponse
	if err := json.NewDecoder(initialResponse.Body).Decode(&initial); err != nil {
		initialResponse.Body.Close()
		t.Fatal(err)
	}
	initialResponse.Body.Close()
	if initial.SourceRevision != source.Revision ||
		initial.Usage != nil ||
		initial.MetadataObservedAt != "" ||
		initial.HeaderObserved ||
		initial.ObservationApplied {
		t.Fatalf("initial metadata response = %+v", initial)
	}

	first := postProfileMetadataRefresh(t, api.URL, source.Revision)
	if !first.HeaderObserved ||
		!first.ObservationApplied ||
		first.Usage == nil ||
		first.Usage.UploadBytes == nil ||
		*first.Usage.UploadBytes != 10 ||
		first.Usage.DownloadBytes == nil ||
		*first.Usage.DownloadBytes != 20 ||
		first.Usage.TotalBytes == nil ||
		*first.Usage.TotalBytes != 100 ||
		first.MetadataObservedAt == "" ||
		first.UsageUpdatedAt == "" ||
		first.MetadataError != "" {
		t.Fatalf("first metadata response = %+v", first)
	}
	if headCalls.Load() != 1 {
		t.Fatalf("HEAD calls = %d, want 1", headCalls.Load())
	}

	state, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.LastAttemptAt != nil ||
		state.LastSuccessAt != nil ||
		state.ConsecutiveFailures != 0 ||
		state.CurrentSnapshotID != nil {
		t.Fatalf("metadata refresh changed full refresh health: %+v", state)
	}

	malformed.Store(true)
	second := postProfileMetadataRefresh(t, api.URL, source.Revision)
	if !second.HeaderObserved ||
		!second.ObservationApplied ||
		second.MetadataError == "" ||
		second.Usage == nil ||
		second.Usage.TotalBytes == nil ||
		*second.Usage.TotalBytes != 100 ||
		second.UsageUpdatedAt != first.UsageUpdatedAt ||
		second.MetadataObservedAt == first.MetadataObservedAt {
		t.Fatalf("malformed metadata response = %+v", second)
	}
	if headCalls.Load() != 2 {
		t.Fatalf("HEAD calls = %d, want 2", headCalls.Load())
	}

	scheduleEdit := source.Spec
	scheduleEdit.UpdateInterval = 5 * time.Minute
	changed, err := store.CommitProfileSource(ctx, source.Revision, scheduleEdit)
	if err != nil {
		t.Fatal(err)
	}
	body := bytes.NewBufferString(`{"expected_source_revision":1}`)
	response, err := http.Post(
		api.URL+"/v1/profiles/profile-a/metadata/refresh",
		"application/json",
		body,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("stale revision status = %d, want 409", response.StatusCode)
	}
	if headCalls.Load() != 2 {
		t.Fatalf("stale revision triggered HEAD; calls = %d", headCalls.Load())
	}
	if changed.Revision == source.Revision {
		t.Fatalf("schedule edit did not advance source revision: %+v", changed)
	}
}

func TestProfileMetadataRefreshGateBoundsGlobalAndPerProfileConcurrency(t *testing.T) {
	gate := newProfileOperationGate(4)
	for _, profileID := range []string{"p1", "p2", "p3", "p4"} {
		if !gate.TryAcquire(profileID) {
			t.Fatalf("failed to acquire %s", profileID)
		}
	}
	if gate.TryAcquire("p1") {
		t.Fatal("same profile metadata refresh re-entered")
	}
	if gate.TryAcquire("p5") {
		t.Fatal("global metadata refresh budget exceeded")
	}

	gate.Release("p2")
	if !gate.TryAcquire("p5") {
		t.Fatal("released metadata slot was not reusable")
	}
	gate.Release("p1")
	gate.Release("p3")
	gate.Release("p4")
	gate.Release("p5")
}

func postProfileMetadataRefresh(
	t *testing.T,
	baseURL string,
	expectedRevision uint64,
) apiv1.ProfileMetadataResponse {
	t.Helper()
	body, err := json.Marshal(apiv1.ProfileMetadataRefreshRequest{
		ExpectedSourceRevision: expectedRevision,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.Post(
		baseURL+"/v1/profiles/profile-a/metadata/refresh",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		var apiErr apiv1.ErrorResponse
		_ = json.NewDecoder(response.Body).Decode(&apiErr)
		t.Fatalf("metadata refresh status = %d error=%q", response.StatusCode, apiErr.Error)
	}
	var result apiv1.ProfileMetadataResponse
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func newDaemonProfileMetadataStore(t *testing.T, ctx context.Context) *storage.Store {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(ctx, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
