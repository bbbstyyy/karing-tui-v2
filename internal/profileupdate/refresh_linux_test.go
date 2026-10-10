//go:build linux

package profileupdate

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/profilefetch"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestRefreshProfileSourceHTTPCommitThenNotModified(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := requests.Add(1)
		if request == 1 {
			w.Header().Set("ETag", "\"v1\"")
			w.Header().Set("Last-Modified", "Wed, 07 Oct 2026 16:00:00 GMT")
			_, _ = w.Write([]byte(validHTTPProfile(8080)))
			return
		}
		if r.Header.Get("If-None-Match") != "\"v1\"" {
			t.Errorf("If-None-Match = %q", r.Header.Get("If-None-Match"))
		}
		if r.Header.Get("If-Modified-Since") != "Wed, 07 Oct 2026 16:00:00 GMT" {
			t.Errorf("If-Modified-Since = %q", r.Header.Get("If-Modified-Since"))
		}
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	source, err := store.CommitProfileSource(ctx, 0, remoteSingBoxSource("profile-a", server.URL))
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := profilefetch.NewSourceFetcher(profilefetch.DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}

	first, err := RefreshProfileSource(
		ctx,
		store,
		fetcher,
		"profile-a",
		source.Revision,
		"refresh-1",
		Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if first.NotModified || len(first.Nodes) != 1 || first.Nodes[0].Port != 8080 {
		t.Fatalf("first refresh = %+v", first)
	}
	firstSnapshotID := first.Commit.Snapshot.ID
	if first.SourceAfter.CurrentSnapshotID == nil ||
		*first.SourceAfter.CurrentSnapshotID != firstSnapshotID ||
		first.SourceAfter.LastSourceRevision != "etag:\"v1\"" ||
		first.SourceAfter.ETag != "\"v1\"" {
		t.Fatalf("first source state = %+v", first.SourceAfter)
	}

	second, err := RefreshProfileSource(
		ctx,
		store,
		fetcher,
		"profile-a",
		source.Revision,
		"refresh-2",
		Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !second.NotModified || second.Commit.Snapshot.ID != 0 || len(second.Nodes) != 0 {
		t.Fatalf("304 refresh = %+v", second)
	}
	if second.SourceAfter.CurrentSnapshotID == nil ||
		*second.SourceAfter.CurrentSnapshotID != firstSnapshotID ||
		second.SourceAfter.LastSourceRevision != first.SourceAfter.LastSourceRevision ||
		second.SourceAfter.ConsecutiveFailures != 0 {
		t.Fatalf("304 source state = %+v", second.SourceAfter)
	}
	if _, ok, err := store.PreviousProfileSnapshot(ctx, "profile-a"); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatal("304 unexpectedly created a second snapshot")
	}
}

func TestRefreshProfileSourcePersistsUsageAndKeepsLastGoodUsageOnMalformedHeader(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	var malformed atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if malformed.Load() {
			w.Header().Set("Subscription-Userinfo", "upload=invalid")
			_, _ = w.Write([]byte(validHTTPProfile(9090)))
			return
		}
		w.Header().Set(
			"Subscription-Userinfo",
			"upload=1024; download=2048; total=4096; expire=1798761600",
		)
		_, _ = w.Write([]byte(validHTTPProfile(8080)))
	}))
	defer server.Close()

	source, err := store.CommitProfileSource(ctx, 0, remoteSingBoxSource("profile-a", server.URL))
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := profilefetch.NewSourceFetcher(profilefetch.DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	first, err := RefreshProfileSource(ctx, store, fetcher, "profile-a", source.Revision, "usage-1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Nodes) != 1 || first.Nodes[0].Port != 8080 ||
		first.SourceAfter.SubscriptionUsage == nil ||
		first.SourceAfter.SubscriptionUsage.TotalBytes == nil ||
		*first.SourceAfter.SubscriptionUsage.TotalBytes != 4096 ||
		first.SourceAfter.LastMetadataError != "" {
		t.Fatalf("first usage refresh = %+v", first)
	}
	firstUsageUpdated := first.SourceAfter.SubscriptionUsageUpdatedAt
	if firstUsageUpdated == nil {
		t.Fatal("first usage refresh did not record metadata timestamp")
	}

	malformed.Store(true)
	second, err := RefreshProfileSource(ctx, store, fetcher, "profile-a", source.Revision, "usage-2", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Nodes) != 1 || second.Nodes[0].Port != 9090 {
		t.Fatalf("malformed metadata blocked node refresh: %+v", second.Nodes)
	}
	if second.SourceAfter.SubscriptionUsage == nil ||
		second.SourceAfter.SubscriptionUsage.TotalBytes == nil ||
		*second.SourceAfter.SubscriptionUsage.TotalBytes != 4096 ||
		second.SourceAfter.SubscriptionUsageUpdatedAt == nil ||
		!second.SourceAfter.SubscriptionUsageUpdatedAt.Equal(*firstUsageUpdated) ||
		second.SourceAfter.LastMetadataError == "" {
		t.Fatalf("malformed metadata replaced last good usage: %+v", second.SourceAfter)
	}
}

func TestRefreshProfileSourceHTTPFailurePreservesSnapshotAndRetryAfter(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	var fail atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("secret remote body"))
			return
		}
		w.Header().Set("ETag", "\"v1\"")
		_, _ = w.Write([]byte(validHTTPProfile(8080)))
	}))
	defer server.Close()

	source, err := store.CommitProfileSource(ctx, 0, remoteSingBoxSource("profile-a", server.URL+"?token=hidden"))
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := profilefetch.NewSourceFetcher(profilefetch.DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	first, err := RefreshProfileSource(ctx, store, fetcher, "profile-a", source.Revision, "refresh-1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	snapshotID := first.Commit.Snapshot.ID

	fail.Store(true)
	before := time.Now().UTC().Add(59 * time.Second)
	failed, err := RefreshProfileSource(ctx, store, fetcher, "profile-a", source.Revision, "refresh-2", Options{})
	after := time.Now().UTC().Add(61 * time.Second)
	var statusErr *profilefetch.HTTPStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("429 refresh error = %v", err)
	}
	if failed.SourceAfter.Revision != 0 {
		t.Fatalf("failed refresh unexpectedly populated SourceAfter: %+v", failed.SourceAfter)
	}

	state, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.CurrentSnapshotID == nil || *state.CurrentSnapshotID != snapshotID ||
		state.ConsecutiveFailures != 1 ||
		state.ActiveUpdateID != "" ||
		state.RetryAfterAt == nil ||
		state.RetryAfterAt.Before(before) ||
		state.RetryAfterAt.After(after) {
		t.Fatalf("429 source state = %+v", state)
	}
	if strings.Contains(state.LastError, "secret remote body") ||
		strings.Contains(state.LastError, "token=hidden") {
		t.Fatalf("failure state leaked remote/source secret: %q", state.LastError)
	}
}

func TestRefreshProfileSourceImportFailurePreservesAcceptedSnapshot(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	var invalid atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if invalid.Load() {
			_, _ = w.Write([]byte(`{
  "outbounds":[{"type":"hysteria2","tag":"unsupported","server":"example.com","server_port":443,"password":"secret"}]
}`))
			return
		}
		_, _ = w.Write([]byte(validHTTPProfile(8080)))
	}))
	defer server.Close()

	source, err := store.CommitProfileSource(ctx, 0, remoteSingBoxSource("profile-a", server.URL))
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := profilefetch.NewSourceFetcher(profilefetch.DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	first, err := RefreshProfileSource(ctx, store, fetcher, "profile-a", source.Revision, "refresh-1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	snapshotID := first.Commit.Snapshot.ID

	invalid.Store(true)
	failed, err := RefreshProfileSource(ctx, store, fetcher, "profile-a", source.Revision, "refresh-2", Options{})
	if !errors.Is(err, ErrImportBlocked) {
		t.Fatalf("unsupported import error = %v", err)
	}
	if !failed.Analysis.HasBlockingDiagnostics() {
		t.Fatalf("blocked refresh diagnostics = %+v", failed.Analysis.Diagnostics)
	}
	state, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.CurrentSnapshotID == nil || *state.CurrentSnapshotID != snapshotID ||
		state.ConsecutiveFailures != 1 ||
		state.ActiveUpdateID != "" {
		t.Fatalf("blocked import source state = %+v", state)
	}
	current, ok, err := store.CurrentProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current.ID != snapshotID {
		t.Fatalf("blocked import changed current snapshot: %+v ok=%v", current, ok)
	}
}

func TestRefreshProfileSourceFileUsesContentHashRevision(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte(validHTTPProfile(8080)), 0o600); err != nil {
		t.Fatal(err)
	}
	sourceSpec := profile.SourceSpec{
		ProfileID:    "profile-a",
		Format:       profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationFile,
		Location:     path,
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	}
	source, err := store.CommitProfileSource(ctx, 0, sourceSpec)
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := profilefetch.NewSourceFetcher(profilefetch.DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}

	first, err := RefreshProfileSource(ctx, store, fetcher, "profile-a", source.Revision, "file-1", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first.Commit.Snapshot.SourceRevision, "sha256:") ||
		first.Commit.Snapshot.SourceRevision != first.SourceAfter.LastSourceRevision {
		t.Fatalf("file source revision = %q state=%q", first.Commit.Snapshot.SourceRevision, first.SourceAfter.LastSourceRevision)
	}
	firstNodeID := first.Nodes[0].NodeID

	if err := os.WriteFile(path, []byte(validHTTPProfile(9090)), 0o600); err != nil {
		t.Fatal(err)
	}
	second, err := RefreshProfileSource(ctx, store, fetcher, "profile-a", source.Revision, "file-2", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Nodes[0].Port != 9090 || second.Nodes[0].NodeID != firstNodeID {
		t.Fatalf("updated file nodes = %+v", second.Nodes)
	}
	if second.Commit.Snapshot.SourceRevision == first.Commit.Snapshot.SourceRevision {
		t.Fatalf("changed file reused content revision %q", second.Commit.Snapshot.SourceRevision)
	}
	previous, ok, err := store.PreviousProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || previous.ID != first.Commit.Snapshot.ID {
		t.Fatalf("previous file snapshot = %+v ok=%v", previous, ok)
	}
}

func TestRefreshProfileSourceNotModifiedWithoutSnapshotFailsLease(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	source, err := store.CommitProfileSource(ctx, 0, remoteSingBoxSource("profile-a", "https://example.com/sub"))
	if err != nil {
		t.Fatal(err)
	}
	fetcher := staticFetcher{result: profilefetch.Result{NotModified: true, ETag: "\"v1\""}}
	_, err = RefreshProfileSource(ctx, store, fetcher, "profile-a", source.Revision, "refresh-1", Options{})
	if !errors.Is(err, ErrNotModifiedWithoutSnapshot) {
		t.Fatalf("304 without snapshot error = %v", err)
	}
	state, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveUpdateID != "" || state.ConsecutiveFailures != 1 || state.CurrentSnapshotID != nil {
		t.Fatalf("304 without snapshot state = %+v", state)
	}
}

func TestRefreshProfileSourceCancellationReleasesDurableLease(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	source, err := store.CommitProfileSource(
		ctx,
		0,
		remoteSingBoxSource("profile-a", "https://example.com/sub"),
	)
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &blockingFetcher{
		started: make(chan struct{}),
		release: make(chan struct{}),
		result:  profilefetch.Result{Body: []byte(validHTTPProfile(8080))},
	}

	refreshCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := RefreshProfileSource(
			refreshCtx,
			store,
			fetcher,
			"profile-a",
			source.Revision,
			"cancel-1",
			Options{},
		)
		done <- err
	}()

	select {
	case <-fetcher.started:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh did not reach cancellable fetch")
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled refresh error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled refresh did not return")
	}

	state, err := store.ProfileSource(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveUpdateID != "" ||
		state.ActiveUpdateStarted != nil ||
		state.ConsecutiveFailures != 1 ||
		!strings.Contains(state.LastError, "context canceled") {
		t.Fatalf("canceled refresh left durable lease/state: %+v", state)
	}

	next, err := store.BeginProfileUpdate(ctx, "profile-a", source.Revision, "cancel-retry")
	if err != nil {
		t.Fatal(err)
	}
	if next.ID != "cancel-retry" {
		t.Fatalf("post-cancel retry lease = %+v", next)
	}
	if err := store.FinishProfileUpdateFailure(ctx, next, "cleanup", nil); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshProfileSourceURIListPreservesIdentityAndBlocksPartialUpdate(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	var version atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch version.Load() {
		case 0:
			_, _ = w.Write([]byte(
				"ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#Before",
			))
		case 1:
			_, _ = w.Write([]byte(
				"ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#After",
			))
		default:
			_, _ = w.Write([]byte(strings.Join([]string{
				"ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#After",
				"vmess://unsupported",
			}, "\n")))
		}
	}))
	defer server.Close()

	source, err := store.CommitProfileSource(
		ctx,
		0,
		remoteURIListSource("profile-uri", server.URL),
	)
	if err != nil {
		t.Fatal(err)
	}
	fetcher, err := profilefetch.NewSourceFetcher(profilefetch.DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}

	first, err := RefreshProfileSource(
		ctx,
		store,
		fetcher,
		"profile-uri",
		source.Revision,
		"uri-refresh-1",
		Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Nodes) != 1 ||
		first.Nodes[0].Shadowsocks == nil ||
		first.Nodes[0].Shadowsocks.Method != "aes-256-gcm" ||
		first.Nodes[0].Shadowsocks.Password != "secret" ||
		first.Commit.Snapshot.SourceKind != string(profile.SourceFormatURIList) ||
		first.Commit.Snapshot.Nodes[0].Identity.SourceName != "Before" {
		t.Fatalf("first URI-list refresh = %+v", first)
	}
	nodeID := first.Nodes[0].NodeID

	version.Store(1)
	second, err := RefreshProfileSource(
		ctx,
		store,
		fetcher,
		"profile-uri",
		source.Revision,
		"uri-refresh-2",
		Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Nodes) != 1 ||
		second.Nodes[0].NodeID != nodeID ||
		second.Commit.Snapshot.Nodes[0].Identity.SourceName != "After" {
		t.Fatalf("renamed URI-list refresh = %+v", second)
	}
	secondSnapshotID := second.Commit.Snapshot.ID

	version.Store(2)
	blocked, err := RefreshProfileSource(
		ctx,
		store,
		fetcher,
		"profile-uri",
		source.Revision,
		"uri-refresh-3",
		Options{},
	)
	if !errors.Is(err, ErrImportBlocked) {
		t.Fatalf("partial URI-list refresh error = %v", err)
	}
	if !blocked.Analysis.HasBlockingDiagnostics() {
		t.Fatalf("partial URI-list refresh diagnostics = %+v", blocked.Analysis.Diagnostics)
	}
	current, ok, err := store.CurrentProfileSnapshot(ctx, "profile-uri")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current.ID != secondSnapshotID {
		t.Fatalf("blocked URI-list refresh changed snapshot: %+v ok=%v", current, ok)
	}
	state, err := store.ProfileSource(ctx, "profile-uri")
	if err != nil {
		t.Fatal(err)
	}
	if state.ConsecutiveFailures != 1 {
		t.Fatalf("blocked URI-list refresh failure state = %+v", state)
	}
}

func TestRefreshProfileSourceBase64URIListPersistsCanonicalNodeAcrossReopen(t *testing.T) {
	ctx := context.Background()
	store, path := newProfileUpdateStore(t, ctx)
	source, err := store.CommitProfileSource(ctx, 0, profile.SourceSpec{
		ProfileID:    "profile-base64",
		Format:       profile.SourceFormatBase64URIList,
		LocationKind: profile.SourceLocationURL,
		Location:     "https://example.com/base64-subscription",
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	original := "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#Before"
	renamed := "ss://YWVzLTI1Ni1nY206c2VjcmV0@ss.example.com:8388#After"
	first, err := RefreshProfileSource(
		ctx,
		store,
		staticFetcher{result: profilefetch.Result{
			Body: []byte(base64.StdEncoding.EncodeToString([]byte(original))),
		}},
		source.Spec.ProfileID,
		source.Revision,
		"base64-refresh-1",
		Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Nodes) != 1 ||
		first.Nodes[0].Shadowsocks == nil ||
		first.Nodes[0].Shadowsocks.Password != "secret" ||
		first.Commit.Snapshot.SourceKind != string(profile.SourceFormatBase64URIList) ||
		first.Commit.Snapshot.Nodes[0].Identity.SourceName != "Before" {
		t.Fatalf("first base64 refresh = %+v", first)
	}
	nodeID := first.Nodes[0].NodeID
	if !strings.Contains(
		string(first.Commit.Snapshot.Nodes[0].PayloadJSON),
		`"type":"shadowsocks"`,
	) {
		t.Fatalf("base64 snapshot did not retain canonical node payload")
	}

	second, err := RefreshProfileSource(
		ctx,
		store,
		staticFetcher{result: profilefetch.Result{
			Body: []byte(base64.RawURLEncoding.EncodeToString([]byte(renamed))),
		}},
		source.Spec.ProfileID,
		source.Revision,
		"base64-refresh-2",
		Options{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Nodes) != 1 ||
		second.Nodes[0].NodeID != nodeID ||
		second.Commit.Snapshot.Nodes[0].Identity.SourceName != "After" {
		t.Fatalf("base64 re-encoded profile lost node identity: %+v", second)
	}
	snapshotID := second.Commit.Snapshot.ID

	unsupported := renamed + "\nvmess://unsupported"
	blocked, err := RefreshProfileSource(
		ctx,
		store,
		staticFetcher{result: profilefetch.Result{
			Body: []byte(base64.StdEncoding.EncodeToString([]byte(unsupported))),
		}},
		source.Spec.ProfileID,
		source.Revision,
		"base64-refresh-3",
		Options{},
	)
	if !errors.Is(err, ErrImportBlocked) ||
		!blocked.Analysis.HasBlockingDiagnostics() {
		t.Fatalf("unsupported base64 URI-list error=%v diagnostics=%+v",
			err, blocked.Analysis.Diagnostics)
	}
	current, ok, err := store.CurrentProfileSnapshot(ctx, source.Spec.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current.ID != snapshotID {
		t.Fatalf("blocked base64 subscription changed snapshot: %+v ok=%v", current, ok)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	retained, err := reopened.ProfileSnapshotByID(ctx, source.Spec.ProfileID, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := MaterializeBasicProfileSnapshot(retained)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].NodeID != nodeID ||
		nodes[0].Shadowsocks == nil || nodes[0].Shadowsocks.Password != "secret" {
		t.Fatalf("reopened base64 snapshot nodes = %+v", nodes)
	}
}

func TestRefreshProfileSourceRejectsConcurrentSameProfileUpdate(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	source, err := store.CommitProfileSource(ctx, 0, remoteSingBoxSource("profile-a", "https://example.com/sub"))
	if err != nil {
		t.Fatal(err)
	}
	fetcher := &blockingFetcher{
		started: make(chan struct{}),
		release: make(chan struct{}),
		result:  profilefetch.Result{Body: []byte(validHTTPProfile(8080))},
	}
	firstDone := make(chan error, 1)
	go func() {
		_, err := RefreshProfileSource(
			ctx,
			store,
			fetcher,
			"profile-a",
			source.Revision,
			"refresh-1",
			Options{},
		)
		firstDone <- err
	}()

	select {
	case <-fetcher.started:
	case <-time.After(2 * time.Second):
		t.Fatal("first refresh did not reach fetch")
	}

	_, err = RefreshProfileSource(
		ctx,
		store,
		fetcher,
		"profile-a",
		source.Revision,
		"refresh-2",
		Options{},
	)
	if !errors.Is(err, storage.ErrProfileUpdateInProgress) {
		t.Fatalf("concurrent refresh error = %v", err)
	}
	close(fetcher.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first refresh after release: %v", err)
	}
}

type staticFetcher struct {
	result profilefetch.Result
	err    error
}

func (f staticFetcher) Fetch(
	context.Context,
	profile.SourceSpec,
	profilefetch.ConditionalRequest,
) (profilefetch.Result, error) {
	return f.result, f.err
}

type blockingFetcher struct {
	started chan struct{}
	release chan struct{}
	result  profilefetch.Result
}

func (f *blockingFetcher) Fetch(
	ctx context.Context,
	_ profile.SourceSpec,
	_ profilefetch.ConditionalRequest,
) (profilefetch.Result, error) {
	close(f.started)
	select {
	case <-ctx.Done():
		return profilefetch.Result{}, ctx.Err()
	case <-f.release:
		return f.result, nil
	}
}

func remoteSingBoxSource(profileID, location string) profile.SourceSpec {
	return profile.SourceSpec{
		ProfileID:    profileID,
		Format:       profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationURL,
		Location:     location,
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	}
}

func remoteURIListSource(profileID, location string) profile.SourceSpec {
	return profile.SourceSpec{
		ProfileID:    profileID,
		Format:       profile.SourceFormatURIList,
		LocationKind: profile.SourceLocationURL,
		Location:     location,
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	}
}

func validHTTPProfile(port int) string {
	return fmt.Sprintf(`{
  "outbounds":[{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":%d}]
}`, port)
}
