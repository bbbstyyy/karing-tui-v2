package profilefetch

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

func TestHTTPFetcherDirectConditionalRequestAndMetadata(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if r.Header.Get("User-Agent") != "profile-test" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		switch call {
		case 1:
			w.Header().Set("ETag", "\"v1\"")
			w.Header().Set("Last-Modified", "Wed, 07 Oct 2026 16:00:00 GMT")
			_, _ = w.Write([]byte("subscription-v1"))
		case 2:
			if r.Header.Get("If-None-Match") != "\"v1\"" {
				t.Errorf("If-None-Match = %q", r.Header.Get("If-None-Match"))
			}
			if r.Header.Get("If-Modified-Since") != "Wed, 07 Oct 2026 16:00:00 GMT" {
				t.Errorf("If-Modified-Since = %q", r.Header.Get("If-Modified-Since"))
			}
			w.WriteHeader(http.StatusNotModified)
		default:
			t.Errorf("unexpected request %d", call)
		}
	}))
	defer server.Close()

	fetcher, err := NewHTTPFetcher(DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	spec := testURLSource(server.URL, profile.FetchPolicy{Mode: profile.FetchDirect})
	spec.UserAgent = "profile-test"

	first, err := fetcher.Fetch(context.Background(), spec, ConditionalRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if first.NotModified || string(first.Body) != "subscription-v1" ||
		first.ETag != "\"v1\"" ||
		first.LastModified != "Wed, 07 Oct 2026 16:00:00 GMT" {
		t.Fatalf("first fetch = %+v", first)
	}

	second, err := fetcher.Fetch(context.Background(), spec, ConditionalRequest{
		ETag:         first.ETag,
		LastModified: first.LastModified,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !second.NotModified || len(second.Body) != 0 ||
		second.ETag != first.ETag ||
		second.LastModified != first.LastModified {
		t.Fatalf("conditional fetch = %+v", second)
	}
}

func TestHTTPFetcherCapturesSubscriptionUsageMetadataWithoutBlockingBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(
			"Subscription-Userinfo",
			"upload=1024; download=2048; total=4096; expire=1798761600",
		)
		_, _ = w.Write([]byte("subscription-v1"))
	}))
	defer server.Close()

	fetcher, err := NewHTTPFetcher(DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	result, err := fetcher.Fetch(
		context.Background(),
		testURLSource(server.URL, profile.FetchPolicy{Mode: profile.FetchDirect}),
		ConditionalRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.UsageMetadataObserved ||
		result.UsageMetadataError != "" ||
		result.SubscriptionUsage == nil ||
		result.SubscriptionUsage.UploadBytes == nil ||
		*result.SubscriptionUsage.UploadBytes != 1024 ||
		result.SubscriptionUsage.DownloadBytes == nil ||
		*result.SubscriptionUsage.DownloadBytes != 2048 ||
		result.SubscriptionUsage.TotalBytes == nil ||
		*result.SubscriptionUsage.TotalBytes != 4096 {
		t.Fatalf("subscription usage result = %+v", result)
	}
}

func TestHTTPFetcherReportsMalformedSubscriptionUsageWithoutFailingFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=not-a-number")
		_, _ = w.Write([]byte("subscription-v1"))
	}))
	defer server.Close()

	fetcher, err := NewHTTPFetcher(DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	result, err := fetcher.Fetch(
		context.Background(),
		testURLSource(server.URL, profile.FetchPolicy{Mode: profile.FetchDirect}),
		ConditionalRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Body) != "subscription-v1" ||
		!result.UsageMetadataObserved ||
		result.SubscriptionUsage != nil ||
		result.UsageMetadataError == "" {
		t.Fatalf("malformed metadata result = %+v", result)
	}
}

func TestHTTPFetcherMetadataUsesHeadAndCapturesUsage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("metadata method = %q, want HEAD", r.Method)
		}
		if r.Header.Get("User-Agent") != "metadata-test" {
			t.Errorf("metadata User-Agent = %q", r.Header.Get("User-Agent"))
		}
		w.Header().Set(
			"Subscription-Userinfo",
			"upload=11; download=22; total=33; expire=1798761600",
		)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fetcher, err := NewHTTPFetcher(DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	spec := testURLSource(server.URL, profile.FetchPolicy{Mode: profile.FetchDirect})
	spec.UserAgent = "metadata-test"
	result, err := fetcher.FetchMetadata(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !result.UsageMetadataObserved ||
		result.UsageMetadataError != "" ||
		result.SubscriptionUsage == nil ||
		result.SubscriptionUsage.UploadBytes == nil ||
		*result.SubscriptionUsage.UploadBytes != 11 ||
		result.SubscriptionUsage.DownloadBytes == nil ||
		*result.SubscriptionUsage.DownloadBytes != 22 ||
		result.SubscriptionUsage.TotalBytes == nil ||
		*result.SubscriptionUsage.TotalBytes != 33 {
		t.Fatalf("metadata result = %+v", result)
	}
}

func TestHTTPFetcherMetadataMalformedHeaderDoesNotBecomeNetworkFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=bad")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fetcher, err := NewHTTPFetcher(DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	result, err := fetcher.FetchMetadata(
		context.Background(),
		testURLSource(server.URL, profile.FetchPolicy{Mode: profile.FetchDirect}),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !result.UsageMetadataObserved ||
		result.SubscriptionUsage != nil ||
		result.UsageMetadataError == "" {
		t.Fatalf("malformed metadata result = %+v", result)
	}
}

func TestHTTPFetcherMetadataRequiresHTTP200AndCapturesRetryAfter(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	fetcher, err := NewHTTPFetcher(DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(119 * time.Second)
	_, err = fetcher.FetchMetadata(
		context.Background(),
		testURLSource(server.URL, profile.FetchPolicy{Mode: profile.FetchDirect}),
	)
	after := time.Now().UTC().Add(121 * time.Second)
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("metadata status error = %v", err)
	}
	if statusErr.StatusCode != http.StatusMethodNotAllowed ||
		statusErr.RetryAfter == nil ||
		statusErr.RetryAfter.Before(before) ||
		statusErr.RetryAfter.After(after) {
		t.Fatalf("metadata Retry-After = %+v", statusErr)
	}
}

func TestHTTPFetcherMetadataUsesSelectedProxyAndSpecificNodeFailsClosed(t *testing.T) {
	proxyRequests := make(chan string, 1)
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("proxied metadata method = %q, want HEAD", r.Method)
		}
		proxyRequests <- r.URL.String()
		w.Header().Set("Subscription-Userinfo", "total=4096")
		w.WriteHeader(http.StatusOK)
	}))
	defer proxyServer.Close()

	addrPort, err := netip.ParseAddrPort(strings.TrimPrefix(proxyServer.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	options := DefaultHTTPOptions()
	options.SelectedProxy = addrPort
	fetcher, err := NewHTTPFetcher(options)
	if err != nil {
		t.Fatal(err)
	}
	selected := testURLSource(
		"http://origin.invalid/subscription?token=hidden",
		profile.FetchPolicy{Mode: profile.FetchSelected},
	)
	result, err := fetcher.FetchMetadata(context.Background(), selected)
	if err != nil {
		t.Fatal(err)
	}
	if result.SubscriptionUsage == nil ||
		result.SubscriptionUsage.TotalBytes == nil ||
		*result.SubscriptionUsage.TotalBytes != 4096 {
		t.Fatalf("selected metadata result = %+v", result)
	}
	select {
	case target := <-proxyRequests:
		if !strings.Contains(target, "origin.invalid/subscription") {
			t.Fatalf("metadata proxy target = %q", target)
		}
	case <-time.After(time.Second):
		t.Fatal("selected proxy did not receive metadata request")
	}

	specific := selected
	specific.Fetch = profile.FetchPolicy{
		Mode:      profile.FetchSpecificNode,
		ProfileID: "bootstrap",
		NodeID:    "node-1",
	}
	if _, err := fetcher.FetchMetadata(context.Background(), specific); !errors.Is(err, ErrUnsupportedFetchMode) {
		t.Fatalf("specific-node metadata error = %v", err)
	}
}

func TestMetadataFetchTimeoutCapsAtKaringConfirmedFiveSeconds(t *testing.T) {
	if got := metadataFetchTimeout(30 * time.Second); got != DefaultMetadataTimeout {
		t.Fatalf("metadata timeout = %v, want %v", got, DefaultMetadataTimeout)
	}
	if got := metadataFetchTimeout(2 * time.Second); got != 2*time.Second {
		t.Fatalf("short configured metadata timeout = %v, want 2s", got)
	}
}

func TestHTTPFetcherMetadataTimeoutIsCappedAtFiveSeconds(t *testing.T) {
	options := DefaultHTTPOptions()
	options.Timeout = 20 * time.Millisecond
	fetcher, err := NewHTTPFetcher(options)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	_, err = fetcher.FetchMetadata(
		context.Background(),
		testURLSource(server.URL, profile.FetchPolicy{Mode: profile.FetchDirect}),
	)
	if !errors.Is(err, ErrFetchTimeout) {
		t.Fatalf("metadata timeout error = %v", err)
	}
}

func TestHTTPFetcherNeverUsesEnvironmentProxyForDirectMode(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")

	transport := newHTTPTransport(nil)
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil {
		t.Fatal("direct profile fetch transport inherited a proxy callback")
	}
}

func TestHTTPFetcherSelectedModeUsesOnlyConfiguredLoopbackProxy(t *testing.T) {
	proxyRequests := make(chan string, 1)
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyRequests <- r.URL.String()
		w.Header().Set("ETag", "\"proxied\"")
		_, _ = w.Write([]byte("through-selected"))
	}))
	defer proxyServer.Close()

	proxyAddress := strings.TrimPrefix(proxyServer.URL, "http://")
	addrPort, err := netip.ParseAddrPort(proxyAddress)
	if err != nil {
		t.Fatal(err)
	}
	options := DefaultHTTPOptions()
	options.SelectedProxy = addrPort
	fetcher, err := NewHTTPFetcher(options)
	if err != nil {
		t.Fatal(err)
	}

	spec := testURLSource(
		"http://origin.invalid/subscription?token=hidden",
		profile.FetchPolicy{Mode: profile.FetchSelected},
	)
	result, err := fetcher.Fetch(context.Background(), spec, ConditionalRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Body) != "through-selected" || result.ETag != "\"proxied\"" {
		t.Fatalf("selected fetch = %+v", result)
	}
	select {
	case target := <-proxyRequests:
		if !strings.Contains(target, "origin.invalid/subscription") {
			t.Fatalf("proxy target = %q", target)
		}
	case <-time.After(time.Second):
		t.Fatal("configured selected proxy did not receive request")
	}
}

func TestHTTPFetcherSpecificNodeFailsClosed(t *testing.T) {
	fetcher, err := NewHTTPFetcher(DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	spec := testURLSource("https://example.com/subscription", profile.FetchPolicy{
		Mode:      profile.FetchSpecificNode,
		ProfileID: "bootstrap",
		NodeID:    "node-1",
	})
	_, err = fetcher.Fetch(context.Background(), spec, ConditionalRequest{})
	if !errors.Is(err, ErrUnsupportedFetchMode) {
		t.Fatalf("specific-node fetch error = %v", err)
	}
}

func TestHTTPFetcherSelectedWithoutProxyFailsClosed(t *testing.T) {
	fetcher, err := NewHTTPFetcher(DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	spec := testURLSource("https://example.com/subscription", profile.FetchPolicy{Mode: profile.FetchSelected})
	_, err = fetcher.Fetch(context.Background(), spec, ConditionalRequest{})
	if !errors.Is(err, ErrSelectedProxyUnavailable) {
		t.Fatalf("selected fetch without proxy error = %v", err)
	}
}

func TestHTTPFetcherBoundsBodyAndRedirects(t *testing.T) {
	large := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer large.Close()

	options := DefaultHTTPOptions()
	options.MaxBodyBytes = 4
	fetcher, err := NewHTTPFetcher(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.Fetch(
		context.Background(),
		testURLSource(large.URL, profile.FetchPolicy{Mode: profile.FetchDirect}),
		ConditionalRequest{},
	); !errors.Is(err, ErrFetchTooLarge) {
		t.Fatalf("large body error = %v", err)
	}

	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/again", http.StatusFound)
	}))
	defer redirect.Close()
	options = DefaultHTTPOptions()
	options.MaxRedirects = 1
	fetcher, err = NewHTTPFetcher(options)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.Fetch(
		context.Background(),
		testURLSource(redirect.URL, profile.FetchPolicy{Mode: profile.FetchDirect}),
		ConditionalRequest{},
	); !errors.Is(err, ErrFetchRedirect) {
		t.Fatalf("redirect limit error = %v", err)
	}
}

func TestHTTPFetcherCapturesRetryAfterWithoutResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("remote error body should not enter the error string"))
	}))
	defer server.Close()

	fetcher, err := NewHTTPFetcher(DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(119 * time.Second)
	_, err = fetcher.Fetch(
		context.Background(),
		testURLSource(server.URL, profile.FetchPolicy{Mode: profile.FetchDirect}),
		ConditionalRequest{},
	)
	after := time.Now().UTC().Add(121 * time.Second)
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("HTTP status error = %v", err)
	}
	if statusErr.StatusCode != http.StatusTooManyRequests ||
		statusErr.RetryAfter == nil ||
		statusErr.RetryAfter.Before(before) ||
		statusErr.RetryAfter.After(after) {
		t.Fatalf("Retry-After = %+v", statusErr)
	}
	if strings.Contains(statusErr.Error(), "remote error body") {
		t.Fatalf("HTTP error leaked response body: %q", statusErr.Error())
	}
}

func TestHTTPFetcherTimeoutAndErrorsDoNotLeakSourceQuery(t *testing.T) {
	options := DefaultHTTPOptions()
	options.Timeout = 20 * time.Millisecond
	fetcher, err := NewHTTPFetcher(options)
	if err != nil {
		t.Fatal(err)
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte("late"))
	}))
	defer slow.Close()

	_, err = fetcher.Fetch(
		context.Background(),
		testURLSource(slow.URL+"?token=supersecret", profile.FetchPolicy{Mode: profile.FetchDirect}),
		ConditionalRequest{},
	)
	if !errors.Is(err, ErrFetchTimeout) {
		t.Fatalf("timeout error = %v", err)
	}
	if strings.Contains(err.Error(), "supersecret") {
		t.Fatalf("fetch error leaked source query: %q", err.Error())
	}
}

func TestHTTPFetcherValidatesOptionsAndConditionalHeaders(t *testing.T) {
	options := DefaultHTTPOptions()
	options.SelectedProxy = netip.MustParseAddrPort("192.0.2.1:2082")
	if _, err := NewHTTPFetcher(options); err == nil {
		t.Fatal("non-loopback selected proxy was accepted")
	}

	fetcher, err := NewHTTPFetcher(DefaultHTTPOptions())
	if err != nil {
		t.Fatal(err)
	}
	_, err = fetcher.Fetch(
		context.Background(),
		testURLSource("https://example.com/sub", profile.FetchPolicy{Mode: profile.FetchDirect}),
		ConditionalRequest{ETag: "bad\nheader"},
	)
	if !errors.Is(err, ErrInvalidFetchMetadata) {
		t.Fatalf("unsafe conditional metadata error = %v", err)
	}
}

func testURLSource(location string, fetch profile.FetchPolicy) profile.SourceSpec {
	return profile.SourceSpec{
		ProfileID:    "profile-a",
		Format:       profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationURL,
		Location:     location,
		Fetch:        fetch,
		Enabled:      true,
	}
}
