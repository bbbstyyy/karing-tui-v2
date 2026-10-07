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
