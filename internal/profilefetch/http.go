package profilefetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

const (
	DefaultMaxBodyBytes    = int64(16 << 20)
	DefaultTimeout         = 30 * time.Second
	DefaultMetadataTimeout = 5 * time.Second
	DefaultMaxRedirects    = 5
)

var (
	ErrUnsupportedSourceLocation = errors.New("profile source location is not supported by HTTP fetcher")
	ErrUnsupportedFetchMode      = errors.New("profile fetch mode is not supported")
	ErrSelectedProxyUnavailable  = errors.New("selected fetch proxy is unavailable")
	ErrFetchTimeout              = errors.New("profile fetch timed out")
	ErrFetchNetwork              = errors.New("profile fetch network failure")
	ErrFetchTooLarge             = errors.New("profile fetch response exceeds size limit")
	ErrFetchRedirect             = errors.New("profile fetch redirect policy rejected response")
	ErrInvalidFetchMetadata      = errors.New("profile fetch response metadata is invalid")
)

type HTTPOptions struct {
	SelectedProxy netip.AddrPort
	Timeout       time.Duration
	MaxBodyBytes  int64
	MaxRedirects  int
	DefaultUA     string
}

func DefaultHTTPOptions() HTTPOptions {
	return HTTPOptions{
		Timeout:      DefaultTimeout,
		MaxBodyBytes: DefaultMaxBodyBytes,
		MaxRedirects: DefaultMaxRedirects,
		DefaultUA:    "karing-tui-v2",
	}
}

type ConditionalRequest struct {
	ETag         string
	LastModified string
}

type Result struct {
	Body                  []byte
	NotModified           bool
	ETag                  string
	LastModified          string
	SubscriptionUsage     *profile.SubscriptionUsage
	UsageMetadataObserved bool
	UsageMetadataError    string
}

type MetadataResult struct {
	SubscriptionUsage     *profile.SubscriptionUsage
	UsageMetadataObserved bool
	UsageMetadataError    string
}

type HTTPStatusError struct {
	StatusCode int
	RetryAfter *time.Time
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("profile fetch returned HTTP status %d", e.StatusCode)
}

type HTTPFetcher struct {
	options HTTPOptions
}

func NewHTTPFetcher(options HTTPOptions) (*HTTPFetcher, error) {
	if options.Timeout <= 0 {
		return nil, errors.New("profile fetch timeout must be positive")
	}
	if options.MaxBodyBytes <= 0 {
		return nil, errors.New("profile fetch body limit must be positive")
	}
	if options.MaxRedirects < 0 || options.MaxRedirects > 20 {
		return nil, errors.New("profile fetch redirect limit must be between 0 and 20")
	}
	if options.SelectedProxy.IsValid() {
		if !options.SelectedProxy.Addr().IsLoopback() || options.SelectedProxy.Port() == 0 {
			return nil, errors.New("selected profile fetch proxy must be a non-zero loopback address")
		}
	}
	if err := validateHeaderValue("default User-Agent", options.DefaultUA); err != nil {
		return nil, err
	}
	return &HTTPFetcher{options: options}, nil
}

func (f *HTTPFetcher) Fetch(
	ctx context.Context,
	spec profile.SourceSpec,
	conditional ConditionalRequest,
) (Result, error) {
	if f == nil {
		return Result{}, errors.New("profile HTTP fetcher is nil")
	}
	if err := spec.Validate(); err != nil {
		return Result{}, err
	}
	if spec.LocationKind != profile.SourceLocationURL {
		return Result{}, ErrUnsupportedSourceLocation
	}
	if err := validateHeaderValue("ETag", conditional.ETag); err != nil {
		return Result{}, err
	}
	if err := validateHeaderValue("Last-Modified", conditional.LastModified); err != nil {
		return Result{}, err
	}

	proxy, err := f.proxyFor(spec.Fetch)
	if err != nil {
		return Result{}, err
	}
	transport := newHTTPTransport(proxy)
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > f.options.MaxRedirects {
				return ErrFetchRedirect
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return ErrFetchRedirect
			}
			if req.URL.User != nil {
				return ErrFetchRedirect
			}
			return nil
		},
	}

	fetchCtx, cancel := context.WithTimeout(ctx, f.options.Timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, spec.Location, nil)
	if err != nil {
		return Result{}, errors.New("profile fetch URL could not be prepared")
	}
	userAgent := spec.UserAgent
	if userAgent == "" {
		userAgent = f.options.DefaultUA
	}
	if userAgent != "" {
		request.Header.Set("User-Agent", userAgent)
	}
	if conditional.ETag != "" {
		request.Header.Set("If-None-Match", conditional.ETag)
	}
	if conditional.LastModified != "" {
		request.Header.Set("If-Modified-Since", conditional.LastModified)
	}
	request.Header.Set("Accept", "*/*")

	response, err := client.Do(request)
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded), errors.Is(fetchCtx.Err(), context.DeadlineExceeded):
			return Result{}, ErrFetchTimeout
		case errors.Is(err, ErrFetchRedirect):
			return Result{}, ErrFetchRedirect
		default:
			return Result{}, ErrFetchNetwork
		}
	}
	defer response.Body.Close()

	etag, err := responseMetadata(response.Header.Get("ETag"), conditional.ETag)
	if err != nil {
		return Result{}, err
	}
	lastModified, err := responseMetadata(response.Header.Get("Last-Modified"), conditional.LastModified)
	if err != nil {
		return Result{}, err
	}
	usage, usageObserved, usageErr := profile.ParseSubscriptionUserinfo(
		response.Header.Get("Subscription-Userinfo"),
	)
	usageError := ""
	if usageErr != nil {
		usageError = usageErr.Error()
	}

	switch response.StatusCode {
	case http.StatusNotModified:
		drainResponse(response.Body)
		return Result{
			NotModified:           true,
			ETag:                  etag,
			LastModified:          lastModified,
			SubscriptionUsage:     usage,
			UsageMetadataObserved: usageObserved,
			UsageMetadataError:    usageError,
		}, nil
	case http.StatusOK:
		body, err := readBoundedBody(response.Body, f.options.MaxBodyBytes)
		if err != nil {
			return Result{}, err
		}
		return Result{
			Body:                  body,
			ETag:                  etag,
			LastModified:          lastModified,
			SubscriptionUsage:     usage,
			UsageMetadataObserved: usageObserved,
			UsageMetadataError:    usageError,
		}, nil
	default:
		retryAfter := parseRetryAfter(response.Header.Get("Retry-After"), time.Now().UTC())
		drainResponse(response.Body)
		return Result{}, &HTTPStatusError{
			StatusCode: response.StatusCode,
			RetryAfter: retryAfter,
		}
	}
}

func (f *HTTPFetcher) FetchMetadata(
	ctx context.Context,
	spec profile.SourceSpec,
) (MetadataResult, error) {
	if f == nil {
		return MetadataResult{}, errors.New("profile HTTP fetcher is nil")
	}
	if err := spec.Validate(); err != nil {
		return MetadataResult{}, err
	}
	if spec.LocationKind != profile.SourceLocationURL {
		return MetadataResult{}, ErrUnsupportedSourceLocation
	}

	proxy, err := f.proxyFor(spec.Fetch)
	if err != nil {
		return MetadataResult{}, err
	}
	transport := newHTTPTransport(proxy)
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > f.options.MaxRedirects {
				return ErrFetchRedirect
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return ErrFetchRedirect
			}
			if req.URL.User != nil {
				return ErrFetchRedirect
			}
			return nil
		},
	}

	fetchCtx, cancel := context.WithTimeout(ctx, metadataFetchTimeout(f.options.Timeout))
	defer cancel()

	request, err := http.NewRequestWithContext(fetchCtx, http.MethodHead, spec.Location, nil)
	if err != nil {
		return MetadataResult{}, errors.New("profile metadata URL could not be prepared")
	}
	userAgent := spec.UserAgent
	if userAgent == "" {
		userAgent = f.options.DefaultUA
	}
	if userAgent != "" {
		request.Header.Set("User-Agent", userAgent)
	}
	request.Header.Set("Accept", "*/*")

	response, err := client.Do(request)
	if err != nil {
		switch {
		case errors.Is(err, context.DeadlineExceeded), errors.Is(fetchCtx.Err(), context.DeadlineExceeded):
			return MetadataResult{}, ErrFetchTimeout
		case errors.Is(err, ErrFetchRedirect):
			return MetadataResult{}, ErrFetchRedirect
		default:
			return MetadataResult{}, ErrFetchNetwork
		}
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		retryAfter := parseRetryAfter(response.Header.Get("Retry-After"), time.Now().UTC())
		drainResponse(response.Body)
		return MetadataResult{}, &HTTPStatusError{
			StatusCode: response.StatusCode,
			RetryAfter: retryAfter,
		}
	}

	usage, observed, usageErr := profile.ParseSubscriptionUserinfo(
		response.Header.Get("Subscription-Userinfo"),
	)
	usageError := ""
	if usageErr != nil {
		usageError = usageErr.Error()
	}
	drainResponse(response.Body)
	return MetadataResult{
		SubscriptionUsage:     usage,
		UsageMetadataObserved: observed,
		UsageMetadataError:    usageError,
	}, nil
}

func (f *HTTPFetcher) proxyFor(policy profile.FetchPolicy) (*url.URL, error) {
	switch policy.Mode {
	case profile.FetchDirect:
		return nil, nil
	case profile.FetchSelected:
		if !f.options.SelectedProxy.IsValid() ||
			!f.options.SelectedProxy.Addr().IsLoopback() ||
			f.options.SelectedProxy.Port() == 0 {
			return nil, ErrSelectedProxyUnavailable
		}
		return &url.URL{
			Scheme: "http",
			Host:   f.options.SelectedProxy.String(),
		}, nil
	case profile.FetchSpecificNode:
		return nil, ErrUnsupportedFetchMode
	default:
		return nil, ErrUnsupportedFetchMode
	}
}

func newHTTPTransport(proxy *url.URL) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           8,
		MaxIdleConnsPerHost:    2,
		IdleConnTimeout:        30 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ResponseHeaderTimeout:  20 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 1 << 20,
	}
	if proxy != nil {
		transport.Proxy = http.ProxyURL(proxy)
	}
	return transport
}

func readBoundedBody(reader io.Reader, limit int64) ([]byte, error) {
	limited := io.LimitReader(reader, limit+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, ErrFetchNetwork
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: limit %d bytes", ErrFetchTooLarge, limit)
	}
	return body, nil
}

func drainResponse(reader io.Reader) {
	_, _ = io.Copy(io.Discard, io.LimitReader(reader, 8<<10))
}

func responseMetadata(value, fallback string) (string, error) {
	if value == "" {
		value = fallback
	}
	if err := validateHeaderValue("response metadata", value); err != nil {
		return "", err
	}
	return value, nil
}

func validateHeaderValue(label, value string) error {
	if len(value) > 4096 {
		return fmt.Errorf("%w: %s exceeds 4096 bytes", ErrInvalidFetchMetadata, label)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalidFetchMetadata, label)
		}
	}
	return nil
}

func metadataFetchTimeout(configured time.Duration) time.Duration {
	if configured > DefaultMetadataTimeout {
		return DefaultMetadataTimeout
	}
	return configured
}

func parseRetryAfter(value string, now time.Time) *time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return nil
		}
		target := now.Add(time.Duration(seconds) * time.Second).UTC()
		return &target
	}
	if parsed, err := http.ParseTime(value); err == nil {
		target := parsed.UTC()
		return &target
	}
	return nil
}
