package coreapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
)

const maxVersionResponseBytes = 64 << 10

type ClashVersionProbe struct {
	versionURL *url.URL
	secret     string
	client     *http.Client
}

func NewClashVersionProbe(endpoint, secret string) (*ClashVersionProbe, error) {
	if secret == "" {
		return nil, errors.New("core control API secret must not be empty")
	}

	base, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse core control API endpoint: %w", err)
	}
	if base.Scheme != "http" {
		return nil, fmt.Errorf("core control API endpoint must use http on loopback")
	}
	if base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("core control API endpoint must not contain credentials, query, or fragment")
	}
	if base.Path != "" && base.Path != "/" {
		return nil, errors.New("core control API endpoint must not contain a path")
	}

	host := base.Hostname()
	portText := base.Port()
	if host == "" || portText == "" {
		return nil, errors.New("core control API endpoint must include loopback host and port")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.IsLoopback() {
		return nil, errors.New("core control API endpoint must use a loopback IP literal")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("core control API endpoint has invalid port")
	}

	versionURL := *base
	versionURL.Path = "/version"
	versionURL.RawPath = ""
	versionURL.RawQuery = ""
	versionURL.Fragment = ""

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil

	return &ClashVersionProbe{
		versionURL: &versionURL,
		secret:     secret,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("core control API redirect refused")
			},
		},
	}, nil
}

func (p *ClashVersionProbe) Ready(ctx context.Context, _ core.Process) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.versionURL.String(), nil)
	if err != nil {
		return fmt.Errorf("build core version request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+p.secret)
	request.Header.Set("Accept", "application/json")

	response, err := p.client.Do(request)
	if err != nil {
		return fmt.Errorf("query authenticated core version endpoint: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("core version endpoint returned HTTP %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		return fmt.Errorf("core version endpoint returned unexpected content type %q", contentType)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxVersionResponseBytes+1))
	if err != nil {
		return fmt.Errorf("read core version response: %w", err)
	}
	if len(body) > maxVersionResponseBytes {
		return errors.New("core version response exceeds size limit")
	}

	var payload struct {
		Version string `json:"version"`
		Premium bool   `json:"premium"`
		Meta    bool   `json:"meta"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fmt.Errorf("decode core version response: %w", err)
	}
	if !strings.HasPrefix(payload.Version, "sing-box ") || strings.TrimSpace(strings.TrimPrefix(payload.Version, "sing-box ")) == "" {
		return fmt.Errorf("core version response has unexpected version %q", payload.Version)
	}
	if !payload.Premium || !payload.Meta {
		return errors.New("core version response does not match the pinned Clash API contract")
	}
	return nil
}
