package coreapi

import (
	"bytes"
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
)

const maxSelectorResponseBytes = 64 << 10

var errSelectorRedirect = errors.New("core selector API redirect refused")

type SelectorSnapshot struct {
	Now string
	All []string
}

type SelectorClient struct {
	base   *url.URL
	secret string
	client *http.Client
}

func NewSelectorClient(endpoint, secret string) (*SelectorClient, error) {
	if secret == "" {
		return nil, errors.New("core control API secret must not be empty")
	}
	base, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse core control API endpoint: %w", err)
	}
	if base.Scheme != "http" {
		return nil, errors.New("core control API endpoint must use http on loopback")
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

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &SelectorClient{
		base:   base,
		secret: secret,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errSelectorRedirect
			},
		},
	}, nil
}

func (c *SelectorClient) Current(ctx context.Context, selectorTag string) (SelectorSnapshot, error) {
	if strings.TrimSpace(selectorTag) == "" {
		return SelectorSnapshot{}, errors.New("selector tag must not be empty")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.proxyURL(selectorTag), nil)
	if err != nil {
		return SelectorSnapshot{}, err
	}
	c.authorize(request)
	response, err := c.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return SelectorSnapshot{}, ctx.Err()
		}
		return SelectorSnapshot{}, fmt.Errorf("read selector %q: %w", selectorTag, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return SelectorSnapshot{}, fmt.Errorf("selector %q returned HTTP %d", selectorTag, response.StatusCode)
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/json" && contentType != "text/plain" {
		return SelectorSnapshot{}, fmt.Errorf("selector %q returned unexpected content type %q", selectorTag, response.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSelectorResponseBytes+1))
	if err != nil {
		return SelectorSnapshot{}, fmt.Errorf("read selector %q response: %w", selectorTag, err)
	}
	if len(body) > maxSelectorResponseBytes {
		return SelectorSnapshot{}, fmt.Errorf("selector %q response exceeds size limit", selectorTag)
	}
	var payload struct {
		Name string   `json:"name"`
		Now  string   `json:"now"`
		All  []string `json:"all"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return SelectorSnapshot{}, fmt.Errorf("decode selector %q response: %w", selectorTag, err)
	}
	if payload.Name != "" && payload.Name != selectorTag {
		return SelectorSnapshot{}, fmt.Errorf("selector response name %q does not match %q", payload.Name, selectorTag)
	}
	if payload.Now == "" {
		return SelectorSnapshot{}, fmt.Errorf("selector %q response has empty current outbound", selectorTag)
	}
	return SelectorSnapshot{Now: payload.Now, All: append([]string(nil), payload.All...)}, nil
}

func (c *SelectorClient) Select(ctx context.Context, selectorTag, outboundTag string) error {
	if strings.TrimSpace(selectorTag) == "" || strings.TrimSpace(outboundTag) == "" {
		return errors.New("selector and outbound tags must not be empty")
	}
	body, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: outboundTag})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, c.proxyURL(selectorTag), bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.authorize(request)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("update selector %q: %w", selectorTag, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("update selector %q returned HTTP %d", selectorTag, response.StatusCode)
	}

	snapshot, err := c.Current(ctx, selectorTag)
	if err != nil {
		return fmt.Errorf("verify selector %q update: %w", selectorTag, err)
	}
	found := false
	for _, candidate := range snapshot.All {
		if candidate == outboundTag {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("selector %q does not advertise outbound %q", selectorTag, outboundTag)
	}
	if snapshot.Now != outboundTag {
		return fmt.Errorf("selector %q readback is %q, want %q", selectorTag, snapshot.Now, outboundTag)
	}
	return nil
}

func (c *SelectorClient) proxyURL(selectorTag string) string {
	endpoint := *c.base
	endpoint.Path = "/proxies/" + url.PathEscape(selectorTag)
	endpoint.RawPath = ""
	endpoint.RawQuery = ""
	endpoint.Fragment = ""
	return endpoint.String()
}

func (c *SelectorClient) authorize(request *http.Request) {
	request.Header.Set("Authorization", "Bearer "+c.secret)
	request.Header.Set("Accept", "application/json")
}
