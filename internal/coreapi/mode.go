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

const maxModeResponseBytes = 64 << 10

var errModeRedirect = errors.New("core mode API redirect refused")

type ModeSnapshot struct {
	Mode     string
	ModeList []string
}

type ModeClient struct {
	configURL *url.URL
	secret    string
	client    *http.Client
}

func NewModeClient(endpoint, secret string) (*ModeClient, error) {
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

	configURL := *base
	configURL.Path = "/configs"
	configURL.RawPath = ""
	configURL.RawQuery = ""
	configURL.Fragment = ""

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &ModeClient{
		configURL: &configURL,
		secret:    secret,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errModeRedirect
			},
		},
	}, nil
}

func (c *ModeClient) Current(ctx context.Context) (ModeSnapshot, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.configURL.String(), nil)
	if err != nil {
		return ModeSnapshot{}, err
	}
	c.authorize(request)
	response, err := c.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ModeSnapshot{}, ctx.Err()
		}
		return ModeSnapshot{}, fmt.Errorf("read core mode: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ModeSnapshot{}, fmt.Errorf("core mode endpoint returned HTTP %d", response.StatusCode)
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/json" && contentType != "text/plain" {
		return ModeSnapshot{}, fmt.Errorf("core mode endpoint returned unexpected content type %q", response.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxModeResponseBytes+1))
	if err != nil {
		return ModeSnapshot{}, fmt.Errorf("read core mode response: %w", err)
	}
	if len(body) > maxModeResponseBytes {
		return ModeSnapshot{}, errors.New("core mode response exceeds size limit")
	}
	var payload struct {
		Mode     string   `json:"mode"`
		ModeList []string `json:"mode-list"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ModeSnapshot{}, fmt.Errorf("decode core mode response: %w", err)
	}
	if payload.Mode == "" {
		return ModeSnapshot{}, errors.New("core mode response has empty mode")
	}
	if payload.ModeList == nil {
		payload.ModeList = []string{}
	}
	return ModeSnapshot{Mode: payload.Mode, ModeList: append([]string(nil), payload.ModeList...)}, nil
}

func (c *ModeClient) Set(ctx context.Context, mode string) error {
	if mode != "Rule" && mode != "Global" && mode != "Direct" {
		return fmt.Errorf("unsupported core mode %q", mode)
	}
	current, err := c.Current(ctx)
	if err != nil {
		return fmt.Errorf("read core mode list before update: %w", err)
	}
	if !modeListContains(current.ModeList, mode) {
		return fmt.Errorf("core mode list does not advertise %q", mode)
	}
	body, err := json.Marshal(struct {
		Mode string `json:"mode"`
	}{Mode: mode})
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.configURL.String(), bytes.NewReader(body))
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
		return fmt.Errorf("update core mode: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("update core mode returned HTTP %d", response.StatusCode)
	}
	updated, err := c.Current(ctx)
	if err != nil {
		return fmt.Errorf("verify core mode update: %w", err)
	}
	if updated.Mode != mode {
		return fmt.Errorf("core mode readback is %q, want %q", updated.Mode, mode)
	}
	return nil
}

func (c *ModeClient) authorize(request *http.Request) {
	request.Header.Set("Authorization", "Bearer "+c.secret)
	request.Header.Set("Accept", "application/json")
}

func modeListContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
