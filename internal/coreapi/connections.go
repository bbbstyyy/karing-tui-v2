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
	"time"
)

const maxConnectionsResponseBytes = 8 << 20

var errConnectionsRedirect = errors.New("core connections API redirect refused")

type ConnectionMetadata struct {
	Network         string `json:"network"`
	Type            string `json:"type"`
	SourceIP        string `json:"sourceIP"`
	DestinationIP   string `json:"destinationIP"`
	SourcePort      string `json:"sourcePort"`
	DestinationPort string `json:"destinationPort"`
	Host            string `json:"host"`
	DNSMode         string `json:"dnsMode"`
	ProcessPath     string `json:"processPath"`
	PackageName     string `json:"packageName"`
	User            string `json:"user"`
	Protocol        string `json:"protocol"`
}

type ConnectionInfo struct {
	ID          string             `json:"id"`
	Metadata    ConnectionMetadata `json:"metadata"`
	Upload      int64              `json:"upload"`
	Download    int64              `json:"download"`
	Start       time.Time          `json:"start"`
	Chains      []string           `json:"chains"`
	Rule        string             `json:"rule"`
	RulePayload string             `json:"rulePayload"`
}

type ConnectionsSnapshot struct {
	DownloadTotal int64            `json:"downloadTotal"`
	UploadTotal   int64            `json:"uploadTotal"`
	Connections   []ConnectionInfo `json:"connections"`
}

type ConnectionsClient struct {
	connectionsURL *url.URL
	secret         string
	client         *http.Client
}

func NewConnectionsClient(endpoint, secret string) (*ConnectionsClient, error) {
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

	connectionsURL := *base
	connectionsURL.Path = "/connections"
	connectionsURL.RawPath = ""
	connectionsURL.RawQuery = ""
	connectionsURL.Fragment = ""

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &ConnectionsClient{
		connectionsURL: &connectionsURL,
		secret:         secret,
		client: &http.Client{
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errConnectionsRedirect
			},
		},
	}, nil
}

func (c *ConnectionsClient) Snapshot(ctx context.Context) (ConnectionsSnapshot, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, c.connectionsURL.String(), nil)
	if err != nil {
		return ConnectionsSnapshot{}, err
	}
	request.Header.Set("Authorization", "Bearer "+c.secret)
	request.Header.Set("Accept", "application/json")

	response, err := c.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return ConnectionsSnapshot{}, ctx.Err()
		}
		return ConnectionsSnapshot{}, fmt.Errorf("read core connections: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return ConnectionsSnapshot{}, fmt.Errorf("core connections endpoint returned HTTP %d", response.StatusCode)
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(response.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/json" && contentType != "text/plain" {
		return ConnectionsSnapshot{}, fmt.Errorf(
			"core connections endpoint returned unexpected content type %q",
			response.Header.Get("Content-Type"),
		)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxConnectionsResponseBytes+1))
	if err != nil {
		return ConnectionsSnapshot{}, fmt.Errorf("read core connections response: %w", err)
	}
	if len(body) > maxConnectionsResponseBytes {
		return ConnectionsSnapshot{}, errors.New("core connections response exceeds size limit")
	}
	var snapshot ConnectionsSnapshot
	if err := json.Unmarshal(body, &snapshot); err != nil {
		return ConnectionsSnapshot{}, fmt.Errorf("decode core connections response: %w", err)
	}
	if snapshot.Connections == nil {
		snapshot.Connections = []ConnectionInfo{}
	}
	for i := range snapshot.Connections {
		connection := &snapshot.Connections[i]
		if connection.ID == "" {
			return ConnectionsSnapshot{}, fmt.Errorf("core connection %d has empty id", i)
		}
		if connection.Metadata.Network == "" {
			return ConnectionsSnapshot{}, fmt.Errorf("core connection %q has empty network", connection.ID)
		}
		connection.Chains = append([]string(nil), connection.Chains...)
	}
	return snapshot, nil
}
