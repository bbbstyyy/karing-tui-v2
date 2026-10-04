package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

type Client struct {
	httpClient *http.Client
}

func New(socketPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		httpClient: &http.Client{Transport: transport, Timeout: 3 * time.Second},
	}
}

func (c *Client) Status(ctx context.Context) (apiv1.StatusResponse, error) {
	var response apiv1.StatusResponse
	if err := c.get(ctx, "/v1/status", &response); err != nil {
		return apiv1.StatusResponse{}, err
	}
	return response, nil
}

func (c *Client) Capabilities(ctx context.Context) (apiv1.CapabilitiesResponse, error) {
	var response apiv1.CapabilitiesResponse
	if err := c.get(ctx, "/v1/capabilities", &response); err != nil {
		return apiv1.CapabilitiesResponse{}, err
	}
	return response, nil
}

func (c *Client) get(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon returned %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decode daemon response: %w", err)
	}
	return nil
}
