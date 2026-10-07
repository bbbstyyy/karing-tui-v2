package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

type Client struct {
	queryClient   *http.Client
	controlClient *http.Client
}

func New(socketPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		queryClient:   &http.Client{Transport: transport, Timeout: 3 * time.Second},
		controlClient: &http.Client{Transport: transport, Timeout: 20 * time.Second},
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

func (c *Client) CoreStart(ctx context.Context) error {
	return c.post(ctx, "/v1/core/start")
}

func (c *Client) CoreStop(ctx context.Context) error {
	return c.post(ctx, "/v1/core/stop")
}

func (c *Client) StorageRetention(ctx context.Context) (apiv1.StorageRetentionResponse, error) {
	var response apiv1.StorageRetentionResponse
	if err := c.get(ctx, "/v1/storage/retention", &response); err != nil {
		return apiv1.StorageRetentionResponse{}, err
	}
	return response, nil
}

func (c *Client) StoragePrune(ctx context.Context) (apiv1.StorageRetentionResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/storage/prune", nil)
	if err != nil {
		return apiv1.StorageRetentionResponse{}, err
	}
	resp, err := c.controlClient.Do(req)
	if err != nil {
		return apiv1.StorageRetentionResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiv1.StorageRetentionResponse{}, responseError(resp)
	}
	var response apiv1.StorageRetentionResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return apiv1.StorageRetentionResponse{}, fmt.Errorf("decode daemon response: %w", err)
	}
	return response, nil
}

func (c *Client) get(ctx context.Context, path string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.queryClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return responseError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decode daemon response: %w", err)
	}
	return nil
}

func (c *Client) post(ctx context.Context, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.controlClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return responseError(resp)
	}
	return nil
}

func responseError(resp *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err == nil && len(body) != 0 {
		var payload apiv1.ErrorResponse
		if json.Unmarshal(body, &payload) == nil && payload.Error != "" {
			return fmt.Errorf("daemon returned %s: %s", resp.Status, payload.Error)
		}
	}
	return fmt.Errorf("daemon returned %s", resp.Status)
}
