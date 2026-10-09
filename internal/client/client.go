package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

type Client struct {
	queryClient   *http.Client
	controlClient *http.Client
	refreshClient *http.Client
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
		refreshClient: &http.Client{Transport: transport, Timeout: 75 * time.Second},
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

const maxObservedConnectionsResponseBytes = 8 << 20

// Bound core snapshots before allocation and JSON decode.
func (c *Client) ObservedConnections(ctx context.Context) (apiv1.ObservedConnectionsResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/connections", nil)
	if err != nil {
		return apiv1.ObservedConnectionsResponse{}, err
	}
	resp, err := c.queryClient.Do(req)
	if err != nil {
		return apiv1.ObservedConnectionsResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiv1.ObservedConnectionsResponse{}, responseError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxObservedConnectionsResponseBytes+1))
	if err != nil {
		return apiv1.ObservedConnectionsResponse{}, fmt.Errorf("read bounded connection snapshot: %w", err)
	}
	if len(body) > maxObservedConnectionsResponseBytes {
		return apiv1.ObservedConnectionsResponse{}, fmt.Errorf("connection snapshot exceeds %d bytes", maxObservedConnectionsResponseBytes)
	}
	var response apiv1.ObservedConnectionsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return apiv1.ObservedConnectionsResponse{}, fmt.Errorf("decode connection snapshot: %w", err)
	}
	return response, nil
}

func (c *Client) RouteExplain(
	ctx context.Context,
	request apiv1.RouteExplainRequest,
) (apiv1.RouteExplainResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return apiv1.RouteExplainResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/route/explain", bytes.NewReader(body))
	if err != nil {
		return apiv1.RouteExplainResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.controlClient.Do(req)
	if err != nil {
		return apiv1.RouteExplainResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiv1.RouteExplainResponse{}, responseError(resp)
	}
	var response apiv1.RouteExplainResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return apiv1.RouteExplainResponse{}, fmt.Errorf("decode daemon response: %w", err)
	}
	return response, nil
}

// InspectConfig is intentionally bounded before JSON decoding: it must never
// accidentally fetch full declarations, core configs or DNS credentials.
const maxInspectionResponseBytes = 1 << 20

func (c *Client) InspectConfig(ctx context.Context) (apiv1.ConfigInspectionResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/config/inspection", nil)
	if err != nil {
		return apiv1.ConfigInspectionResponse{}, err
	}
	resp, err := c.queryClient.Do(req)
	if err != nil {
		return apiv1.ConfigInspectionResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiv1.ConfigInspectionResponse{}, responseError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxInspectionResponseBytes+1))
	if err != nil {
		return apiv1.ConfigInspectionResponse{}, fmt.Errorf("read bounded inspection: %w", err)
	}
	if len(body) > maxInspectionResponseBytes {
		return apiv1.ConfigInspectionResponse{}, fmt.Errorf("inspection response exceeds %d bytes", maxInspectionResponseBytes)
	}
	var response apiv1.ConfigInspectionResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return apiv1.ConfigInspectionResponse{}, fmt.Errorf("decode inspection: %w", err)
	}
	return response, nil
}

func (c *Client) RoutingMode(ctx context.Context) (apiv1.RoutingModeResponse, error) {
	var response apiv1.RoutingModeResponse
	if err := c.get(ctx, "/v1/routing/mode", &response); err != nil {
		return apiv1.RoutingModeResponse{}, err
	}
	return response, nil
}

func (c *Client) SetRoutingMode(ctx context.Context, mode string) (apiv1.RoutingModeResponse, error) {
	return c.SetRoutingPolicy(ctx, apiv1.RoutingModeRequest{Mode: mode})
}

func (c *Client) SetRoutingPolicy(
	ctx context.Context,
	request apiv1.RoutingModeRequest,
) (apiv1.RoutingModeResponse, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return apiv1.RoutingModeResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://unix/v1/routing/mode", bytes.NewReader(body))
	if err != nil {
		return apiv1.RoutingModeResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.controlClient.Do(req)
	if err != nil {
		return apiv1.RoutingModeResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiv1.RoutingModeResponse{}, responseError(resp)
	}
	var response apiv1.RoutingModeResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return apiv1.RoutingModeResponse{}, fmt.Errorf("decode daemon response: %w", err)
	}
	return response, nil
}

func (c *Client) CurrentSelection(ctx context.Context) (apiv1.CurrentSelectionResponse, error) {
	var response apiv1.CurrentSelectionResponse
	if err := c.get(ctx, "/v1/selection/current", &response); err != nil {
		return apiv1.CurrentSelectionResponse{}, err
	}
	return response, nil
}

// Checked selection commits require the revision and applied-generation
// binding read from GET. A 409 must trigger a new GET, never a blind retry.
func (c *Client) SetCurrentSelectionChecked(
	ctx context.Context, request apiv1.CurrentSelectionCheckedRequest,
) (apiv1.CurrentSelectionResponse, error) {
	var response apiv1.CurrentSelectionResponse
	if err := c.sendJSON(ctx, c.controlClient, http.MethodPut, "/v1/selection/current/checked", request, &response); err != nil {
		return apiv1.CurrentSelectionResponse{}, err
	}
	return response, nil
}

func (c *Client) SetCurrentSelection(
	ctx context.Context,
	target domain.TargetRef,
) (apiv1.CurrentSelectionResponse, error) {
	body, err := json.Marshal(apiv1.CurrentSelectionRequest{Target: target})
	if err != nil {
		return apiv1.CurrentSelectionResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://unix/v1/selection/current", bytes.NewReader(body))
	if err != nil {
		return apiv1.CurrentSelectionResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.controlClient.Do(req)
	if err != nil {
		return apiv1.CurrentSelectionResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiv1.CurrentSelectionResponse{}, responseError(resp)
	}
	var response apiv1.CurrentSelectionResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return apiv1.CurrentSelectionResponse{}, fmt.Errorf("decode daemon response: %w", err)
	}
	return response, nil
}

func (c *Client) ProfileSources(
	ctx context.Context,
) (apiv1.ProfileSourceListResponse, error) {
	var response apiv1.ProfileSourceListResponse
	if err := c.get(ctx, "/v1/profiles", &response); err != nil {
		return apiv1.ProfileSourceListResponse{}, err
	}
	return response, nil
}

func (c *Client) ProfileSource(
	ctx context.Context,
	profileID string,
) (apiv1.ProfileSourceResponse, error) {
	var response apiv1.ProfileSourceResponse
	path := "/v1/profiles/" + url.PathEscape(profileID)
	if err := c.get(ctx, path, &response); err != nil {
		return apiv1.ProfileSourceResponse{}, err
	}
	return response, nil
}

func (c *Client) PutProfileSource(
	ctx context.Context,
	profileID string,
	request apiv1.ProfileSourcePutRequest,
) (apiv1.ProfileSourceResponse, error) {
	var response apiv1.ProfileSourceResponse
	path := "/v1/profiles/" + url.PathEscape(profileID)
	if err := c.sendJSON(ctx, c.controlClient, http.MethodPut, path, request, &response); err != nil {
		return apiv1.ProfileSourceResponse{}, err
	}
	return response, nil
}

func (c *Client) RefreshProfileSource(
	ctx context.Context,
	profileID string,
	request apiv1.ProfileRefreshRequest,
) (apiv1.ProfileRefreshResponse, error) {
	var response apiv1.ProfileRefreshResponse
	path := "/v1/profiles/" + url.PathEscape(profileID) + "/refresh"
	if err := c.sendJSON(ctx, c.refreshClient, http.MethodPost, path, request, &response); err != nil {
		return apiv1.ProfileRefreshResponse{}, err
	}
	return response, nil
}

func (c *Client) sendJSON(
	ctx context.Context,
	httpClient *http.Client,
	method string,
	path string,
	payload any,
	target any,
) error {
	return c.sendJSONWithStatus(ctx, httpClient, method, path, payload, target, http.StatusOK)
}

func (c *Client) sendJSONWithStatus(
	ctx context.Context,
	httpClient *http.Client,
	method string,
	path string,
	payload any,
	target any,
	expectedStatus int,
) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(
		ctx, method, "http://unix"+path, bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != expectedStatus {
		return responseError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("decode daemon response: %w", err)
	}
	return nil
}

func (c *Client) ProfileMetadata(
	ctx context.Context,
	profileID string,
) (apiv1.ProfileMetadataResponse, error) {
	var response apiv1.ProfileMetadataResponse
	path := "/v1/profiles/" + url.PathEscape(profileID) + "/metadata"
	if err := c.get(ctx, path, &response); err != nil {
		return apiv1.ProfileMetadataResponse{}, err
	}
	return response, nil
}

func (c *Client) RefreshProfileMetadata(
	ctx context.Context,
	profileID string,
	expectedSourceRevision uint64,
) (apiv1.ProfileMetadataResponse, error) {
	body, err := json.Marshal(apiv1.ProfileMetadataRefreshRequest{
		ExpectedSourceRevision: expectedSourceRevision,
	})
	if err != nil {
		return apiv1.ProfileMetadataResponse{}, err
	}
	path := "/v1/profiles/" + url.PathEscape(profileID) + "/metadata/refresh"
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"http://unix"+path,
		bytes.NewReader(body),
	)
	if err != nil {
		return apiv1.ProfileMetadataResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.controlClient.Do(req)
	if err != nil {
		return apiv1.ProfileMetadataResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return apiv1.ProfileMetadataResponse{}, responseError(resp)
	}
	var response apiv1.ProfileMetadataResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return apiv1.ProfileMetadataResponse{}, fmt.Errorf("decode daemon response: %w", err)
	}
	return response, nil
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

func (c *Client) ProfileNodes(ctx context.Context, profileID string, offset, limit int) (apiv1.ProfileNodeListResponse, error) {
	var response apiv1.ProfileNodeListResponse
	path := fmt.Sprintf("/v1/profiles/%s/nodes?offset=%d&limit=%d", url.PathEscape(profileID), offset, limit)
	if err := c.get(ctx, path, &response); err != nil {
		return apiv1.ProfileNodeListResponse{}, err
	}
	return response, nil
}
func (c *Client) PutProfileNodeOverlay(ctx context.Context, profileID, nodeID string, request apiv1.ProfileNodeOverlayPutRequest) (apiv1.ProfileNodeOverlayResponse, error) {
	var response apiv1.ProfileNodeOverlayResponse
	path := "/v1/profiles/" + url.PathEscape(profileID) + "/nodes/" + url.PathEscape(nodeID) + "/overlay"
	if err := c.sendJSON(ctx, c.controlClient, http.MethodPut, path, request, &response); err != nil {
		return apiv1.ProfileNodeOverlayResponse{}, err
	}
	return response, nil
}

func (c *Client) PreviewProfileDeclaration(
	ctx context.Context,
	profileID string,
	request apiv1.ProfileDeclarationPreviewRequest,
) (apiv1.ProfileDeclarationPreviewResponse, error) {
	var response apiv1.ProfileDeclarationPreviewResponse
	path := "/v1/profiles/" + url.PathEscape(profileID) + "/declaration/preview"
	if err := c.sendJSON(ctx, c.refreshClient, http.MethodPost, path, request, &response); err != nil {
		return apiv1.ProfileDeclarationPreviewResponse{}, err
	}
	return response, nil
}

func (c *Client) StageProfileDeclaration(
	ctx context.Context,
	profileID string,
	request apiv1.ProfileDeclarationStageRequest,
) (apiv1.ProfileDeclarationStageResponse, error) {
	var response apiv1.ProfileDeclarationStageResponse
	path := "/v1/profiles/" + url.PathEscape(profileID) + "/declaration/stage"
	if err := c.sendJSONWithStatus(
		ctx, c.refreshClient, http.MethodPost, path, request, &response, http.StatusCreated,
	); err != nil {
		return apiv1.ProfileDeclarationStageResponse{}, err
	}
	return response, nil
}
