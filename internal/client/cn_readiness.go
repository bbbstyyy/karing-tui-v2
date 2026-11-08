package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

// A pinned 28-group inventory is far smaller than this limit. Read it
// independently from generic client.get, which does not bound response size.
const maxCNReadinessResponseBytes = 128 << 10

// CNReadiness is a single bounded, read-only request. It does not prove that
// local rule resources are installed or that a CN-enabled Core can run.
func (c *Client) CNReadiness(ctx context.Context) (apiv1.CNResourceReadinessResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix/v1/cn/resources/readiness", nil)
	if err != nil {
		return apiv1.CNResourceReadinessResponse{}, err
	}
	res, err := c.queryClient.Do(req)
	if err != nil {
		return apiv1.CNResourceReadinessResponse{}, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return apiv1.CNResourceReadinessResponse{}, responseError(res)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxCNReadinessResponseBytes+1))
	if err != nil {
		return apiv1.CNResourceReadinessResponse{}, errors.New("read CN readiness response")
	}
	if len(body) > maxCNReadinessResponseBytes {
		return apiv1.CNResourceReadinessResponse{}, errors.New("CN readiness response exceeds byte limit")
	}
	var report apiv1.CNResourceReadinessResponse
	if err := json.Unmarshal(body, &report); err != nil {
		// Never print raw server response: it may be malicious or untrusted.
		return apiv1.CNResourceReadinessResponse{}, errors.New("invalid CN readiness response")
	}
	return report, nil
}
