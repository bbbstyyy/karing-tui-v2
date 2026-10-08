//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/profilefetch"
	"github.com/bbbstyyy/karing-tui-v2/internal/profileupdate"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

const maxConcurrentProfileMetadataRefreshes = 4

type profileOperationGate struct {
	slots chan struct{}

	mu     sync.Mutex
	active map[string]struct{}
}

func newProfileOperationGate(limit int) *profileOperationGate {
	return &profileOperationGate{
		slots:  make(chan struct{}, limit),
		active: make(map[string]struct{}),
	}
}

func (g *profileOperationGate) TryAcquire(profileID string) bool {
	if g == nil {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, exists := g.active[profileID]; exists {
		return false
	}
	select {
	case g.slots <- struct{}{}:
		g.active[profileID] = struct{}{}
		return true
	default:
		return false
	}
}

func (g *profileOperationGate) Release(profileID string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	if _, exists := g.active[profileID]; exists {
		delete(g.active, profileID)
		<-g.slots
	}
	g.mu.Unlock()
}

func registerProfileMetadataRoutes(
	mux *http.ServeMux,
	store *storage.Store,
	runtime *serverRuntime,
) bool {
	if mux == nil || store == nil {
		return false
	}
	fetcher, fetcherErr := profilefetch.NewSourceFetcher(profileFetchOptions(runtime))
	gate := newProfileOperationGate(maxConcurrentProfileMetadataRefreshes)

	mux.HandleFunc("GET /v1/profiles/{profile_id}/metadata", func(w http.ResponseWriter, r *http.Request) {
		state, err := store.ProfileSource(r.Context(), r.PathValue("profile_id"))
		if err != nil {
			writeProfileMetadataError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, profileMetadataResponse(
			state,
			state.SubscriptionMetadataObservedAt != nil,
			false,
		))
	})

	mux.HandleFunc("POST /v1/profiles/{profile_id}/metadata/refresh", func(w http.ResponseWriter, r *http.Request) {
		if fetcherErr != nil || fetcher == nil {
			writeJSON(
				w,
				http.StatusServiceUnavailable,
				apiv1.ErrorResponse{Error: "profile metadata fetcher is not configured"},
			)
			return
		}

		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
		decoder.DisallowUnknownFields()
		var request apiv1.ProfileMetadataRefreshRequest
		if err := decoder.Decode(&request); err != nil {
			writeJSON(
				w,
				http.StatusBadRequest,
				apiv1.ErrorResponse{Error: "decode profile metadata refresh request: " + err.Error()},
			)
			return
		}
		if request.ExpectedSourceRevision == 0 {
			writeJSON(
				w,
				http.StatusBadRequest,
				apiv1.ErrorResponse{Error: "expected source revision must be positive"},
			)
			return
		}

		profileID := r.PathValue("profile_id")
		if !gate.TryAcquire(profileID) {
			w.Header().Set("Retry-After", "1")
			writeJSON(
				w,
				http.StatusTooManyRequests,
				apiv1.ErrorResponse{Error: "profile metadata refresh budget is busy"},
			)
			return
		}
		defer gate.Release(profileID)

		ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
		defer cancel()
		result, err := profileupdate.RefreshProfileSourceMetadata(
			ctx,
			store,
			fetcher,
			profileID,
			request.ExpectedSourceRevision,
		)
		if err != nil {
			writeProfileMetadataError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, profileMetadataResponse(
			result.SourceAfter,
			result.Fetch.UsageMetadataObserved,
			result.Applied,
		))
	})

	return fetcherErr == nil
}

func profileMetadataResponse(
	state storage.ProfileSourceState,
	headerObserved bool,
	applied bool,
) apiv1.ProfileMetadataResponse {
	response := apiv1.ProfileMetadataResponse{
		ProfileID:          state.Spec.ProfileID,
		SourceRevision:     state.Revision,
		MetadataError:      state.LastMetadataError,
		HeaderObserved:     headerObserved,
		ObservationApplied: applied,
	}
	if state.SubscriptionUsage != nil {
		usage := state.SubscriptionUsage
		response.Usage = &apiv1.ProfileSubscriptionUsageResponse{
			UploadBytes:   copyAPIInt64(usage.UploadBytes),
			DownloadBytes: copyAPIInt64(usage.DownloadBytes),
			TotalBytes:    copyAPIInt64(usage.TotalBytes),
		}
		if usage.ExpiresAt != nil {
			response.Usage.ExpiresAt = usage.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
	}
	if state.SubscriptionUsageUpdatedAt != nil {
		response.UsageUpdatedAt = state.SubscriptionUsageUpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	if state.SubscriptionMetadataObservedAt != nil {
		response.MetadataObservedAt = state.SubscriptionMetadataObservedAt.UTC().Format(time.RFC3339Nano)
	}
	return response
}

func copyAPIInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}

func writeProfileMetadataError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, storage.ErrProfileSourceNotFound):
		status = http.StatusNotFound
	case errors.Is(err, storage.ErrProfileSourceRevisionConflict),
		errors.Is(err, storage.ErrProfileUpdateInProgress),
		errors.Is(err, storage.ErrProfileSourceDisabled):
		status = http.StatusConflict
	case errors.Is(err, profilefetch.ErrUnsupportedSourceLocation),
		errors.Is(err, profilefetch.ErrUnsupportedFetchMode):
		status = http.StatusUnprocessableEntity
	case errors.Is(err, profilefetch.ErrSelectedProxyUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, profilefetch.ErrFetchTimeout),
		errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	case errors.Is(err, profilefetch.ErrFetchNetwork):
		status = http.StatusBadGateway
	default:
		var statusErr *profilefetch.HTTPStatusError
		if errors.As(err, &statusErr) {
			status = http.StatusBadGateway
			if statusErr.RetryAfter != nil {
				seconds := int(time.Until(*statusErr.RetryAfter).Seconds())
				if seconds < 1 {
					seconds = 1
				}
				w.Header().Set("Retry-After", fmt.Sprint(seconds))
			}
		}
	}
	writeJSON(w, status, apiv1.ErrorResponse{Error: err.Error()})
}
