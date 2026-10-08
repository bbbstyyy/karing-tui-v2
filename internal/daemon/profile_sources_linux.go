//go:build linux

package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	singboximport "github.com/bbbstyyy/karing-tui-v2/internal/importer/singbox"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/profilefetch"
	"github.com/bbbstyyy/karing-tui-v2/internal/profileupdate"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

const (
	maxProfileAPIRequestBytes = 16 << 10
	manualProfileRefreshTimeout = 60 * time.Second
)

func registerProfileSourceRoutes(
	mux *http.ServeMux,
	store *storage.Store,
	runtime *serverRuntime,
	gate *profileOperationGate,
) bool {
	if mux == nil || store == nil || gate == nil {
		return false
	}
	fetcher, fetcherErr := profilefetch.NewSourceFetcher(profileFetchOptions(runtime))

	mux.HandleFunc("GET /v1/profiles", func(w http.ResponseWriter, r *http.Request) {
		states, err := store.ListProfileSources(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiv1.ErrorResponse{
				Error: "read profile source list",
			})
			return
		}
		response := apiv1.ProfileSourceListResponse{
			Profiles: make([]apiv1.ProfileSourceResponse, 0, len(states)),
		}
		for _, state := range states {
			response.Profiles = append(response.Profiles, profileSourceResponse(state))
		}
		writeJSON(w, http.StatusOK, response)
	})

	mux.HandleFunc("GET /v1/profiles/{profile_id}", func(w http.ResponseWriter, r *http.Request) {
		state, err := store.ProfileSource(r.Context(), r.PathValue("profile_id"))
		if err != nil {
			writeProfileSourceAPIError(w, err, nil)
			return
		}
		writeJSON(w, http.StatusOK, profileSourceResponse(state))
	})

	mux.HandleFunc("PUT /v1/profiles/{profile_id}", func(w http.ResponseWriter, r *http.Request) {
		var request apiv1.ProfileSourcePutRequest
		if err := decodeProfileAPIRequest(w, r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: err.Error()})
			return
		}
		spec, err := profileSourceFromAPI(r.PathValue("profile_id"), request.Source)
		if err != nil {
			writeProfileSourceAPIError(w, err, nil)
			return
		}
		if !gate.TryAcquire(spec.ProfileID) {
			writeProfileAPIBusy(w)
			return
		}
		defer gate.Release(spec.ProfileID)

		state, err := store.CommitProfileSource(
			r.Context(), request.ExpectedRevision, spec,
		)
		if err != nil {
			writeProfileSourceAPIError(w, err, nil)
			return
		}
		writeJSON(w, http.StatusOK, profileSourceResponse(state))
	})

	mux.HandleFunc("POST /v1/profiles/{profile_id}/refresh", func(w http.ResponseWriter, r *http.Request) {
		if fetcherErr != nil || fetcher == nil {
			writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{
				Error: "profile source fetcher is not configured",
			})
			return
		}
		var request apiv1.ProfileRefreshRequest
		if err := decodeProfileAPIRequest(w, r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: err.Error()})
			return
		}
		if request.ExpectedSourceRevision == 0 {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{
				Error: "expected source revision must be positive",
			})
			return
		}
		profileID := r.PathValue("profile_id")
		if err := profile.ValidateProfileID(profileID); err != nil {
			writeProfileSourceAPIError(w, err, nil)
			return
		}
		if !gate.TryAcquire(profileID) {
			writeProfileAPIBusy(w)
			return
		}
		defer gate.Release(profileID)
		updateID, err := newManualProfileUpdateID()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiv1.ErrorResponse{
				Error: "generate profile refresh identifier",
			})
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), manualProfileRefreshTimeout)
		defer cancel()
		result, err := profileupdate.RefreshProfileSource(
			ctx,
			store,
			fetcher,
			profileID,
			request.ExpectedSourceRevision,
			updateID,
			profileupdate.Options{AllowEmpty: request.AllowEmpty},
		)
		if err != nil {
			writeProfileSourceAPIError(w, err, result.Analysis.Diagnostics)
			return
		}

		response := apiv1.ProfileRefreshResponse{
			ProfileID:        profileID,
			SourceRevision:   result.SourceAfter.Revision,
			AcceptedRevision: result.SourceAfter.LastSourceRevision,
			NotModified:      result.NotModified,
			CurrentSnapshotID: result.SourceAfter.CurrentSnapshotID,
			NodeCount:        len(result.Nodes),
			Diagnostics:      profileDiagnosticsResponse(result.Analysis.Diagnostics),
		}
		if result.NotModified && result.SourceAfter.CurrentSnapshotID != nil {
			snapshot, err := store.ProfileSnapshotByID(
				r.Context(), profileID, *result.SourceAfter.CurrentSnapshotID,
			)
			if err != nil {
				writeProfileSourceAPIError(w, err, nil)
				return
			}
			response.NodeCount = len(snapshot.Nodes)
		}
		writeJSON(w, http.StatusOK, response)
	})
	return fetcherErr == nil
}

func decodeProfileAPIRequest(w http.ResponseWriter, r *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxProfileAPIRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode profile request: %w", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("profile request must contain exactly one JSON object")
	}
	return nil
}

func profileSourceFromAPI(
	profileID string,
	source apiv1.ProfileSourceSpec,
) (profile.SourceSpec, error) {
	const maxSeconds = int64(profile.MaxUpdateInterval / time.Second)
	if source.UpdateIntervalSeconds < 0 || source.UpdateIntervalSeconds > maxSeconds {
		return profile.SourceSpec{}, fmt.Errorf(
			"%w: update interval seconds out of range",
			profile.ErrInvalidProfileSource,
		)
	}
	spec := profile.SourceSpec{
		ProfileID:      profileID,
		Format:         profile.SourceFormat(source.Format),
		LocationKind:   profile.SourceLocationKind(source.LocationKind),
		Location:       source.Location,
		UserAgent:      source.UserAgent,
		UpdateInterval: time.Duration(source.UpdateIntervalSeconds) * time.Second,
		Enabled:        source.Enabled,
		Fetch: profile.FetchPolicy{
			Mode:      profile.FetchMode(source.Fetch.Mode),
			ProfileID: source.Fetch.ProfileID,
			NodeID:    source.Fetch.NodeID,
		},
		Filter: profile.NodeFilterSpec{
			Method:         profile.NodeFilterMethod(source.Filter.Method),
			KeywordOrRegex: source.Filter.KeywordOrRegex,
			MatchAttribute: source.Filter.MatchAttribute,
		},
	}
	if err := spec.Validate(); err != nil {
		return profile.SourceSpec{}, err
	}
	return spec, nil
}

func profileSourceResponse(state storage.ProfileSourceState) apiv1.ProfileSourceResponse {
	spec := state.Spec
	response := apiv1.ProfileSourceResponse{
		ProfileID:         spec.ProfileID,
		Revision:          state.Revision,
		CreatedAt:         state.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:         state.UpdatedAt.UTC().Format(time.RFC3339Nano),
		LastError:         state.LastError,
		LastSourceRevision: state.LastSourceRevision,
		ETag:              state.ETag,
		LastModified:      state.LastModified,
		ConsecutiveFailures: state.ConsecutiveFailures,
		ActiveUpdateID:    state.ActiveUpdateID,
		CurrentSnapshotID: state.CurrentSnapshotID,
		Source: apiv1.ProfileSourceSpec{
			Format:                string(spec.Format),
			LocationKind:          string(spec.LocationKind),
			Location:              spec.Location,
			UserAgent:             spec.UserAgent,
			UpdateIntervalSeconds: int64(spec.UpdateInterval / time.Second),
			Enabled:               spec.Enabled,
			Fetch: apiv1.ProfileSourceFetchPolicy{
				Mode:      string(spec.Fetch.Mode),
				ProfileID: spec.Fetch.ProfileID,
				NodeID:    spec.Fetch.NodeID,
			},
			Filter: apiv1.ProfileSourceFilter{
				Method:         string(spec.Filter.Method),
				KeywordOrRegex: spec.Filter.KeywordOrRegex,
				MatchAttribute: spec.Filter.MatchAttribute,
			},
		},
	}
	if state.LastAttemptAt != nil {
		response.LastAttemptAt = state.LastAttemptAt.UTC().Format(time.RFC3339Nano)
	}
	if state.LastSuccessAt != nil {
		response.LastSuccessAt = state.LastSuccessAt.UTC().Format(time.RFC3339Nano)
	}
	if state.RetryAfterAt != nil {
		response.RetryAfterAt = state.RetryAfterAt.UTC().Format(time.RFC3339Nano)
	}
	if state.ActiveUpdateStarted != nil {
		response.ActiveUpdateStartedAt = state.ActiveUpdateStarted.UTC().Format(time.RFC3339Nano)
	}
	return response
}

func profileDiagnosticsResponse(
	diagnostics []singboximport.Diagnostic,
) []apiv1.ProfileDiagnosticResponse {
	if len(diagnostics) == 0 {
		return nil
	}
	result := make([]apiv1.ProfileDiagnosticResponse, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		result = append(result, apiv1.ProfileDiagnosticResponse{
			Level:   string(diagnostic.Level),
			Path:    diagnostic.Path,
			Code:    diagnostic.Code,
			Message: diagnostic.Message,
		})
	}
	return result
}

func newManualProfileUpdateID() (string, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "manual-" + hex.EncodeToString(random[:]), nil
}

func writeProfileAPIBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "1")
	writeJSON(w, http.StatusTooManyRequests, apiv1.ErrorResponse{
		Error: "profile operation budget is busy",
	})
}

func writeProfileSourceAPIError(
	w http.ResponseWriter,
	err error,
	diagnostics []singboximport.Diagnostic,
) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, storage.ErrProfileSourceNotFound):
		status = http.StatusNotFound
	case errors.Is(err, storage.ErrProfileSourceRevisionConflict),
		errors.Is(err, storage.ErrProfileUpdateInProgress),
		errors.Is(err, storage.ErrProfileSourceDisabled),
		errors.Is(err, profileupdate.ErrNotModifiedWithoutSnapshot):
		status = http.StatusConflict
	case errors.Is(err, profile.ErrInvalidProfileSource),
		errors.Is(err, profile.ErrInvalidNodeFilter),
		errors.Is(err, profileupdate.ErrImportBlocked),
		errors.Is(err, profilefetch.ErrUnsupportedSourceLocation),
		errors.Is(err, profilefetch.ErrUnsupportedFetchMode),
		errors.Is(err, profile.ErrInvalidProfileID):
		status = http.StatusUnprocessableEntity
	case errors.Is(err, profilefetch.ErrSelectedProxyUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, profilefetch.ErrFetchTimeout),
		errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
	case errors.Is(err, profilefetch.ErrFetchNetwork):
		status = http.StatusBadGateway
	default:
		var upstream *profilefetch.HTTPStatusError
		if errors.As(err, &upstream) {
			status = http.StatusBadGateway
			if upstream.RetryAfter != nil {
				seconds := int(time.Until(*upstream.RetryAfter).Seconds())
				if seconds < 1 {
					seconds = 1
				}
				w.Header().Set("Retry-After", fmt.Sprint(seconds))
			}
		}
	}
	writeJSON(w, status, apiv1.ProfileRefreshErrorResponse{
		Error:       err.Error(),
		Diagnostics: profileDiagnosticsResponse(diagnostics),
	})
}
