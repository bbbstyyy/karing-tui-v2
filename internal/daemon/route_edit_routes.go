package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

const routeEditBodyLimit = 4096

func registerRouteEditRoutes(mux *http.ServeMux, store *storage.Store, runtime *serverRuntime) {
	ready := func() bool {
		return runtime != nil && runtime.DeclarationCompilerReady() && runtime.gate != nil
	}
	mux.HandleFunc("GET /v1/config/route-edit/context", func(w http.ResponseWriter, req *http.Request) {
		if !ready() {
			writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{Error: "route edit compiler unavailable"})
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), 3*time.Second)
		defer cancel()
		binding, err := routeEditContext(ctx, store)
		if err != nil {
			writeRouteEditError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, binding)
	})
	mux.HandleFunc("POST /v1/config/route-edit/preview", func(w http.ResponseWriter, req *http.Request) {
		if !ready() {
			writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{Error: "route edit compiler unavailable"})
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, routeEditBodyLimit))
		decoder.DisallowUnknownFields()
		var proposal apiv1.RouteEditRequest
		if err := decoder.Decode(&proposal); err != nil || requireJSONEOF(decoder) != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "invalid or oversized route edit proposal"})
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), 25*time.Second)
		defer cancel()
		var preview apiv1.RouteEditPreviewResponse
		err := runtime.gate.Do(ctx, "route-edit-preview", func(inner context.Context) error {
			var e error
			preview, e = previewRouteEdit(inner, store, runtime.declarations, proposal)
			return e
		})
		if err != nil {
			writeRouteEditError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, preview)
	})
	mux.HandleFunc("POST /v1/config/route-edit/stage", func(w http.ResponseWriter, req *http.Request) {
		if !ready() {
			writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{Error: "route edit compiler unavailable"})
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, routeEditBodyLimit))
		decoder.DisallowUnknownFields()
		var proposal apiv1.RouteEditStageRequest
		if err := decoder.Decode(&proposal); err != nil || requireJSONEOF(decoder) != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "invalid or oversized route edit confirmation"})
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), 25*time.Second)
		defer cancel()
		var result apiv1.RouteEditStageResponse
		err := runtime.gate.Do(ctx, "route-edit-stage", func(inner context.Context) error {
			var e error
			result, e = stageRouteEdit(inner, store, runtime.declarations, proposal)
			return e
		})
		if err != nil {
			writeRouteEditError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, result)
	})
}

// Do not echo unknown-field names, runtime secret-bearing compile failures,
// matcher values or backend rule-set paths in operator-facing error bodies.
func writeRouteEditError(w http.ResponseWriter, err error) {
	status := http.StatusServiceUnavailable
	message := "route edit unavailable; refresh status"
	switch {
	case errors.Is(err, ErrRouteEditConflict):
		status, message = http.StatusConflict, "route edit state changed; preview again, do not retry stale confirmation"
	case errors.Is(err, ErrRouteEditRejected):
		status, message = http.StatusUnprocessableEntity, "route edit rejected by validation or strict compiler"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		status, message = http.StatusGatewayTimeout, "route edit outcome uncertain; GET current declaration before any further action"
	}
	writeJSON(w, status, apiv1.ErrorResponse{Error: message})
}
