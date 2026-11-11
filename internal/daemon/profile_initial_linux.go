//go:build linux

package daemon

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/profileupdate"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

const initialDeclarationRoutingMode = "proxy-only-no-cn"

// A separate first-run endpoint avoids weakening the existing snapshot ->
// declaration stage contract, whose base revision must be positive.
// It is a proxy-only technical preview, NOT CN routing initialization.
func registerInitialProfileDeclarationRoutes(
	mux *http.ServeMux, store *storage.Store, gate *profileOperationGate,
) {
	if mux == nil || store == nil || gate == nil {
		return
	}
	mux.HandleFunc("POST /v1/profiles/{profile_id}/declaration/initial/preview", func(w http.ResponseWriter, r *http.Request) {
		var request apiv1.InitialProfileDeclarationPreviewRequest
		if err := decodeProfileAPIRequest(w, r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "invalid first-run preview request"})
			return
		}
		id := r.PathValue("profile_id")
		if profile.ValidateProfileID(id) != nil || request.SnapshotID <= 0 ||
			request.SelectedNodeID == "" || request.ResolverAddress == "" {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "accepted snapshot, selected node ID and explicit DNS IP:port are required"})
			return
		}
		if !gate.TryAcquire(id) {
			writeProfileAPIBusy(w)
			return
		}
		defer gate.Release(id)
		ctx, cancel := context.WithTimeout(r.Context(), profilePreviewTimeout)
		defer cancel()
		preview, err := profileupdate.PreviewInitialProfileDeclaration(
			ctx, store, id, request.SnapshotID, request.SelectedNodeID, request.ResolverAddress,
		)
		if err != nil {
			writeInitialProfileDeclarationError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, apiv1.InitialProfileDeclarationPreviewResponse{
			ProfileID: id, SnapshotID: preview.SnapshotID,
			SourceRevision: preview.SourceRevision, BaseDeclarationRevision: 0,
			EffectiveNodeCount: preview.EffectiveNodeCount,
			SelectedNodeID:     preview.SelectedNodeID, ResolverAddress: preview.ResolverAddress,
			RuntimeOverlaySHA256: preview.RuntimeOverlaySHA256, CandidateSHA256: preview.CandidateSHA256,
			RoutingMode: initialDeclarationRoutingMode, CNRulesReady: false,
			CoreValidated: false, Applied: false,
		})
	})
	mux.HandleFunc("POST /v1/profiles/{profile_id}/declaration/initial/stage", func(w http.ResponseWriter, r *http.Request) {
		var request apiv1.InitialProfileDeclarationStageRequest
		if err := decodeProfileAPIRequest(w, r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "invalid first-run stage request"})
			return
		}
		id := r.PathValue("profile_id")
		if profile.ValidateProfileID(id) != nil || request.SnapshotID <= 0 ||
			request.ExpectedSourceRevision == 0 || request.SelectedNodeID == "" ||
			request.ResolverAddress == "" || !validStageDigest(request.CandidateSHA256) ||
			!validStageDigest(request.RuntimeOverlaySHA256) ||
			!request.AcknowledgeProxyOnlyNoCN {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "explicit proxy-only acknowledgement and exact first-run preview receipt required"})
			return
		}
		if !gate.TryAcquire(id) {
			writeProfileAPIBusy(w)
			return
		}
		defer gate.Release(id)
		// A disconnected UI cannot undo a potentially committed declaration.
		// Never retry silently after a network timeout.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 30*time.Second)
		defer cancel()
		staged, err := profileupdate.StageInitialProfileDeclaration(
			ctx, store, id, request.SnapshotID, request.ExpectedSourceRevision,
			request.SelectedNodeID, request.ResolverAddress,
			request.CandidateSHA256, request.RuntimeOverlaySHA256,
		)
		if err != nil {
			writeInitialProfileDeclarationError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, apiv1.InitialProfileDeclarationStageResponse{
			ProfileID: id, SnapshotID: request.SnapshotID,
			SourceRevision:      request.ExpectedSourceRevision,
			DeclarationRevision: staged.Revision,
			DeclarationSHA256:   staged.SHA256,
			RoutingMode:         initialDeclarationRoutingMode,
			CNRulesReady:        false, CoreValidated: false, Applied: false,
		})
	})
}

func writeInitialProfileDeclarationError(w http.ResponseWriter, err error) {
	status := http.StatusUnprocessableEntity
	message := "first-run profile declaration rejected; review selected node and explicit DNS resolver"
	switch {
	case errors.Is(err, storage.ErrProfileSourceNotFound):
		status, message = http.StatusNotFound, "profile source not found"
	case errors.Is(err, profileupdate.ErrInitialDeclarationUnavailable),
		errors.Is(err, profileupdate.ErrInitialDeclarationMismatch),
		errors.Is(err, storage.ErrProfileDeclarationGuardConflict),
		errors.Is(err, storage.ErrDeclarationRevisionConflict):
		status, message = http.StatusConflict, "first-run declaration, snapshot or overlay preconditions changed"
	case errors.Is(err, context.DeadlineExceeded):
		status, message = http.StatusGatewayTimeout, "initial declaration operation timed out"
	case errors.Is(err, profileupdate.ErrInitialDeclarationInvalid),
		errors.Is(err, storage.ErrDeclarationTooLarge):
		status, message = http.StatusUnprocessableEntity, "invalid initial declaration candidate or DNS/selected node"
	}
	// Never echo incoming URI, raw snapshot data, selection credentials or
	// lower-level errors, which could carry imported proxy secrets.
	writeJSON(w, status, apiv1.ErrorResponse{Error: message})
}
