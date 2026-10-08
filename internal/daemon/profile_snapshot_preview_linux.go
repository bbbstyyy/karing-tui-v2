//go:build linux

package daemon

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/profileupdate"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

const profilePreviewTimeout = 20 * time.Second

func registerProfileSnapshotPreviewRoutes(mux *http.ServeMux, store *storage.Store, gate *profileOperationGate) {
	if mux == nil || store == nil || gate == nil {
		return
	}
	mux.HandleFunc("POST /v1/profiles/{profile_id}/declaration/preview", func(w http.ResponseWriter, r *http.Request) {
		var request apiv1.ProfileDeclarationPreviewRequest
		if err := decodeProfileAPIRequest(w, r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "invalid declaration preview request"})
			return
		}
		if request.SnapshotID <= 0 || request.ExpectedDeclarationRevision == 0 {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "a positive current snapshot ID and declaration revision are required"})
			return
		}
		profileID := r.PathValue("profile_id")
		if err := profile.ValidateProfileID(profileID); err != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "invalid profile ID"})
			return
		}
		if !gate.TryAcquire(profileID) {
			writeProfileAPIBusy(w)
			return
		}
		defer gate.Release(profileID)
		ctx, cancel := context.WithTimeout(r.Context(), profilePreviewTimeout)
		defer cancel()
		preview, err := profileupdate.PreviewProfileSnapshotDeclaration(ctx, store, profileID,
			request.SnapshotID, request.ExpectedDeclarationRevision)
		if err != nil {
			writeProfileSnapshotPreviewError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, apiv1.ProfileDeclarationPreviewResponse{
			ProfileID:               preview.ProfileID,
			SnapshotID:              preview.SnapshotID,
			BaseDeclarationRevision: preview.BaseDeclarationRevision,
			SourceRevision:          preview.SourceRevision,
			SnapshotNodeCount:       preview.SnapshotNodeCount,
			EffectiveNodeCount:      preview.EffectiveNodeCount,
			AddedNodeCount:          len(preview.Impact.AddedNodeIDs),
			RemovedNodeCount:        len(preview.Impact.RemovedNodeIDs),
			RetainedNodeCount:       len(preview.Impact.RetainedNodeIDs),
			RuntimeOverlaySHA256:    preview.RuntimeOverlaySHA256,
			CandidateSHA256:         preview.CandidateSHA256,
			CoreValidated:           false,
			Applied:                 false,
		})
	})
}

func writeProfileSnapshotPreviewError(w http.ResponseWriter, err error) {
	status := http.StatusUnprocessableEntity
	message := "snapshot-to-declaration preview rejected by compatibility or reference validation"
	switch {
	case errors.Is(err, storage.ErrProfileSourceNotFound):
		status = http.StatusNotFound
		message = "profile source not found"
	case errors.Is(err, profileupdate.ErrNoBaseDeclaration),
		errors.Is(err, profileupdate.ErrPreviewSnapshotNotCurrent),
		errors.Is(err, profileupdate.ErrPreviewDeclarationStale),
		errors.Is(err, profileupdate.ErrPreviewDeclarationIntegrity),
		errors.Is(err, profileupdate.ErrPreviewOverlayStale),
		errors.Is(err, profileupdate.ErrPreviewSourceDisabled):
		status = http.StatusConflict
		message = "current enabled source, accepted snapshot, overlay or base declaration revision changed"
	case errors.Is(err, context.DeadlineExceeded):
		status = http.StatusGatewayTimeout
		message = "declaration preview timed out"
	case errors.Is(err, storage.ErrDeclarationTooLarge),
		errors.Is(err, declaration.ErrProfileNodeReplacementInvalid),
		errors.Is(err, profileupdate.ErrInvalidRuntimeNodeOverlay),
		errors.Is(err, storage.ErrProfileSnapshotMissing):
		status = http.StatusUnprocessableEntity
	default:
		// Database and materializer details are deliberately not echoed: the source
		// payload can contain credentials or hostile diagnostic content.
	}
	writeJSON(w, status, apiv1.ErrorResponse{Error: message})
}
