package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var (
	ErrCheckedApplyConflict    = errors.New("checked apply state changed")
	ErrCheckedApplyRejected    = errors.New("checked apply receipt or compile invalid")
	ErrCheckedApplyUnavailable = errors.New("checked apply state unavailable")
)

// The checked operation is intentionally limited to the CURRENT head. The
// legacy versioned /declaration/apply endpoint still supports explicit old
// revisions for recovery, but does not satisfy this UI's preview binding.
func checkedApplyContext(ctx context.Context, store *storage.Store) (apiv1.RouteEditContext, error) {
	b, err := routeEditContext(ctx, store)
	switch {
	case errors.Is(err, ErrRouteEditConflict):
		return apiv1.RouteEditContext{}, ErrCheckedApplyConflict
	case err != nil:
		return apiv1.RouteEditContext{}, ErrCheckedApplyUnavailable
	}
	return b, nil
}

// Fail closed if the current declaration is already the verified applied
// declaration. A legacy generation with no trustworthy manifest cannot
// establish "unapplied"; operators must migrate/recover it separately.
func ensureUnappliedDeclaration(ctx context.Context, store *storage.Store, b apiv1.RouteEditContext) error {
	if b.AppliedGenerationID == nil {
		return nil
	}
	artifacts, err := store.GenerationArtifacts(ctx, *b.AppliedGenerationID)
	if err != nil || len(artifacts.ManifestJSON) == 0 {
		return ErrCheckedApplyUnavailable
	}
	var applied struct {
		DeclarationRevision uint64 `json:"declaration_revision"`
		DeclarationSHA256   string `json:"declaration_sha256"`
	}
	if err := json.Unmarshal(artifacts.ManifestJSON, &applied); err != nil ||
		applied.DeclarationRevision == 0 || !validRouteEditSHA(applied.DeclarationSHA256) {
		return ErrCheckedApplyUnavailable
	}
	if applied.DeclarationRevision == b.DeclarationRevision {
		if applied.DeclarationSHA256 != b.DeclarationSHA256 {
			return ErrCheckedApplyUnavailable
		}
		return ErrCheckedApplyConflict
	}
	return nil
}

func checkedApplyReceiptFor(b apiv1.RouteEditContext, nativeSHA string) apiv1.CheckedApplyReceipt {
	return apiv1.CheckedApplyReceipt{
		DeclarationRevision: b.DeclarationRevision,
		DeclarationSHA256: b.DeclarationSHA256,
		ExpectedConfigRevision: b.ConfigRevision,
		ExpectedAppliedGenerationID: cloneRouteEditGeneration(b.AppliedGenerationID),
		ExpectedSelectionRevision: b.SelectionRevision,
		NativeConfigSHA256: nativeSHA,
	}
}

func validateCheckedApplyReceipt(receipt apiv1.CheckedApplyReceipt, b apiv1.RouteEditContext) error {
	if receipt.DeclarationRevision == 0 || receipt.DeclarationRevision > uint64(1<<63-1) ||
		!validRouteEditSHA(receipt.DeclarationSHA256) ||
		!validRouteEditSHA(receipt.NativeConfigSHA256) ||
		(receipt.ExpectedAppliedGenerationID != nil && *receipt.ExpectedAppliedGenerationID <= 0) {
		return ErrCheckedApplyRejected
	}
	if receipt.DeclarationRevision != b.DeclarationRevision ||
		receipt.DeclarationSHA256 != b.DeclarationSHA256 ||
		receipt.ExpectedConfigRevision != b.ConfigRevision ||
		!sameGenerationID(receipt.ExpectedAppliedGenerationID, b.AppliedGenerationID) ||
		receipt.ExpectedSelectionRevision != b.SelectionRevision {
		return ErrCheckedApplyConflict
	}
	return nil
}

func checkedApplyArtifactMatches(b apiv1.RouteEditContext, artifact compiler.NativeConfigArtifact) bool {
	return artifact.Manifest.DeclarationRevision == b.DeclarationRevision &&
		artifact.Manifest.DeclarationSHA256 == b.DeclarationSHA256 &&
		validRouteEditSHA(artifact.SHA256) &&
		artifact.SHA256 == artifact.Manifest.ConfigSHA256 &&
		artifact.Manifest.SchemaID != ""
}

func (r *serverRuntime) CheckedApplyPreview(
	ctx context.Context, store *storage.Store,
) (apiv1.CheckedApplyPreviewResponse, error) {
	if r == nil || r.apply == nil || r.declarations == nil || r.gate == nil || store == nil {
		return apiv1.CheckedApplyPreviewResponse{}, ErrCheckedApplyUnavailable
	}
	var result apiv1.CheckedApplyPreviewResponse
	err := r.gate.Do(ctx, "checked-apply-preview", func(inner context.Context) error {
		base, err := checkedApplyContext(inner, store)
		if err != nil { return err }
		if err := ensureUnappliedDeclaration(inner, store, base); err != nil { return err }

		artifact, err := r.declarations.CompileRevision(inner, base.DeclarationRevision)
		if err != nil { return fmt.Errorf("%w: current declaration could not compile", ErrCheckedApplyRejected) }
		if !checkedApplyArtifactMatches(base, artifact) { return ErrCheckedApplyRejected }

		fresh, err := checkedApplyContext(inner, store)
		if err != nil { return err }
		if !reflect.DeepEqual(base, fresh) { return ErrCheckedApplyConflict }
		if err := ensureUnappliedDeclaration(inner, store, fresh); err != nil { return err }

		result = apiv1.CheckedApplyPreviewResponse{
			APIVersion: apiv1.Version,
			Receipt: checkedApplyReceiptFor(base, artifact.SHA256),
			NativeSchemaID: artifact.Manifest.SchemaID,
			RouteEntryCount: len(artifact.SourceMap),
			DNSServerCount: len(artifact.Manifest.DNSServerTags),
			RuleSetCount: len(artifact.Manifest.RuleSets),
			CompilerValidated: true, CoreValidated: false, Applied: false,
		}
		return nil
	})
	return result, err
}

// One gate covers validation, strict recompile, core check, activation,
// verification and durable commit. On errors the existing apply journal
// owns rollback and recovery. No implicit retry is attempted.
func (r *serverRuntime) CheckedApplyConfirm(
	ctx context.Context, store *storage.Store, receipt apiv1.CheckedApplyReceipt,
) (apiv1.CheckedApplyResponse, error) {
	if r == nil || r.apply == nil || r.declarations == nil || r.gate == nil || store == nil {
		return apiv1.CheckedApplyResponse{}, ErrCheckedApplyUnavailable
	}
	var result apiv1.CheckedApplyResponse
	err := r.gate.Do(ctx, "checked-apply-confirm", func(inner context.Context) error {
		base, err := checkedApplyContext(inner, store)
		if err != nil { return err }
		if err := validateCheckedApplyReceipt(receipt, base); err != nil { return err }
		if err := ensureUnappliedDeclaration(inner, store, base); err != nil { return err }

		artifact, err := r.declarations.CompileRevision(inner, receipt.DeclarationRevision)
		if err != nil { return fmt.Errorf("%w: current declaration could not compile", ErrCheckedApplyRejected) }
		if !checkedApplyArtifactMatches(base, artifact) { return ErrCheckedApplyRejected }
		if artifact.SHA256 != receipt.NativeConfigSHA256 { return ErrCheckedApplyConflict }

		fresh, err := checkedApplyContext(inner, store)
		if err != nil { return err }
		if err := validateCheckedApplyReceipt(receipt, fresh); err != nil { return err }
		if err := ensureUnappliedDeclaration(inner, store, fresh); err != nil { return err }

		// Do not re-enter the non-reentrant operation gate.
		attempt, err := r.applyNativeArtifact(inner, receipt.ExpectedConfigRevision, artifact)
		if err != nil { return err }

		result = apiv1.CheckedApplyResponse{
			DeclarationApplyResponse: apiv1.DeclarationApplyResponse{
				DeclarationRevision: artifact.Manifest.DeclarationRevision,
				DeclarationSHA256: artifact.Manifest.DeclarationSHA256,
				NativeSchemaID: artifact.Manifest.SchemaID,
				ConfigSHA256: artifact.Manifest.ConfigSHA256,
				AttemptID: attempt.ID,
				GenerationID: attempt.GenerationID,
				BaseConfigRevision: attempt.BaseRevision,
				TargetConfigRevision: attempt.TargetRevision,
			},
			CoreChecked: true, Verified: true, Applied: true,
		}
		return nil
	})
	return result, err
}

func registerCheckedApplyRoutes(mux *http.ServeMux, store *storage.Store, runtime *serverRuntime) {
	ready := func() bool {
		return runtime != nil && runtime.DeclarationApplyReady() && runtime.gate != nil
	}
	mux.HandleFunc("GET /v1/config/apply/preview", func(w http.ResponseWriter, req *http.Request) {
		if !ready() {
			writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{Error: "checked apply runtime unavailable"})
			return
		}
		ctx, cancel := context.WithTimeout(req.Context(), 25*time.Second)
		defer cancel()
		preview, err := runtime.CheckedApplyPreview(ctx, store)
		if err != nil { writeCheckedApplyError(w, err); return }
		writeJSON(w, http.StatusOK, preview)
	})
	mux.HandleFunc("POST /v1/config/apply/confirm", func(w http.ResponseWriter, req *http.Request) {
		if !ready() {
			writeJSON(w, http.StatusServiceUnavailable, apiv1.ErrorResponse{Error: "checked apply runtime unavailable"})
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, req.Body, 4096))
		decoder.DisallowUnknownFields()
		var receipt apiv1.CheckedApplyReceipt
		if err := decoder.Decode(&receipt); err != nil || requireJSONEOF(decoder) != nil {
			writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: "invalid or oversized apply receipt"})
			return
		}
		// The operation must complete cleanup even if the CLI disconnects.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), 80*time.Second)
		defer cancel()
		result, err := runtime.CheckedApplyConfirm(ctx, store, receipt)
		if err != nil { writeCheckedApplyError(w, err); return }
		writeJSON(w, http.StatusOK, result)
	})
}

func writeCheckedApplyError(w http.ResponseWriter, err error) {
	status, message := http.StatusBadGateway,
		"apply outcome uncertain or failed; inspect daemon status/recovery and do not retry automatically"
	switch {
	case errors.Is(err, ErrCheckedApplyConflict), errors.Is(err, storage.ErrRevisionConflict),
		errors.Is(err, storage.ErrRecoveryRequired), errors.Is(err, storage.ErrApplyInProgress):
		status, message = http.StatusConflict, "apply state changed or already applied; preview again"
	case errors.Is(err, ErrCheckedApplyRejected):
		status, message = http.StatusUnprocessableEntity, "apply receipt or strict compiler rejected candidate"
	case errors.Is(err, ErrCheckedApplyUnavailable):
		status, message = http.StatusServiceUnavailable, "apply provenance or state unavailable"
	case errors.Is(err, storage.ErrGenerationStorageBudget):
		status, message = http.StatusInsufficientStorage, "generation storage budget exceeded"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		status, message = http.StatusGatewayTimeout,
			"apply timeout: outcome uncertain; inspect durable status and recovery before further action"
	}
	// Never expose native core errors, node credentials, matcher/DNS payloads.
	writeJSON(w, status, apiv1.ErrorResponse{Error: message})
}
