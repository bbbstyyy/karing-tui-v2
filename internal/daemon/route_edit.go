package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var (
	ErrRouteEditConflict = errors.New("route edit optimistic binding conflict")
	ErrRouteEditRejected = errors.New("route edit or DNS binding cannot be compiled")
	ErrRouteEditUnavailable = errors.New("route edit unavailable")
)

const routeEditStageSource = "tui:route-dns-stage"

// routeEditContext never returns raw declarations, matcher payloads, DNS
// upstream servers, credentials or the core secret.
func routeEditContext(ctx context.Context, store *storage.Store) (apiv1.RouteEditContext, error) {
	if store == nil {
		return apiv1.RouteEditContext{}, ErrRouteEditUnavailable
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return apiv1.RouteEditContext{}, ErrRouteEditUnavailable
	}
	if snapshot.RecoveryRequired || snapshot.ActiveAttemptID != nil {
		return apiv1.RouteEditContext{}, ErrRouteEditConflict
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil || current.Revision == 0 || len(current.DocumentJSON) == 0 ||
		!validRouteEditSHA(current.SHA256) {
		return apiv1.RouteEditContext{}, ErrRouteEditUnavailable
	}
	sum := sha256.Sum256(current.DocumentJSON)
	if hex.EncodeToString(sum[:]) != current.SHA256 {
		return apiv1.RouteEditContext{}, ErrRouteEditUnavailable
	}
	intent, _, err := store.CurrentSelectionIntent(ctx)
	if err != nil {
		return apiv1.RouteEditContext{}, ErrRouteEditUnavailable
	}
	recheck, err := store.Snapshot(ctx)
	if err != nil || recheck.Revision != snapshot.Revision ||
		recheck.RecoveryRequired || recheck.ActiveAttemptID != nil ||
		!sameGenerationID(recheck.AppliedGenerationID, snapshot.AppliedGenerationID) {
		return apiv1.RouteEditContext{}, ErrRouteEditConflict
	}
	head, err := store.CurrentDeclaration(ctx)
	if err != nil || head.Revision != current.Revision || head.SHA256 != current.SHA256 {
		return apiv1.RouteEditContext{}, ErrRouteEditConflict
	}
	return apiv1.RouteEditContext{
		APIVersion: apiv1.Version,
		DeclarationRevision: current.Revision,
		DeclarationSHA256: current.SHA256,
		ConfigRevision: snapshot.Revision,
		AppliedGenerationID: cloneRouteEditGeneration(snapshot.AppliedGenerationID),
		SelectionRevision: intent.Revision,
	}, nil
}

func cloneRouteEditGeneration(id *int64) *int64 {
	if id == nil {
		return nil
	}
	value := *id
	return &value
}

func validRouteEditSHA(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func validateRouteEditBinding(base apiv1.RouteEditContext, req apiv1.RouteEditRequest) error {
	if req.ExpectedDeclarationRevision == 0 ||
		req.ExpectedDeclarationRevision > uint64(1<<63-1) ||
		!validRouteEditSHA(req.ExpectedDeclarationSHA256) ||
		(req.ExpectedGenerationID != nil && *req.ExpectedGenerationID <= 0) {
		return ErrRouteEditRejected
	}
	if base.DeclarationRevision != req.ExpectedDeclarationRevision ||
		base.DeclarationSHA256 != req.ExpectedDeclarationSHA256 ||
		base.ConfigRevision != req.ExpectedConfigRevision ||
		!sameGenerationID(base.AppliedGenerationID, req.ExpectedGenerationID) ||
		base.SelectionRevision != req.ExpectedSelectionRevision {
		return ErrRouteEditConflict
	}
	return nil
}

type routeEditEvaluated struct {
	preview apiv1.RouteEditPreviewResponse
	document []byte
}

func evaluateRouteEdit(
	ctx context.Context,
	store *storage.Store,
	compiler *DeclarationCompileCoordinator,
	req apiv1.RouteEditRequest,
) (routeEditEvaluated, error) {
	if store == nil || compiler == nil {
		return routeEditEvaluated{}, ErrRouteEditUnavailable
	}
	base, err := routeEditContext(ctx, store)
	if err != nil {
		return routeEditEvaluated{}, err
	}
	if err := validateRouteEditBinding(base, req); err != nil {
		return routeEditEvaluated{}, err
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil || current.Revision != req.ExpectedDeclarationRevision ||
		current.SHA256 != req.ExpectedDeclarationSHA256 {
		return routeEditEvaluated{}, ErrRouteEditConflict
	}
	edit, err := declaration.PatchRouteGroupV1(current.DocumentJSON, declaration.RoutePatch{
		Layer: req.Layer, GroupID: req.GroupID,
		Enabled: req.Enabled, Target: req.Target, DNSProfileID: req.DNSProfileID,
	})
	if err != nil || len(edit.Document) > storage.MaxDeclarationBytes {
		return routeEditEvaluated{}, ErrRouteEditRejected
	}
	artifact, err := compiler.CompileCandidate(ctx, edit.Document)
	if err != nil {
		// Resources must be resolved by the configured strict compiler.
		// Do not surface user-controlled matcher or credential values.
		return routeEditEvaluated{}, fmt.Errorf("%w: strict candidate compile failed", ErrRouteEditRejected)
	}
	// The validation/compilation path must be pinned to the same selector,
	// generation, config and declaration state read before compiling.
	fresh, err := routeEditContext(ctx, store)
	if err != nil {
		return routeEditEvaluated{}, err
	}
	if err := validateRouteEditBinding(fresh, req); err != nil {
		return routeEditEvaluated{}, err
	}
	sum := sha256.Sum256(edit.Document)
	return routeEditEvaluated{
		document: edit.Document,
		preview: apiv1.RouteEditPreviewResponse{
			APIVersion: apiv1.Version,
			Request: req,
			Origin: edit.Origin,
			BeforeEnabled: edit.Before.Enabled,
			AfterEnabled: edit.After.Enabled,
			BeforeTarget: edit.Before.Target,
			AfterTarget: edit.After.Target,
			BeforeDNSProfileID: edit.Before.DNSProfileID,
			AfterDNSProfileID: edit.After.DNSProfileID,
			CandidateSHA256: hex.EncodeToString(sum[:]),
			NativeConfigSHA256: artifact.SHA256,
			NativeSchemaID: artifact.Manifest.SchemaID,
			RouteEntryCount: len(artifact.SourceMap),
			DNSServerCount: len(artifact.Manifest.DNSServerTags),
			RuleSetCount: len(artifact.Manifest.RuleSets),
			CompilerValidated: true,
			CoreValidated: false,
			Staged: false,
			Applied: false,
		},
	}, nil
}

func previewRouteEdit(
	ctx context.Context, store *storage.Store,
	compiler *DeclarationCompileCoordinator, req apiv1.RouteEditRequest,
) (apiv1.RouteEditPreviewResponse, error) {
	evaluated, err := evaluateRouteEdit(ctx, store, compiler, req)
	if err != nil {
		return apiv1.RouteEditPreviewResponse{}, err
	}
	return evaluated.preview, nil
}

// The stage operation *always* regenerates and recompiles its candidate;
// acknowledgements are immutable SHA-256 digests from preview. No request
// can upload raw declaration/core JSON through this route.
func stageRouteEdit(
	ctx context.Context, store *storage.Store,
	compiler *DeclarationCompileCoordinator, req apiv1.RouteEditStageRequest,
) (apiv1.RouteEditStageResponse, error) {
	if !validRouteEditSHA(req.CandidateSHA256) || !validRouteEditSHA(req.NativeConfigSHA256) {
		return apiv1.RouteEditStageResponse{}, ErrRouteEditRejected
	}
	evaluated, err := evaluateRouteEdit(ctx, store, compiler, req.RouteEditRequest)
	if err != nil {
		return apiv1.RouteEditStageResponse{}, err
	}
	if evaluated.preview.CandidateSHA256 != req.CandidateSHA256 ||
		evaluated.preview.NativeConfigSHA256 != req.NativeConfigSHA256 {
		return apiv1.RouteEditStageResponse{}, ErrRouteEditConflict
	}
	// CommitDeclaration's SQLite transaction is the second authority: a
	// competing legacy POST still cannot overwrite an intervening revision.
	committed, err := store.CommitDeclaration(
		ctx, req.ExpectedDeclarationRevision, evaluated.document, routeEditStageSource,
	)
	if errors.Is(err, storage.ErrDeclarationRevisionConflict) {
		return apiv1.RouteEditStageResponse{}, ErrRouteEditConflict
	}
	if err != nil {
		return apiv1.RouteEditStageResponse{}, ErrRouteEditUnavailable
	}
	if committed.Revision != req.ExpectedDeclarationRevision+1 ||
		committed.SHA256 != req.CandidateSHA256 {
		return apiv1.RouteEditStageResponse{}, ErrRouteEditUnavailable
	}
	return apiv1.RouteEditStageResponse{
		DeclarationRevision: committed.Revision,
		DeclarationSHA256: committed.SHA256,
		NativeConfigSHA256: evaluated.preview.NativeConfigSHA256,
		CompilerValidated: true, CoreValidated: false,
		Staged: true, Applied: false,
	}, nil
}
