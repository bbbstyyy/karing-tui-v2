package profileupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/netip"

	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var (
	ErrInitialDeclarationUnavailable = errors.New("first-run declaration is not available")
	ErrInitialDeclarationInvalid     = errors.New("first-run declaration inputs are invalid")
	ErrInitialDeclarationMismatch    = errors.New("first-run declaration receipt changed")
)

type InitialDeclarationPreview struct {
	ProfileID            string
	SnapshotID           int64
	SourceRevision       uint64
	EffectiveNodeCount   int
	SelectedNodeID       string
	ResolverAddress      string
	RuntimeOverlaySHA256 string
	CandidateSHA256      string
}

func PreviewInitialProfileDeclaration(
	ctx context.Context, store *storage.Store,
	profileID string, snapshotID int64, selectedNodeID, resolverAddress string,
) (InitialDeclarationPreview, error) {
	if store == nil || profile.ValidateProfileID(profileID) != nil || snapshotID <= 0 ||
		selectedNodeID == "" {
		return InitialDeclarationPreview{}, ErrInitialDeclarationInvalid
	}
	resolver, err := netip.ParseAddrPort(resolverAddress)
	if err != nil || !resolver.IsValid() {
		return InitialDeclarationPreview{}, ErrInitialDeclarationInvalid
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil {
		return InitialDeclarationPreview{}, err
	}
	state, err := store.Snapshot(ctx)
	if err != nil {
		return InitialDeclarationPreview{}, err
	}
	if current.Revision != 0 || state.Revision != 0 ||
		state.AppliedGenerationID != nil || state.LastKnownGoodGenerationID != nil ||
		state.RecoveryRequired || state.ActiveAttemptID != nil {
		return InitialDeclarationPreview{}, ErrInitialDeclarationUnavailable
	}
	source, err := store.ProfileSource(ctx, profileID)
	if err != nil {
		return InitialDeclarationPreview{}, err
	}
	if !source.Spec.Enabled || source.Revision == 0 ||
		source.CurrentSnapshotID == nil || *source.CurrentSnapshotID != snapshotID {
		return InitialDeclarationPreview{}, ErrInitialDeclarationUnavailable
	}
	snapshot, err := store.ProfileSnapshotByID(ctx, profileID, snapshotID)
	if err != nil {
		return InitialDeclarationPreview{}, err
	}
	imported, err := MaterializeBasicProfileSnapshot(snapshot)
	if err != nil {
		return InitialDeclarationPreview{}, ErrInitialDeclarationInvalid
	}
	overlays, err := store.ProfileNodeOverlays(ctx, profileID)
	if err != nil {
		return InitialDeclarationPreview{}, err
	}
	effective, overlaySHA, err := ApplyRuntimeNodeOverlays(imported, overlays)
	if err != nil {
		return InitialDeclarationPreview{}, ErrInitialDeclarationInvalid
	}
	document, err := declaration.BuildInitialProxyOnlyV1(effective, selectedNodeID, resolver)
	if err != nil || len(document) > storage.MaxDeclarationBytes {
		return InitialDeclarationPreview{}, ErrInitialDeclarationInvalid
	}
	sum := sha256.Sum256(document)
	preview := InitialDeclarationPreview{
		ProfileID: profileID, SnapshotID: snapshotID,
		SourceRevision:       source.Revision,
		EffectiveNodeCount:   len(effective),
		SelectedNodeID:       selectedNodeID,
		ResolverAddress:      resolver.String(),
		RuntimeOverlaySHA256: overlaySHA,
		CandidateSHA256:      hex.EncodeToString(sum[:]),
	}
	freshSource, err := store.ProfileSource(ctx, profileID)
	if err != nil {
		return InitialDeclarationPreview{}, err
	}
	freshCurrent, err := store.CurrentDeclaration(ctx)
	if err != nil {
		return InitialDeclarationPreview{}, err
	}
	freshOverlays, err := store.ProfileNodeOverlays(ctx, profileID)
	if err != nil {
		return InitialDeclarationPreview{}, err
	}
	freshState, err := store.Snapshot(ctx)
	if err != nil {
		return InitialDeclarationPreview{}, err
	}
	if freshSource.Revision != source.Revision || !freshSource.Spec.Enabled ||
		freshSource.CurrentSnapshotID == nil || *freshSource.CurrentSnapshotID != snapshotID ||
		freshCurrent.Revision != 0 || !sameProfileOverlayRevisions(overlays, freshOverlays) ||
		freshState.Revision != 0 || freshState.AppliedGenerationID != nil ||
		freshState.LastKnownGoodGenerationID != nil || freshState.RecoveryRequired ||
		freshState.ActiveAttemptID != nil {
		return InitialDeclarationPreview{}, ErrInitialDeclarationUnavailable
	}
	return preview, nil
}

func StageInitialProfileDeclaration(
	ctx context.Context, store *storage.Store, profileID string,
	snapshotID int64, expectedSourceRevision uint64, selectedNodeID, resolverAddress,
	expectedCandidateSHA256, expectedOverlaySHA256 string,
) (storage.DeclarationRevision, error) {
	if store == nil || expectedSourceRevision == 0 ||
		len(expectedCandidateSHA256) != 64 || len(expectedOverlaySHA256) != 64 {
		return storage.DeclarationRevision{}, ErrInitialDeclarationMismatch
	}
	preview, err := PreviewInitialProfileDeclaration(ctx, store, profileID, snapshotID,
		selectedNodeID, resolverAddress)
	if err != nil {
		return storage.DeclarationRevision{}, err
	}
	if preview.SourceRevision != expectedSourceRevision ||
		preview.CandidateSHA256 != expectedCandidateSHA256 ||
		preview.RuntimeOverlaySHA256 != expectedOverlaySHA256 {
		return storage.DeclarationRevision{}, ErrInitialDeclarationMismatch
	}
	snapshot, err := store.ProfileSnapshotByID(ctx, profileID, snapshotID)
	if err != nil {
		return storage.DeclarationRevision{}, err
	}
	nodes, err := MaterializeBasicProfileSnapshot(snapshot)
	if err != nil {
		return storage.DeclarationRevision{}, ErrInitialDeclarationMismatch
	}
	overlays, err := store.ProfileNodeOverlays(ctx, profileID)
	if err != nil {
		return storage.DeclarationRevision{}, err
	}
	effective, overlaySHA, err := ApplyRuntimeNodeOverlays(nodes, overlays)
	if err != nil || overlaySHA != expectedOverlaySHA256 {
		return storage.DeclarationRevision{}, ErrInitialDeclarationMismatch
	}
	resolver, err := netip.ParseAddrPort(resolverAddress)
	if err != nil {
		return storage.DeclarationRevision{}, ErrInitialDeclarationMismatch
	}
	document, err := declaration.BuildInitialProxyOnlyV1(effective, selectedNodeID, resolver)
	if err != nil {
		return storage.DeclarationRevision{}, ErrInitialDeclarationMismatch
	}
	sum := sha256.Sum256(document)
	if hex.EncodeToString(sum[:]) != expectedCandidateSHA256 {
		return storage.DeclarationRevision{}, ErrInitialDeclarationMismatch
	}
	// The SQLite transaction atomically checks source, accepted snapshot,
	// overlays and declaration revision zero. No Core action takes place.
	return store.CommitProfileDeclarationGuarded(
		ctx, profileID, snapshotID, expectedSourceRevision, overlays, 0,
		document, "first-run:proxy-only",
	)
}
