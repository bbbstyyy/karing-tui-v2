package profileupdate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var (
	ErrPreviewSnapshotNotCurrent   = errors.New("profile snapshot preview requires current accepted snapshot")
	ErrPreviewDeclarationStale     = errors.New("profile snapshot preview declaration revision changed")
	ErrPreviewDeclarationIntegrity = errors.New("profile snapshot preview base declaration integrity mismatch")
	ErrPreviewOverlayStale         = errors.New("profile snapshot preview overlay revisions changed")
	ErrPreviewSourceDisabled       = errors.New("profile declaration preview requires an enabled source")
)

type DeclarationSnapshotPreview struct {
	ProfileID               string
	SnapshotID              int64
	BaseDeclarationRevision uint64
	SourceRevision          uint64
	SnapshotNodeCount       int
	EffectiveNodeCount      int
	RuntimeOverlaySHA256    string
	CandidateSHA256         string
	Impact                  declaration.ProfileNodeReplacementImpact
}

// PreviewProfileSnapshotDeclaration never commits the declaration or the core.
// The digest is a proposed document identity only, not proof of runtime
// compilability. A future commit must revalidate these same exact inputs.
func PreviewProfileSnapshotDeclaration(
	ctx context.Context,
	store *storage.Store,
	profileID string,
	snapshotID int64,
	expectedDeclarationRevision uint64,
) (DeclarationSnapshotPreview, error) {
	if store == nil {
		return DeclarationSnapshotPreview{}, errors.New("profile snapshot preview store is nil")
	}
	if expectedDeclarationRevision == 0 {
		return DeclarationSnapshotPreview{}, ErrNoBaseDeclaration
	}
	source, err := store.ProfileSource(ctx, profileID)
	if err != nil {
		return DeclarationSnapshotPreview{}, err
	}
	if !source.Spec.Enabled {
		return DeclarationSnapshotPreview{}, ErrPreviewSourceDisabled
	}
	if source.CurrentSnapshotID == nil || *source.CurrentSnapshotID != snapshotID || snapshotID <= 0 {
		return DeclarationSnapshotPreview{}, ErrPreviewSnapshotNotCurrent
	}
	base, err := store.CurrentDeclaration(ctx)
	if err != nil {
		return DeclarationSnapshotPreview{}, err
	}
	if base.Revision != expectedDeclarationRevision {
		return DeclarationSnapshotPreview{}, fmt.Errorf("%w: expected %d, current %d", ErrPreviewDeclarationStale, expectedDeclarationRevision, base.Revision)
	}
	if len(base.DocumentJSON) == 0 || base.SHA256 == "" {
		return DeclarationSnapshotPreview{}, ErrPreviewDeclarationIntegrity
	}
	sum := sha256.Sum256(base.DocumentJSON)
	if hex.EncodeToString(sum[:]) != base.SHA256 {
		return DeclarationSnapshotPreview{}, ErrPreviewDeclarationIntegrity
	}
	snapshot, err := store.ProfileSnapshotByID(ctx, profileID, snapshotID)
	if err != nil {
		return DeclarationSnapshotPreview{}, err
	}
	preview := DeclarationSnapshotPreview{
		ProfileID: profileID, SnapshotID: snapshotID, BaseDeclarationRevision: base.Revision,
		SnapshotNodeCount: len(snapshot.Nodes), SourceRevision: source.Revision,
	}
	nodes, err := MaterializeBasicProfileSnapshot(snapshot)
	if err != nil {
		return preview, err
	}
	overlays, err := store.ProfileNodeOverlays(ctx, profileID)
	if err != nil {
		return preview, err
	}
	effective, overlaySHA, err := ApplyRuntimeNodeOverlays(nodes, overlays)
	if err != nil {
		return preview, err
	}
	preview.EffectiveNodeCount = len(effective)
	preview.RuntimeOverlaySHA256 = overlaySHA
	replacement, err := declaration.ReplaceProfileNodesV1(base.DocumentJSON, profileID, effective)
	preview.Impact = replacement.Impact
	if err != nil {
		return preview, err
	}
	if len(replacement.Document) > storage.MaxDeclarationBytes {
		return preview, storage.ErrDeclarationTooLarge
	}
	candidate := sha256.Sum256(replacement.Document)
	preview.CandidateSHA256 = hex.EncodeToString(candidate[:])
	latest, err := store.ProfileSource(ctx, profileID)
	if err != nil {
		return preview, err
	}
	if latest.CurrentSnapshotID == nil || *latest.CurrentSnapshotID != snapshotID || latest.Revision != source.Revision {
		return preview, ErrPreviewSnapshotNotCurrent
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil {
		return preview, err
	}
	if current.Revision != expectedDeclarationRevision || current.SHA256 != base.SHA256 {
		return preview, ErrPreviewDeclarationStale
	}
	latestOverlays, err := store.ProfileNodeOverlays(ctx, profileID)
	if err != nil {
		return preview, err
	}
	if !sameProfileOverlayRevisions(overlays, latestOverlays) {
		return preview, ErrPreviewOverlayStale
	}
	return preview, nil
}

func sameProfileOverlayRevisions(before, after []storage.ProfileNodeOverlayState) bool {
	if len(before) != len(after) {
		return false
	}
	for i := range before {
		if before[i].Overlay.NodeID != after[i].Overlay.NodeID ||
			before[i].Revision != after[i].Revision {
			return false
		}
	}
	return true
}
