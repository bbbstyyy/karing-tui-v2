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

var ErrProfileStagePreviewMismatch = errors.New("profile declaration differs from acknowledged preview")

type DeclarationStageResult struct {
 Preview DeclarationSnapshotPreview
 Revision storage.DeclarationRevision
}

// StageProfileSnapshotDeclaration re-materializes the exact accepted snapshot,
// checks the acknowledged preview digests, and stages a declaration with
// transactional source/snapshot/overlay guards. This never applies the core.
func StageProfileSnapshotDeclaration(
 ctx context.Context, store *storage.Store, profileID string,
 snapshotID int64, expectedDeclarationRevision uint64,
 expectedCandidateSHA256 string, expectedOverlaySHA256 string,
) (DeclarationStageResult, error) {
 if len(expectedCandidateSHA256) != 64 || len(expectedOverlaySHA256) != 64 {
  return DeclarationStageResult{}, ErrProfileStagePreviewMismatch
 }
 preview, err := PreviewProfileSnapshotDeclaration(ctx, store, profileID, snapshotID, expectedDeclarationRevision)
 if err != nil { return DeclarationStageResult{}, err }
 if preview.CandidateSHA256 != expectedCandidateSHA256 || preview.RuntimeOverlaySHA256 != expectedOverlaySHA256 {
  return DeclarationStageResult{}, ErrProfileStagePreviewMismatch
 }
 source, err := store.ProfileSource(ctx, profileID)
 if err != nil { return DeclarationStageResult{}, err }
 base, err := store.CurrentDeclaration(ctx)
 if err != nil { return DeclarationStageResult{}, err }
 if base.Revision != expectedDeclarationRevision { return DeclarationStageResult{}, ErrPreviewDeclarationStale }
 snapshot, err := store.ProfileSnapshotByID(ctx, profileID, snapshotID)
 if err != nil { return DeclarationStageResult{}, err }
 nodes, err := MaterializeBasicProfileSnapshot(snapshot)
 if err != nil { return DeclarationStageResult{}, err }
 overlays, err := store.ProfileNodeOverlays(ctx, profileID)
 if err != nil { return DeclarationStageResult{}, err }
 effective, overlayHash, err := ApplyRuntimeNodeOverlays(nodes, overlays)
 if err != nil { return DeclarationStageResult{}, err }
 replacement, err := declaration.ReplaceProfileNodesV1(base.DocumentJSON, profileID, effective)
 if err != nil { return DeclarationStageResult{}, err }
 sum := sha256.Sum256(replacement.Document)
 if hex.EncodeToString(sum[:]) != expectedCandidateSHA256 || overlayHash != expectedOverlaySHA256 {
  return DeclarationStageResult{}, ErrProfileStagePreviewMismatch
 }
 revision, err := store.CommitProfileDeclarationGuarded(ctx, profileID, snapshotID,
  source.Revision, overlays, expectedDeclarationRevision, replacement.Document,
  fmt.Sprintf("profile-snapshot/%d/overlay/%s", snapshotID, overlayHash))
 if err != nil { return DeclarationStageResult{}, err }
 return DeclarationStageResult{Preview:preview, Revision:revision}, nil
}
