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

func registerProfileDeclarationStageRoutes(mux *http.ServeMux, store *storage.Store, gate *profileOperationGate) {
 mux.HandleFunc("POST /v1/profiles/{profile_id}/declaration/stage", func(w http.ResponseWriter, r *http.Request) {
  var request apiv1.ProfileDeclarationStageRequest
  if err:=decodeProfileAPIRequest(w,r,&request); err!=nil {
   writeJSON(w,http.StatusBadRequest,apiv1.ErrorResponse{Error:"invalid declaration stage request"});return
  }
  if request.SnapshotID<=0 || request.ExpectedDeclarationRevision==0 ||
    len(request.CandidateSHA256)!=64 || len(request.RuntimeOverlaySHA256)!=64 {
   writeJSON(w,http.StatusBadRequest,apiv1.ErrorResponse{Error:"snapshot, revision and 64-character preview digests required"});return
  }
  id:=r.PathValue("profile_id")
  if err:=profile.ValidateProfileID(id); err!=nil {
   writeJSON(w,http.StatusBadRequest,apiv1.ErrorResponse{Error:"invalid profile ID"});return
  }
  if !gate.TryAcquire(id) {writeProfileAPIBusy(w);return}
  defer gate.Release(id)
  ctx,cancel:=context.WithTimeout(context.WithoutCancel(r.Context()),30*time.Second)
  defer cancel()
  result,err:=profileupdate.StageProfileSnapshotDeclaration(ctx,store,id,request.SnapshotID,
   request.ExpectedDeclarationRevision,request.CandidateSHA256,request.RuntimeOverlaySHA256)
  if err!=nil {
   if errors.Is(err,profileupdate.ErrProfileStagePreviewMismatch) ||
    errors.Is(err,storage.ErrProfileDeclarationGuardConflict) ||
    errors.Is(err,storage.ErrDeclarationRevisionConflict) {
    writeJSON(w,http.StatusConflict,apiv1.ErrorResponse{Error:"profile declaration stage preconditions changed"});return
   }
   writeProfileSnapshotPreviewError(w,err);return
  }
  writeJSON(w,http.StatusCreated,apiv1.ProfileDeclarationStageResponse{
   ProfileID:id,SnapshotID:request.SnapshotID,DeclarationRevision:result.Revision.Revision,
   DeclarationSHA256:result.Revision.SHA256,CoreValidated:false,Applied:false,
  })
 })
}
