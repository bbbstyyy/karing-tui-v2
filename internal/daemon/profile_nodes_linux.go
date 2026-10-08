//go:build linux

package daemon

import (
 "errors"
 "net/http"
 "strconv"
 "time"

 "github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
 "github.com/bbbstyyy/karing-tui-v2/internal/profile"
 "github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func registerProfileNodeRoutes(mux *http.ServeMux, store *storage.Store, gate *profileOperationGate) {
 if mux == nil || store == nil || gate == nil { return }
 mux.HandleFunc("GET /v1/profiles/{profile_id}/nodes", func(w http.ResponseWriter, r *http.Request) {
  profileID := r.PathValue("profile_id")
  if _, err := store.ProfileSource(r.Context(), profileID); err != nil { writeProfileSourceAPIError(w, err, nil); return }
  offset, limit, err := parseProfileNodePagination(r)
  if err != nil { writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: err.Error()}); return }
  page, err := store.CurrentProfileNodePage(r.Context(), profileID, offset, limit)
  if err != nil { writeProfileSourceAPIError(w, err, nil); return }
  response := apiv1.ProfileNodeListResponse{ProfileID: profileID, SnapshotID: page.SnapshotID,
   Offset: offset, Limit: limit, Total: page.Total, Nodes: make([]apiv1.ProfileNodeSummary, 0, len(page.Nodes))}
  for _, node := range page.Nodes {
   display := node.SourceName
   if node.Alias != "" { display = node.Alias }
   response.Nodes = append(response.Nodes, apiv1.ProfileNodeSummary{
    NodeID: node.NodeID, SourceName: node.SourceName, DisplayName: display,
    OverlayRevision: node.OverlayRevision, Disabled: node.Disabled, Favorite: node.Favorite,
    Alias: node.Alias, SortRank: node.SortRank,
   })
  }
  writeJSON(w, http.StatusOK, response)
 })
 mux.HandleFunc("PUT /v1/profiles/{profile_id}/nodes/{node_id}/overlay", func(w http.ResponseWriter, r *http.Request) {
  var request apiv1.ProfileNodeOverlayPutRequest
  if err := decodeProfileAPIRequest(w, r, &request); err != nil {
   writeJSON(w, http.StatusBadRequest, apiv1.ErrorResponse{Error: err.Error()}); return
  }
  profileID, nodeID := r.PathValue("profile_id"), r.PathValue("node_id")
  overlay := profile.NodeOverlay{ProfileID: profileID, NodeID: nodeID,
   Disabled: request.Overlay.Disabled, Favorite: request.Overlay.Favorite,
   Alias: request.Overlay.Alias, SortRank: request.Overlay.SortRank}
  if err := overlay.Validate(); err != nil { writeProfileSourceAPIError(w, err, nil); return }
  if !gate.TryAcquire(profileID) { writeProfileAPIBusy(w); return }
  defer gate.Release(profileID)
  if _, err := store.ProfileSource(r.Context(), profileID); err != nil { writeProfileSourceAPIError(w, err, nil); return }
  state, err := store.CommitProfileNodeOverlay(r.Context(), request.ExpectedRevision, overlay)
  if err != nil { writeProfileSourceAPIError(w, err, nil); return }
  writeJSON(w, http.StatusOK, apiv1.ProfileNodeOverlayResponse{
   ProfileID: profileID, NodeID: nodeID, Revision: state.Revision,
   UpdatedAt: state.UpdatedAt.UTC().Format(time.RFC3339Nano), Overlay: request.Overlay,
  })
 })
}

func parseProfileNodePagination(r *http.Request) (int, int, error) {
 offset, limit := 0, storage.DefaultProfileNodePageSize
 query := r.URL.Query()
 for key, values := range query {
  if (key != "offset" && key != "limit") || len(values) != 1 || values[0] == "" {
   return 0, 0, errors.New("invalid node pagination query")
  }
 }
 if values, ok := query["offset"]; ok {
  value, err := strconv.Atoi(values[0]); if err != nil { return 0, 0, errors.New("invalid node offset") }; offset = value
 }
 if values, ok := query["limit"]; ok {
  value, err := strconv.Atoi(values[0]); if err != nil { return 0, 0, errors.New("invalid node limit") }; limit = value
 }
 if offset < 0 || offset > storage.MaxProfileNodePageOffset ||
  limit <= 0 || limit > storage.MaxProfileNodePageSize {
  return 0, 0, errors.New("node pagination exceeds limit")
 }
 return offset, limit, nil
}
