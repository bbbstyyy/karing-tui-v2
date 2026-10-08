//go:build linux

package daemon

import (
 "bytes"
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "time"

 "github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
 "github.com/bbbstyyy/karing-tui-v2/internal/profile"
 "github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestProfileNodeAPIPageAndCAS(t *testing.T) {
 ctx := context.Background()
 store := newDaemonProfileMetadataStore(t, ctx)
 defer store.Close()
 _, err := store.CommitProfileSource(ctx, 0, profile.SourceSpec{
  ProfileID:"profile-a", Format:profile.SourceFormatSingBox,
  LocationKind:profile.SourceLocationFile, Location:"/tmp/source.json",
  Fetch:profile.FetchPolicy{Mode:profile.FetchDirect}, Enabled:true,
 })
 if err != nil { t.Fatal(err) }
 commit, err := store.CommitProfileSnapshot(ctx, storage.ProfileSnapshotCandidate{
  ProfileID:"profile-a", SourceKind:"sing-box", SourceSHA256:strings.Repeat("a",64),
  Nodes:[]profile.SourceNode{{SourceKey:"private-key", SourceName:"Node A",
   PayloadJSON:[]byte("{\"type\":\"http\",\"tag\":\"private-key\",\"server\":\"example.org\",\"server_port\":443,\"password\":\"SECRET_VALUE\"}")}},
 },storage.ProfileSnapshotCommitOptions{})
 if err != nil { t.Fatal(err) }
 id := commit.Snapshot.Nodes[0].Identity.NodeID
 api := httptest.NewServer((&Server{started:time.Now().UTC()}).handler(store,nil))
 defer api.Close()
 status, body := requestProfileAPI(t,api.URL,http.MethodGet,"/v1/profiles/profile-a/nodes?limit=1",nil)
 if status != 200 || bytes.Contains(body,[]byte("SECRET_VALUE")) || bytes.Contains(body,[]byte("private-key")) {
  t.Fatalf("unsafe nodes response: %d %s",status,body)
 }
 var page apiv1.ProfileNodeListResponse
 if err := json.Unmarshal(body,&page); err != nil {t.Fatal(err)}
 if page.Total != 1 || len(page.Nodes) != 1 || page.Nodes[0].NodeID != id || page.Nodes[0].OverlayRevision != 0 {
  t.Fatalf("node page: %+v",page)
 }
 path := "/v1/profiles/profile-a/nodes/"+id+"/overlay"
 status, body = requestProfileAPI(t,api.URL,http.MethodPut,path,apiv1.ProfileNodeOverlayPutRequest{
  ExpectedRevision:0,Overlay:apiv1.ProfileNodeOverlaySpec{Disabled:true,Favorite:true,Alias:"Pinned"},
 })
 if status != 200 {t.Fatalf("overlay put: %d %s",status,body)}
 status, _ = requestProfileAPI(t,api.URL,http.MethodPut,path,apiv1.ProfileNodeOverlayPutRequest{ExpectedRevision:0})
 if status != 409 {t.Fatalf("stale CAS: %d",status)}
 status, _ = requestProfileAPI(t,api.URL,http.MethodPut,path,map[string]any{
  "expected_revision":1,"overlay":map[string]any{"unknown":true},
 })
 if status != 400 {t.Fatalf("unknown field: %d",status)}
 status, _ = requestProfileAPI(t,api.URL,http.MethodPut,path,apiv1.ProfileNodeOverlayPutRequest{
  ExpectedRevision:1, Overlay:apiv1.ProfileNodeOverlaySpec{Alias:"bad\nname"},
 })
 if status != 422 {t.Fatalf("invalid alias: %d",status)}
 status, _ = requestProfileAPI(t,api.URL,http.MethodPut,"/v1/profiles/profile-a/nodes/absent/overlay",apiv1.ProfileNodeOverlayPutRequest{})
 if status != 409 {t.Fatalf("unknown node: %d",status)}
 for _, query := range []string{"?limit=201","?offset=-1","?limit=1&limit=2","?other=1"} {
  status,_ = requestProfileAPI(t,api.URL,http.MethodGet,"/v1/profiles/profile-a/nodes"+query,nil)
  if status != 400 {t.Fatalf("query %s: %d",query,status)}
 }
 status,body = requestProfileAPI(t,api.URL,http.MethodGet,"/v1/profiles/profile-a/nodes",nil)
 if status != 200 || bytes.Contains(body,[]byte("SECRET_VALUE")) {t.Fatalf("read after edit: %d %s",status,body)}
 if err := json.Unmarshal(body,&page); err != nil {t.Fatal(err)}
 if page.Nodes[0].OverlayRevision != 1 || page.Nodes[0].DisplayName != "Pinned" || !page.Nodes[0].Disabled {t.Fatalf("overlay not joined: %+v",page)}
 snapshot,ok,err := store.CurrentProfileSnapshot(ctx,"profile-a")
 if err != nil || !ok || snapshot.ID != commit.Snapshot.ID {t.Fatalf("snapshot mutated: %+v, %v",snapshot,err)}
 decl,err := store.CurrentDeclaration(ctx)
 if err != nil || decl.Revision != 0 {t.Fatalf("declaration mutated: %+v, %v",decl,err)}
}
