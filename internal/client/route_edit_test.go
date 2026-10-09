package client

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestRouteEditClientCarriesFullBindingAndDoesNotRetryStaleStage(t *testing.T) {
	listener,err:=net.Listen("unix",filepath.Join(t.TempDir(),"edit.sock"))
	if err!=nil{t.Fatal(err)}
	counts:=map[string]int{}
	server:=httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,req *http.Request){
		counts[req.URL.Path]++
		switch req.URL.Path {
		case "/v1/config/route-edit/context":
			if req.Method!=http.MethodGet {w.WriteHeader(http.StatusMethodNotAllowed);return}
			_ = json.NewEncoder(w).Encode(apiv1.RouteEditContext{
				APIVersion:"v1",DeclarationRevision:7,DeclarationSHA256:strings.Repeat("a",64),
				ConfigRevision:4,SelectionRevision:9,
			})
		case "/v1/config/route-edit/preview":
			if req.Method!=http.MethodPost {w.WriteHeader(http.StatusMethodNotAllowed);return}
			var q apiv1.RouteEditRequest
			if err:=json.NewDecoder(req.Body).Decode(&q);err!=nil {w.WriteHeader(400);return}
			if q.ExpectedDeclarationRevision!=7||q.ExpectedConfigRevision!=4||
				q.ExpectedSelectionRevision!=9||q.ExpectedDeclarationSHA256!=strings.Repeat("a",64)||
				q.Target==nil||q.Target.Kind!=domain.TargetDirect||
				q.Layer!=domain.LayerFinal||q.GroupID!="FINAL" {
				w.WriteHeader(http.StatusBadRequest);return
			}
			_ = json.NewEncoder(w).Encode(apiv1.RouteEditPreviewResponse{
				APIVersion:"v1",Request:q,CandidateSHA256:strings.Repeat("b",64),
				NativeConfigSHA256:strings.Repeat("c",64),CompilerValidated:true,
			})
		case "/v1/config/route-edit/stage":
			if req.Method!=http.MethodPost {w.WriteHeader(http.StatusMethodNotAllowed);return}
			var q apiv1.RouteEditStageRequest
			if err:=json.NewDecoder(req.Body).Decode(&q);err!=nil {w.WriteHeader(400);return}
			if q.ExpectedDeclarationRevision!=7||q.ExpectedConfigRevision!=4||
				q.ExpectedSelectionRevision!=9||q.Target==nil||q.Target.Kind!=domain.TargetDirect||
				q.CandidateSHA256!=strings.Repeat("b",64)||q.NativeConfigSHA256!=strings.Repeat("c",64) {
				w.WriteHeader(http.StatusBadRequest);return
			}
			if counts[req.URL.Path]>1 {w.WriteHeader(http.StatusConflict);return}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(apiv1.RouteEditStageResponse{
				DeclarationRevision:8,DeclarationSHA256:strings.Repeat("b",64),
				NativeConfigSHA256:strings.Repeat("c",64),Staged:true,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	if err:=server.Listener.Close();err!=nil{t.Fatal(err)}
	server.Listener=listener;server.Start();defer server.Close()
	api:=New(listener.Addr().String())
	b,err:=api.RouteEditContext(context.Background())
	if err!=nil||b.DeclarationRevision!=7{t.Fatalf("binding: %+v %v",b,err)}
	req:=apiv1.RouteEditRequest{
		ExpectedDeclarationRevision:b.DeclarationRevision,
		ExpectedDeclarationSHA256:b.DeclarationSHA256,
		ExpectedConfigRevision:b.ConfigRevision,
		ExpectedSelectionRevision:b.SelectionRevision,
		Layer:domain.LayerFinal,GroupID:"FINAL",
		Target:&domain.TargetRef{Kind:domain.TargetDirect},
	}
	p,err:=api.PreviewRouteEdit(context.Background(),req)
	if err!=nil||p.CandidateSHA256!=strings.Repeat("b",64){t.Fatalf("preview: %+v %v",p,err)}
	s:=apiv1.RouteEditStageRequest{RouteEditRequest:p.Request,
		CandidateSHA256:p.CandidateSHA256,NativeConfigSHA256:p.NativeConfigSHA256}
	if _,err=api.StageRouteEdit(context.Background(),s);err!=nil{t.Fatal(err)}
	if _,err=api.StageRouteEdit(context.Background(),s);err==nil||
		!strings.Contains(err.Error(),"409")||counts["/v1/config/route-edit/stage"]!=2 {
		t.Fatalf("stale write was hidden or retried: err=%v calls=%d",err,counts["/v1/config/route-edit/stage"])
	}
}
