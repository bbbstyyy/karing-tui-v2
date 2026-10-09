package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

type fakeRouteConfigCLI struct {
	contextCalls int
	previewCalls int
	stageCalls int
	contextValue apiv1.RouteEditContext
	previewReq apiv1.RouteEditRequest
	stageReq apiv1.RouteEditStageRequest
	contextError error
	previewError error
	stageError error
}

func (f *fakeRouteConfigCLI) RouteEditContext(context.Context)(apiv1.RouteEditContext,error){
	f.contextCalls++
	return f.contextValue,f.contextError
}
func (f *fakeRouteConfigCLI) PreviewRouteEdit(_ context.Context,r apiv1.RouteEditRequest)(apiv1.RouteEditPreviewResponse,error){
	f.previewCalls++;f.previewReq=r
	if f.previewError!=nil {return apiv1.RouteEditPreviewResponse{},f.previewError}
	return apiv1.RouteEditPreviewResponse{
		APIVersion:apiv1.Version,Request:r,Origin:"custom",
		BeforeEnabled:true,AfterEnabled:true,
		BeforeTarget:domain.TargetRef{Kind:domain.TargetCurrentSelected},
		AfterTarget:domain.TargetRef{Kind:domain.TargetDirect},
		CandidateSHA256:strings.Repeat("b",64),NativeConfigSHA256:strings.Repeat("c",64),
		NativeSchemaID:"sing-box-compatible",CompilerValidated:true,
		CoreValidated:false,Staged:false,Applied:false,
	},nil
}
func (f *fakeRouteConfigCLI) StageRouteEdit(_ context.Context,r apiv1.RouteEditStageRequest)(apiv1.RouteEditStageResponse,error){
	f.stageCalls++;f.stageReq=r
	if f.stageError!=nil{return apiv1.RouteEditStageResponse{},f.stageError}
	return apiv1.RouteEditStageResponse{
		DeclarationRevision:r.ExpectedDeclarationRevision+1,DeclarationSHA256:r.CandidateSHA256,
		NativeConfigSHA256:r.NativeConfigSHA256,CompilerValidated:true,Staged:true,Applied:false,
	},nil
}
func routeConfigTest(ctx context.Context, api *fakeRouteConfigCLI,args ...string)(int,string,string){
	var out,err bytes.Buffer
	code:=runRouteConfigCommand(ctx,api,args,&out,&err)
	return code,out.String(),err.String()
}
func routeConfigFake() *fakeRouteConfigCLI {
	return &fakeRouteConfigCLI{contextValue:apiv1.RouteEditContext{
		APIVersion:apiv1.Version,DeclarationRevision:8,
		DeclarationSHA256:strings.Repeat("a",64),ConfigRevision:12,
		SelectionRevision:3,
	}}
}
func TestRouteConfigCLIPreviewAndConfirmedStageDoNotAutoApply(t *testing.T){
	api:=routeConfigFake()
	path:=filepath.Join(t.TempDir(),"route-receipt.json")
	code,out,stderr:=routeConfigTest(context.Background(),api,
		"route-preview","--layer=final","--group=FINAL","--target-kind=direct","--out="+path)
	if code!=0 || stderr!="" || api.contextCalls!=1 || api.previewCalls!=1 ||
		api.stageCalls!=0 || api.previewReq.Layer!=domain.LayerFinal ||
		api.previewReq.GroupID!="FINAL" || api.previewReq.Target==nil ||
		api.previewReq.Target.Kind!=domain.TargetDirect ||
		api.previewReq.ExpectedDeclarationRevision!=8 || api.previewReq.ExpectedConfigRevision!=12 ||
		api.previewReq.ExpectedSelectionRevision!=3 ||
		!strings.Contains(out,"receipt saved") {
		t.Fatalf("preview: exit=%d out=%q stderr=%q req=%+v",code,out,stderr,api.previewReq)
	}
	st,err:=os.Stat(path)
	if err!=nil||st.Mode().Perm()!=0o600{t.Fatalf("receipt permissions: %+v %v",st,err)}
	code,out,stderr=routeConfigTest(context.Background(),api,"route-stage","--receipt="+path,"--confirm")
	if code!=0||stderr!=""||api.stageCalls!=1||
		api.stageReq.CandidateSHA256!=strings.Repeat("b",64) ||
		api.stageReq.NativeConfigSHA256!=strings.Repeat("c",64) ||
		!strings.Contains(out,"\"staged\": true") ||
		!strings.Contains(out,"\"applied\": false"){
		t.Fatalf("stage: exit=%d out=%q stderr=%q req=%+v",code,out,stderr,api.stageReq)
	}
	if code,_,_:=routeConfigTest(context.Background(),api,"route-preview","--layer=final",
		"--group=FINAL","--target-kind=direct","--out="+path);code!=1{
		t.Fatal("preview overwrote an existing receipt")
	}
}

func TestRouteConfigCLIRejectsUnsafeOptionsWithoutDaemonCalls(t *testing.T){
	api:=routeConfigFake()
	bad:=[][]string{
		{"route-preview"},
		{"route-preview","--layer=final","--group=FINAL"},
		{"route-preview","--layer=isp","--group=x","--target-kind=direct"},
		{"route-preview","--layer=final","--group=FINAL","--dns-profile-id=private"},
		{"route-preview","--layer=final","--group=FINAL","--enabled=false"},
		{"route-preview","--layer=custom","--group=x","--target-kind=direct","--enabled=false"},
		{"route-preview","--layer=custom","--group=x","--target-kind=specific_node","--profile-id=p"},
		{"route-preview","--layer=custom","--group=x","--node-id=n","--dns-profile-id="},
		{"route-preview","--layer=custom","--group=x","--enabled=maybe"},
		{"route-stage"},
		{"route-stage","--receipt=missing"},
		{"route-stage","--receipt=missing","--confirm=false"},
		{"route-stage","--receipt=missing","--confirm","extra"},
	}
	for _,args:=range bad {
		code,stdout,_:=routeConfigTest(context.Background(),api,args...)
		if code!=2||stdout!=""{t.Fatalf("invalid %v allowed: %d %q",args,code,stdout)}
	}
	if api.contextCalls!=0 || api.previewCalls!=0 || api.stageCalls!=0 {
		t.Fatalf("invalid arguments reached daemon: %+v",api)
	}
}

func TestRouteConfigCLIRefusesWorldReadableAndSymlinkReceipt(t *testing.T){
	api:=routeConfigFake()
	private:=filepath.Join(t.TempDir(),"receipt.json")
	_,_,_ = routeConfigTest(context.Background(),api,"route-preview","--layer=final",
		"--group=FINAL","--target-kind=direct","--out="+private)
	if err:=os.Chmod(private,0o644);err!=nil {t.Fatal(err)}
	code,_,_:=routeConfigTest(context.Background(),api,"route-stage","--receipt="+private,"--confirm")
	if code!=2||api.stageCalls!=0{t.Fatal("world-readable receipt was accepted")}
	if err:=os.Chmod(private,0o600);err!=nil{t.Fatal(err)}
	link:=filepath.Join(filepath.Dir(private),"symlink.json")
	if err:=os.Symlink(private,link);err!=nil{t.Fatal(err)}
	code,_,_ = routeConfigTest(context.Background(),api,"route-stage","--receipt="+link,"--confirm")
	if code!=2||api.stageCalls!=0{t.Fatal("symlink receipt was followed")}
}

func TestRouteConfigCLIRedactsDaemonErrorsAndWarnsUncertainOutcome(t *testing.T){
	api:=routeConfigFake()
	api.contextError=errors.New("daemon returned 409 Conflict: https://user:password@hidden/?token=VERY_PRIVATE")
	code,out,stderr:=routeConfigTest(context.Background(),api,"route-preview",
		"--layer=final","--group=FINAL","--target-kind=direct")
	if code!=1||out!=""||strings.Contains(stderr,"VERY_PRIVATE")||!strings.Contains(stderr,"HTTP 409"){
		t.Fatalf("preview leaked error: %d %q %q",code,out,stderr)
	}
	api.contextError=nil
	path:=filepath.Join(t.TempDir(),"confirmed.json")
	code,_,stderr=routeConfigTest(context.Background(),api,"route-preview",
		"--layer=final","--group=FINAL","--target-kind=direct","--out="+path)
	if code!=0{t.Fatalf("prep receipt: %q",stderr)}
	api.stageError=errors.New("daemon returned 502 Bad Gateway: password=VERY_PRIVATE")
	code,out,stderr=routeConfigTest(context.Background(),api,"route-stage","--receipt="+path,"--confirm")
	if code!=1||out!=""||strings.Contains(stderr,"VERY_PRIVATE")||
		!strings.Contains(stderr,"HTTP 502")||!strings.Contains(stderr,"inspect current declaration"){
		t.Fatalf("stage exposed secret or suggested retry: %d %q %q",code,out,stderr)
	}
}
