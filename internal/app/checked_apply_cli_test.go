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
)

type fakeCheckedApplyCLI struct {
	preview apiv1.CheckedApplyPreviewResponse
	apply   apiv1.CheckedApplyResponse
	status  apiv1.StatusResponse
	previewError error
	applyError error
	statusError error
	previewCalls int
	applyCalls int
	statusCalls int
	lastReceipt apiv1.CheckedApplyReceipt
}

func newCheckedApplyFake() *fakeCheckedApplyCLI {
	digestA,digestB:=strings.Repeat("a",64),strings.Repeat("b",64)
	return &fakeCheckedApplyCLI{
		preview:apiv1.CheckedApplyPreviewResponse{
			APIVersion:apiv1.Version,
			Receipt:apiv1.CheckedApplyReceipt{
				DeclarationRevision:4,
				DeclarationSHA256:digestA,
				ExpectedConfigRevision:2,
				ExpectedSelectionRevision:7,
				NativeConfigSHA256:digestB,
			},
			NativeSchemaID:"native-schema",RouteEntryCount:31,DNSServerCount:5,
			RuleSetCount:2,CompilerValidated:true,
		},
		apply:apiv1.CheckedApplyResponse{
			DeclarationApplyResponse:apiv1.DeclarationApplyResponse{
				DeclarationRevision:4,DeclarationSHA256:digestA,
				NativeSchemaID:"native-schema",ConfigSHA256:digestB,
				AttemptID:11,GenerationID:22,
				BaseConfigRevision:2,TargetConfigRevision:3,
			},
			CoreChecked:true,Verified:true,Applied:true,
		},
		status:apiv1.StatusResponse{
			APIVersion:apiv1.Version,ConfigRevision:3,
			DeclarationRevision:4,AppliedGenerationID:func()*int64{v:=int64(22);return &v}(),
			CoreState:"running",CoreLastError:"password=PRIVATE_STATUS",
		},
	}
}

func (f *fakeCheckedApplyCLI) CheckedApplyPreview(ctx context.Context) (apiv1.CheckedApplyPreviewResponse,error) {
	f.previewCalls++
	if _,ok:=ctx.Deadline();!ok { return apiv1.CheckedApplyPreviewResponse{},errors.New("no preview deadline") }
	return f.preview,f.previewError
}
func (f *fakeCheckedApplyCLI) CheckedApply(ctx context.Context, receipt apiv1.CheckedApplyReceipt) (apiv1.CheckedApplyResponse,error) {
	f.applyCalls++
	f.lastReceipt=receipt
	if _,ok:=ctx.Deadline();!ok { return apiv1.CheckedApplyResponse{},errors.New("no apply deadline") }
	return f.apply,f.applyError
}
func (f *fakeCheckedApplyCLI) Status(ctx context.Context) (apiv1.StatusResponse,error) {
	f.statusCalls++
	if _,ok:=ctx.Deadline();!ok { return apiv1.StatusResponse{},errors.New("no status deadline") }
	return f.status,f.statusError
}

func checkedApplyCLIForTest(api *fakeCheckedApplyCLI,args ...string)(int,string,string) {
	var stdout,stderr bytes.Buffer
	code:=runCheckedApplyCLI(context.Background(),api,args,&stdout,&stderr)
	return code,stdout.String(),stderr.String()
}

func TestCheckedApplyCLIPrivatePreviewExplicitConfirmationAndReadback(t *testing.T) {
	api:=newCheckedApplyFake()
	path:=filepath.Join(t.TempDir(),"apply-preview.json")
	code,output,errOut:=checkedApplyCLIForTest(api,"apply-preview","--out="+path)
	if code!=0 || errOut!="" || api.previewCalls!=1 || api.applyCalls!=0 ||
		!strings.Contains(output,"NOT checked/applied") {
		t.Fatalf("compiler preview failed: %d %q %q",code,output,errOut)
	}
	info,err:=os.Stat(path)
	if err!=nil || info.Mode().Perm()!=0o600 { t.Fatalf("receipt not private: %+v %v",info,err) }
	code,_,_=checkedApplyCLIForTest(api,"apply","--receipt="+path)
	if code!=2 || api.applyCalls!=0 { t.Fatal("apply sent without explicit confirmation") }
	code,output,errOut=checkedApplyCLIForTest(api,"apply","--receipt="+path,"--confirm")
	if code!=0 || errOut!="" || api.applyCalls!=1 || api.statusCalls!=1 ||
		api.lastReceipt!=api.preview.Receipt ||
		!strings.Contains(output,`"core_checked": true`) ||
		!strings.Contains(output,`"readback_generation_id": 22`) ||
		strings.Contains(output,"PRIVATE_STATUS") {
		t.Fatalf("apply/readback unexpected: %d %q %q",code,output,errOut)
	}
	code,_,_=checkedApplyCLIForTest(api,"apply-preview","--out="+path)
	if code!=1 { t.Fatal("preview overwrote existing receipt") }
}

func TestCheckedApplyCLIRejectsUnsafeReceiptsWithoutMutation(t *testing.T) {
	for _,mode:=range []string{"world-readable","symlink","unknown-field","no-compiler","missing-native","extra-json"} {
		t.Run(mode,func(t *testing.T){
			api:=newCheckedApplyFake()
			path:=filepath.Join(t.TempDir(),"receipt.json")
			if code,_,stderr:=checkedApplyCLIForTest(api,"apply-preview","--out="+path);code!=0{
				t.Fatalf("fixture preview failed: %s",stderr)
			}
			switch mode {
			case "world-readable":
				if err:=os.Chmod(path,0o644);err!=nil{t.Fatal(err)}
			case "symlink":
				link:=path+".link"
				if err:=os.Symlink(path,link);err!=nil{t.Fatal(err)}
				path=link
			case "unknown-field":
				content,err:=os.ReadFile(path)
				if err!=nil{t.Fatal(err)}
				content=bytes.Replace(content,[]byte(`"applied": false`),[]byte(`"applied": false, "SECRET_FIELD": "private"`),1)
				if err:=os.WriteFile(path,content,0o600);err!=nil{t.Fatal(err)}
			case "no-compiler":
				content,err:=os.ReadFile(path)
				if err!=nil{t.Fatal(err)}
				content=bytes.Replace(content,[]byte(`"compiler_validated": true`),[]byte(`"compiler_validated": false`),1)
				if err:=os.WriteFile(path,content,0o600);err!=nil{t.Fatal(err)}
			case "missing-native":
				content,err:=os.ReadFile(path)
				if err!=nil{t.Fatal(err)}
				content=bytes.Replace(content,[]byte(strings.Repeat("b",64)),[]byte("BAD"),1)
				if err:=os.WriteFile(path,content,0o600);err!=nil{t.Fatal(err)}
			case "extra-json":
				file,err:=os.OpenFile(path,os.O_APPEND|os.O_WRONLY,0o600)
				if err!=nil{t.Fatal(err)}
				_,err=file.WriteString("{}")
				_ = file.Close()
				if err!=nil{t.Fatal(err)}
			}
			code,stdout,_:=checkedApplyCLIForTest(api,"apply","--receipt="+path,"--confirm")
			if code!=2 || stdout!="" || api.applyCalls!=0 {
				t.Fatalf("invalid %s receipt caused apply: code=%d output=%s",mode,code,stdout)
			}
		})
	}
}

func TestCheckedApplyCLIRejectsMissingOrFalseConfirmationAndExtraArgs(t *testing.T) {
	api:=newCheckedApplyFake()
	invalid:=[][]string{
		{"apply"},{"apply","--receipt=xx"},{"apply","--receipt=xx","--confirm=false"},
		{"apply","--receipt=xx","--confirm","extra"},
		{"apply-preview","--out="},{"apply-preview","extra"},
	}
	for _,args:=range invalid {
		code,output,_:=checkedApplyCLIForTest(api,args...)
		if code!=2 || output!="" { t.Fatalf("invalid %v accepted: %d %q",args,code,output) }
	}
	if api.applyCalls!=0 || api.previewCalls!=0 { t.Fatal("invalid args performed I/O") }
}

func TestCheckedApplyCLIUncertainErrorsNeverRetryAndNeverExposeSecrets(t *testing.T) {
	api:=newCheckedApplyFake()
	path:=filepath.Join(t.TempDir(),"receipt.json")
	if code,_,_:=checkedApplyCLIForTest(api,"apply-preview","--out="+path);code!=0{t.Fatal("fixture failed")}
	api.applyError=errors.New("daemon HTTP 502 password=VERY_PRIVATE")
	code,output,errOut:=checkedApplyCLIForTest(api,"apply","--receipt="+path,"--confirm")
	if code!=1 || output!="" || api.applyCalls!=1 || api.statusCalls!=0 ||
		!strings.Contains(errOut,"NEVER auto-retry") ||
		strings.Contains(errOut,"VERY_PRIVATE") {
		t.Fatalf("ambiguous apply not safe: %d %s %s",code,output,errOut)
	}
	api.applyError=nil
	api.statusError=errors.New("daemon disconnected with key=SECRET_STATUS")
	code,output,errOut=checkedApplyCLIForTest(api,"apply","--receipt="+path,"--confirm")
	if code!=1 || output!="" || api.applyCalls!=2 || api.statusCalls!=1 ||
		strings.Contains(errOut,"SECRET_STATUS") {
		t.Fatalf("ambiguous readback not safe: %d %s %s",code,output,errOut)
	}
}

func TestCheckedApplyCLIRefusesInvalidAcknowledgementOrMismatchedGeneration(t *testing.T) {
	for _,mode:=range []string{"digest","core-unverified","readback","recovery"} {
		t.Run(mode,func(t *testing.T){
			api:=newCheckedApplyFake()
			path:=filepath.Join(t.TempDir(),"receipt.json")
			if code,_,_:=checkedApplyCLIForTest(api,"apply-preview","--out="+path);code!=0{t.Fatal("fixture")}
			switch mode {
			case "digest":api.apply.ConfigSHA256=strings.Repeat("9",64)
			case "core-unverified":api.apply.Verified=false
			case "readback":v:=int64(33);api.status.AppliedGenerationID=&v
			case "recovery":api.status.RecoveryRequired=true
			}
			code,out,_:=checkedApplyCLIForTest(api,"apply","--receipt="+path,"--confirm")
			if code!=1 || out!="" || api.applyCalls!=1 || api.statusCalls>1 {
				t.Fatalf("invalid %s acknowledge accepted: code=%d out=%s",mode,code,out)
			}
		})
	}
}
