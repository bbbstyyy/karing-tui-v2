package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func routeEditHandler(t *testing.T) (*storage.Store, http.Handler) {
	t.Helper()
	store := openServerTestStore(t, context.Background())
	if _, err := store.CommitDeclaration(context.Background(), 0,
		currentSelectionTestDeclaration(), "test:route-edit"); err != nil {
		t.Fatal(err)
	}
	engine, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       domain.DefaultInboundSet(),
		ControlAddress: netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:  declarationAPITestSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	compilation, err := NewDeclarationCompileCoordinator(store, engine)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &serverRuntime{declarations: compilation, gate: NewOperationGate()}
	return store, New(runtimepath.Paths{}).handler(store, runtime)
}

func routeEditCall(t *testing.T, handler http.Handler, method, route string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var input []byte
	if body != nil {
		var err error
		input, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(method, route, bytes.NewReader(input)))
	return rec
}

func routeEditContextForTest(t *testing.T, handler http.Handler) apiv1.RouteEditContext {
	t.Helper()
	rec := routeEditCall(t, handler, http.MethodGet, "/v1/config/route-edit/context", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET context %d: %s", rec.Code, rec.Body.String())
	}
	var v apiv1.RouteEditContext
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func routeEditTestRequest(ctx apiv1.RouteEditContext) apiv1.RouteEditRequest {
	target := domain.TargetRef{Kind: domain.TargetDirect}
	return apiv1.RouteEditRequest{
		ExpectedDeclarationRevision: ctx.DeclarationRevision,
		ExpectedDeclarationSHA256:   ctx.DeclarationSHA256,
		ExpectedConfigRevision:      ctx.ConfigRevision,
		ExpectedGenerationID:        ctx.AppliedGenerationID,
		ExpectedSelectionRevision:   ctx.SelectionRevision,
		Layer:                       domain.LayerFinal, GroupID: "FINAL", Target: &target,
	}
}

func previewRouteEditTest(t *testing.T, h http.Handler, req apiv1.RouteEditRequest) apiv1.RouteEditPreviewResponse {
	t.Helper()
	rec := routeEditCall(t, h, http.MethodPost, "/v1/config/route-edit/preview", req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview %d: %s", rec.Code, rec.Body.String())
	}
	var p apiv1.RouteEditPreviewResponse
	if err := json.NewDecoder(rec.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	return p
}

func stageRouteEditTest(t *testing.T, h http.Handler, preview apiv1.RouteEditPreviewResponse) *httptest.ResponseRecorder {
	t.Helper()
	return routeEditCall(t, h, http.MethodPost, "/v1/config/route-edit/stage", apiv1.RouteEditStageRequest{
		RouteEditRequest:   preview.Request,
		CandidateSHA256:    preview.CandidateSHA256,
		NativeConfigSHA256: preview.NativeConfigSHA256,
	})
}

func TestRouteEditPreviewStageRequiresTwoDigestsAndNeverApplies(t *testing.T) {
	store, handler := routeEditHandler(t)
	defer store.Close()
	ctx := routeEditContextForTest(t, handler)
	if ctx.DeclarationRevision != 1 || ctx.ConfigRevision != 0 ||
		ctx.AppliedGenerationID != nil || ctx.SelectionRevision != 0 || !validRouteEditSHA(ctx.DeclarationSHA256) {
		t.Fatalf("bad initial context: %+v", ctx)
	}
	request := routeEditTestRequest(ctx)
	preview := previewRouteEditTest(t, handler, request)
	if preview.APIVersion != "v1" || preview.Origin != "declaration" ||
		preview.BeforeTarget.Kind != domain.TargetCurrentSelected ||
		preview.AfterTarget.Kind != domain.TargetDirect ||
		!validRouteEditSHA(preview.CandidateSHA256) ||
		!validRouteEditSHA(preview.NativeConfigSHA256) ||
		preview.CandidateSHA256 == ctx.DeclarationSHA256 ||
		preview.NativeSchemaID == "" ||
		!preview.CompilerValidated || preview.CoreValidated || preview.Staged || preview.Applied {
		t.Fatalf("unexpected preflight receipt: %+v", preview)
	}
	current, _ := store.CurrentDeclaration(context.Background())
	if current.Revision != 1 {
		t.Fatalf("preview committed revision %d", current.Revision)
	}
	snap, _ := store.Snapshot(context.Background())
	if snap.Revision != 0 || snap.AppliedGenerationID != nil {
		t.Fatalf("preview changed runtime: %+v", snap)
	}
	rec := stageRouteEditTest(t, handler, preview)
	if rec.Code != http.StatusCreated {
		t.Fatalf("stage %d: %s", rec.Code, rec.Body.String())
	}
	var staged apiv1.RouteEditStageResponse
	if err := json.NewDecoder(rec.Body).Decode(&staged); err != nil {
		t.Fatal(err)
	}
	if staged.DeclarationRevision != 2 || staged.DeclarationSHA256 != preview.CandidateSHA256 ||
		staged.NativeConfigSHA256 != preview.NativeConfigSHA256 ||
		!staged.CompilerValidated || staged.CoreValidated || !staged.Staged || staged.Applied {
		t.Fatalf("unexpected stage result: %+v", staged)
	}
	current, _ = store.CurrentDeclaration(context.Background())
	if current.Revision != 2 || current.SHA256 != preview.CandidateSHA256 ||
		!bytes.Contains(current.DocumentJSON, []byte(`"kind":"direct"`)) {
		t.Fatalf("stage didn't preserve immutable candidate: %+v", current)
	}
	snap, _ = store.Snapshot(context.Background())
	if snap.Revision != 0 || snap.AppliedGenerationID != nil {
		t.Fatalf("stage applied or restarted core: %+v", snap)
	}
	if rec := stageRouteEditTest(t, handler, preview); rec.Code != http.StatusConflict {
		t.Fatalf("stale second confirmation = %d", rec.Code)
	}
}

func TestRouteEditStageRejectsDigestMismatchAndConcurrentChanges(t *testing.T) {
	store, handler := routeEditHandler(t)
	defer store.Close()
	ctx := routeEditContextForTest(t, handler)
	receipt := previewRouteEditTest(t, handler, routeEditTestRequest(ctx))
	bad := apiv1.RouteEditStageRequest{
		RouteEditRequest:   receipt.Request,
		CandidateSHA256:    strings.Repeat("a", 64),
		NativeConfigSHA256: receipt.NativeConfigSHA256,
	}
	if rec := routeEditCall(t, handler, http.MethodPost, "/v1/config/route-edit/stage", bad); rec.Code != http.StatusConflict {
		t.Fatalf("bad digest accepted: %d %s", rec.Code, rec.Body.String())
	}
	before, _ := store.CurrentDeclaration(context.Background())
	if before.Revision != 1 {
		t.Fatal("digest mismatch committed")
	}
	// A CurrentSelected switch invalidates a pending route/DNS preview.
	target := []byte(`{"kind":"specific_node","profile_id":"profile-a","node_id":"node-b"}`)
	if _, err := store.SetCurrentSelectionIntent(context.Background(), target); err != nil {
		t.Fatal(err)
	}
	if rec := stageRouteEditTest(t, handler, receipt); rec.Code != http.StatusConflict {
		t.Fatalf("selection race failed open: %d %s", rec.Code, rec.Body.String())
	}
	receipt = previewRouteEditTest(t, handler, routeEditTestRequest(routeEditContextForTest(t, handler)))
	// Even a legacy unconditional declaration commit must invalidate the CAS.
	old, _ := store.CurrentDeclaration(context.Background())
	if _, err := store.CommitDeclaration(context.Background(), old.Revision, old.DocumentJSON, "test:legacy-race"); err != nil {
		t.Fatal(err)
	}
	if rec := stageRouteEditTest(t, handler, receipt); rec.Code != http.StatusConflict {
		t.Fatalf("legacy declaration edit was overwritten: %d", rec.Code)
	}
	next, _ := store.CurrentDeclaration(context.Background())
	if next.Revision != 2 {
		t.Fatalf("unexpected latest revision: %d", next.Revision)
	}
}

func TestRouteEditStagingHasOnlyOneWinner(t *testing.T) {
	store, handler := routeEditHandler(t)
	defer store.Close()
	receipt := previewRouteEditTest(t, handler, routeEditTestRequest(routeEditContextForTest(t, handler)))
	const workers = 6
	results := make(chan int, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			b, _ := json.Marshal(apiv1.RouteEditStageRequest{
				RouteEditRequest:   receipt.Request,
				CandidateSHA256:    receipt.CandidateSHA256,
				NativeConfigSHA256: receipt.NativeConfigSHA256,
			})
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/config/route-edit/stage", bytes.NewReader(b)))
			results <- rec.Code
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	ok, conflicts := 0, 0
	for status := range results {
		switch status {
		case http.StatusCreated:
			ok++
		case http.StatusConflict:
			conflicts++
		default:
			t.Fatalf("unexpected concurrent status %d", status)
		}
	}
	if ok != 1 || conflicts != workers-1 {
		t.Fatalf("CAS writers: winner=%d conflicts=%d", ok, conflicts)
	}
	latest, _ := store.CurrentDeclaration(context.Background())
	if latest.Revision != 2 {
		t.Fatalf("concurrent confirmation advanced head to %d", latest.Revision)
	}
}

func TestRouteEditRejectsUnsafeOperationsAndLeakyErrors(t *testing.T) {
	store, handler := routeEditHandler(t)
	defer store.Close()
	ctx := routeEditContextForTest(t, handler)
	good := routeEditTestRequest(ctx)
	for name, modify := range map[string]func(*apiv1.RouteEditRequest){
		"unsupported ISP layer":    func(r *apiv1.RouteEditRequest) { r.Layer = "isp" },
		"unknown group":            func(r *apiv1.RouteEditRequest) { r.GroupID = "https://u:pass@bad.test?token=TOP_SECRET" },
		"two edits":                func(r *apiv1.RouteEditRequest) { disabled := false; r.Enabled = &disabled },
		"no change":                func(r *apiv1.RouteEditRequest) { r.Target = &domain.TargetRef{Kind: domain.TargetCurrentSelected} },
		"wrong config revision":    func(r *apiv1.RouteEditRequest) { r.ExpectedConfigRevision++ },
		"wrong selection revision": func(r *apiv1.RouteEditRequest) { r.ExpectedSelectionRevision++ },
		"wrong declaration SHA":    func(r *apiv1.RouteEditRequest) { r.ExpectedDeclarationSHA256 = strings.Repeat("f", 64) },
	} {
		r := good
		modify(&r)
		rec := routeEditCall(t, handler, http.MethodPost, "/v1/config/route-edit/preview", r)
		if rec.Code != http.StatusConflict && rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s: status=%d %s", name, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "TOP_SECRET") || strings.Contains(rec.Body.String(), "pass@") {
			t.Errorf("%s: leaked sensitive request content", name)
		}
	}
	current, _ := store.CurrentDeclaration(context.Background())
	if current.Revision != 1 {
		t.Fatal("invalid route edits wrote state")
	}
	// The bare server has no strict compiler; safe edits are unavailable.
	h := New(runtimepath.Paths{}).handler(store, nil)
	if rec := routeEditCall(t, h, http.MethodPost, "/v1/config/route-edit/preview", good); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing compiler preview status %d", rec.Code)
	}
}
