package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func checkedApplyHarness(t *testing.T) (*storage.Store, *fakeApplyCore, *serverRuntime, http.Handler) {
	t.Helper()
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	if _, err := store.CommitDeclaration(ctx, 0, declarationAPIMinimalDocument(), "test:checked-apply"); err != nil {
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
	core := &fakeApplyCore{}
	apply, err := NewApplyCoordinator(store, core, testApplyPolicy())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &serverRuntime{apply: apply, declarations: compilation, gate: NewOperationGate()}
	return store, core, runtime, New(runtimepath.Paths{}).handler(store, runtime)
}

func checkedPreviewTest(t *testing.T, handler http.Handler) apiv1.CheckedApplyPreviewResponse {
	t.Helper()
	response := routeEditCall(t, handler, http.MethodGet, "/v1/config/apply/preview", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", response.Code, response.Body.String())
	}
	var receipt apiv1.CheckedApplyPreviewResponse
	if err := json.NewDecoder(response.Body).Decode(&receipt); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func TestCheckedApplyPreviewConfirmRecheckAndNoReplay(t *testing.T) {
	store, core, _, handler := checkedApplyHarness(t)
	defer store.Close()
	ctx := context.Background()
	preview := checkedPreviewTest(t, handler)
	if preview.APIVersion != apiv1.Version || preview.Receipt.DeclarationRevision != 1 ||
		preview.Receipt.ExpectedConfigRevision != 0 || preview.Receipt.ExpectedAppliedGenerationID != nil ||
		preview.Receipt.ExpectedSelectionRevision != 0 ||
		!validRouteEditSHA(preview.Receipt.DeclarationSHA256) ||
		!validRouteEditSHA(preview.Receipt.NativeConfigSHA256) ||
		preview.NativeSchemaID == "" || preview.RouteEntryCount < 1 ||
		!preview.CompilerValidated || preview.CoreValidated || preview.Applied ||
		len(core.events) != 0 {
		t.Fatalf("unsafe or unexpected preview: %+v, core=%v", preview, core.events)
	}
	snapshot, _ := store.Snapshot(ctx)
	if snapshot.AppliedGenerationID != nil || snapshot.Revision != 0 || snapshot.ActiveAttemptID != nil {
		t.Fatalf("preview mutated core state: %+v", snapshot)
	}
	response := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", preview.Receipt)
	if response.Code != http.StatusOK {
		t.Fatalf("confirmed apply status=%d body=%s", response.Code, response.Body.String())
	}
	var applied apiv1.CheckedApplyResponse
	if err := json.NewDecoder(response.Body).Decode(&applied); err != nil {
		t.Fatal(err)
	}
	if !applied.CoreChecked || !applied.Verified || !applied.Applied ||
		applied.DeclarationRevision != preview.Receipt.DeclarationRevision ||
		applied.DeclarationSHA256 != preview.Receipt.DeclarationSHA256 ||
		applied.ConfigSHA256 != preview.Receipt.NativeConfigSHA256 ||
		applied.NativeSchemaID != preview.NativeSchemaID ||
		applied.GenerationID <= 0 || applied.AttemptID <= 0 ||
		applied.BaseConfigRevision != 0 || applied.TargetConfigRevision != 1 ||
		strings.Join(core.events, ",") != "check,activate,verify" {
		t.Fatalf("incorrect confirmed apply: %+v events=%v", applied, core.events)
	}
	snapshot, _ = store.Snapshot(ctx)
	if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil ||
		*snapshot.AppliedGenerationID != applied.GenerationID ||
		snapshot.LastKnownGoodGenerationID == nil || *snapshot.LastKnownGoodGenerationID != applied.GenerationID {
		t.Fatalf("durable generation not committed: %+v", snapshot)
	}
	artifacts, err := store.GenerationArtifacts(ctx, applied.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(artifacts.ManifestJSON), preview.Receipt.DeclarationSHA256) ||
		!strings.Contains(string(artifacts.ManifestJSON), preview.Receipt.NativeConfigSHA256) {
		t.Fatal("persisted generation lacks preview provenance")
	}
	replayed := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", preview.Receipt)
	if replayed.Code != http.StatusConflict || len(core.events) != 3 {
		t.Fatalf("stale receipt reapplied: %d events=%v", replayed.Code, core.events)
	}
	if again := routeEditCall(t, handler, http.MethodGet, "/v1/config/apply/preview", nil); again.Code != http.StatusConflict {
		t.Fatalf("already-applied head offered again: %d", again.Code)
	}
}

func TestCheckedApplyRejectsDriftAndInvalidReceiptsWithoutCoreIO(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(context.Context, *storage.Store, *serverRuntime, *apiv1.CheckedApplyReceipt) error
		want   int
	}{
		{"declaration race", func(ctx context.Context, s *storage.Store, _ *serverRuntime, _ *apiv1.CheckedApplyReceipt) error {
			head, err := s.CurrentDeclaration(ctx)
			if err != nil {
				return err
			}
			_, err = s.CommitDeclaration(ctx, head.Revision, head.DocumentJSON, "test:concurrent")
			return err
		}, http.StatusConflict},
		{"selection race", func(ctx context.Context, s *storage.Store, _ *serverRuntime, _ *apiv1.CheckedApplyReceipt) error {
			_, err := s.SetCurrentSelectionIntent(ctx, []byte("{\"kind\":\"specific_node\",\"profile_id\":\"p1\",\"node_id\":\"n1\"}"))
			return err
		}, http.StatusConflict},
		{"config and generation race", func(ctx context.Context, _ *storage.Store, r *serverRuntime, _ *apiv1.CheckedApplyReceipt) error {
			_, _, err := r.ApplyDeclarationRevision(ctx, 1, 0)
			return err
		}, http.StatusConflict},
		{"native digest mismatch", func(_ context.Context, _ *storage.Store, _ *serverRuntime, receipt *apiv1.CheckedApplyReceipt) error {
			receipt.NativeConfigSHA256 = strings.Repeat("f", 64)
			return nil
		}, http.StatusConflict},
		{"malformed digest", func(_ context.Context, _ *storage.Store, _ *serverRuntime, receipt *apiv1.CheckedApplyReceipt) error {
			receipt.NativeConfigSHA256 = "INVALID"
			return nil
		}, http.StatusUnprocessableEntity},
		{"generation pointer mismatch", func(_ context.Context, _ *storage.Store, _ *serverRuntime, receipt *apiv1.CheckedApplyReceipt) error {
			id := int64(10)
			receipt.ExpectedAppliedGenerationID = &id
			return nil
		}, http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store, core, runtime, handler := checkedApplyHarness(t)
			defer store.Close()
			receipt := checkedPreviewTest(t, handler).Receipt
			ctx := context.Background()
			if err := tc.mutate(ctx, store, runtime, &receipt); err != nil {
				t.Fatal(err)
			}
			before := len(core.events)
			result := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", receipt)
			if result.Code != tc.want || len(core.events) != before {
				t.Fatalf("unsafe confirmation status=%d want=%d events=%v body=%s", result.Code, tc.want, core.events, result.Body.String())
			}
		})
	}
}

func TestCheckedApplyCandidateVerificationFailureUsesRollbackAndSanitizedHTTP(t *testing.T) {
	store, core, _, handler := checkedApplyHarness(t)
	defer store.Close()
	ctx := context.Background()
	first := checkedPreviewTest(t, handler)
	if rec := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", first.Receipt); rec.Code != http.StatusOK {
		t.Fatalf("seed apply failed: %d", rec.Code)
	}
	base, _ := store.Snapshot(ctx)
	head, err := store.CurrentDeclaration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.CommitDeclaration(ctx, head.Revision, head.DocumentJSON, "test:second-stage"); err != nil {
		t.Fatal(err)
	}
	next := checkedPreviewTest(t, handler)
	core.events = nil
	core.verifyErr = errors.New("core upstream error password=DO_NOT_EXPOSE")
	result := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", next.Receipt)
	if result.Code != http.StatusBadGateway || strings.Contains(result.Body.String(), "DO_NOT_EXPOSE") ||
		strings.Join(core.events, ",") != "check,activate,verify,rollback" {
		t.Fatalf("failure not sanitized or rolled back: status=%d events=%v body=%s", result.Code, core.events, result.Body.String())
	}
	now, _ := store.Snapshot(ctx)
	if now.Revision != base.Revision || now.AppliedGenerationID == nil ||
		base.AppliedGenerationID == nil || *now.AppliedGenerationID != *base.AppliedGenerationID ||
		now.RecoveryRequired || now.ActiveAttemptID != nil ||
		len(core.rollbacks) != 1 || core.rollbacks[0] == nil || core.rollbacks[0].ID != *base.AppliedGenerationID {
		t.Fatalf("failed verification changed prior applied generation: %+v", now)
	}
}

func TestCheckedApplyRejectsUnknownAndOversizedRequestsAndMissingRuntime(t *testing.T) {
	store, _, _, handler := checkedApplyHarness(t)
	defer store.Close()
	for _, bad := range []string{
		"{\"unexpected\":true}",
		"{\"native_config_sha256\":\"" + strings.Repeat("A", 4096) + "\"}",
		"{}{}",
	} {
		result := httptest.NewRecorder()
		handler.ServeHTTP(result, httptest.NewRequest(http.MethodPost, "/v1/config/apply/confirm", strings.NewReader(bad)))
		if result.Code != http.StatusBadRequest {
			t.Fatalf("invalid JSON accepted: %d, body=%s", result.Code, result.Body.String())
		}
	}
	nilHandler := New(runtimepath.Paths{}).handler(store, nil)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		endpoint := "/v1/config/apply/preview"
		if method == http.MethodPost {
			endpoint = "/v1/config/apply/confirm"
		}
		if result := routeEditCall(t, nilHandler, method, endpoint, nil); result.Code != http.StatusServiceUnavailable {
			t.Fatalf("no runtime accepted %s: %d", method, result.Code)
		}
	}
}

func TestCheckedApplyCapabilityAdvertisedOnlyWithRuntime(t *testing.T) {
	store, _, _, handler := checkedApplyHarness(t)
	defer store.Close()
	inspect := func(h http.Handler) bool {
		rec := routeEditCall(t, h, http.MethodGet, "/v1/capabilities", nil)
		if rec.Code != http.StatusOK { t.Fatalf("capabilities: %d", rec.Code) }
		var caps apiv1.CapabilitiesResponse
		if err := json.NewDecoder(rec.Body).Decode(&caps); err != nil { t.Fatal(err) }
		return caps.Capabilities["checked_declaration_apply_api"]
	}
	if !inspect(handler) || inspect(New(runtimepath.Paths{}).handler(store, nil)) {
		t.Fatal("checked apply advertised without compiler, core or gate")
	}
}
