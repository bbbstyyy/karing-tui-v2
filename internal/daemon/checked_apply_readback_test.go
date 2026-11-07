//go:build linux

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type readbackMutationStore struct {
	checkedApplyReadbackStore
	changeState     func(*storage.Snapshot)
	changeAttempt   func(*storage.Attempt)
	changeArtifacts func(*storage.GenerationArtifacts)
}

func (s readbackMutationStore) Snapshot(ctx context.Context) (storage.Snapshot, error) {
	value, err := s.checkedApplyReadbackStore.Snapshot(ctx)
	if err == nil && s.changeState != nil {
		s.changeState(&value)
	}
	return value, err
}

func (s readbackMutationStore) Attempt(ctx context.Context, id int64) (storage.Attempt, error) {
	value, err := s.checkedApplyReadbackStore.Attempt(ctx, id)
	if err == nil && s.changeAttempt != nil {
		s.changeAttempt(&value)
	}
	return value, err
}

func (s readbackMutationStore) GenerationArtifacts(ctx context.Context, id int64) (storage.GenerationArtifacts, error) {
	value, err := s.checkedApplyReadbackStore.GenerationArtifacts(ctx, id)
	if err == nil && s.changeArtifacts != nil {
		s.changeArtifacts(&value)
	}
	return value, err
}

func TestCheckedApplyReadbackBindsVerifiedJournalAndGeneration(t *testing.T) {
	store, core, _, handler := checkedApplyHarness(t)
	defer store.Close()
	ctx := context.Background()
	preview := checkedPreviewTest(t, handler)
	applied := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", preview.Receipt)
	if applied.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", applied.Code, applied.Body.String())
	}
	var confirmed apiv1.CheckedApplyResponse
	if err := json.NewDecoder(applied.Body).Decode(&confirmed); err != nil {
		t.Fatal(err)
	}
	attempt, err := store.Attempt(ctx, confirmed.AttemptID)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCheckedApplyReadback(ctx, store, preview.Receipt, attempt); err != nil {
		t.Fatalf("committed readback rejected: %v", err)
	}
	cases := []struct {
		name   string
		change readbackMutationStore
	}{
		{"config revision", readbackMutationStore{changeState: func(s *storage.Snapshot) { s.Revision++ }}},
		{"applied pointer", readbackMutationStore{changeState: func(s *storage.Snapshot) { s.AppliedGenerationID = nil }}},
		{"LKG pointer", readbackMutationStore{changeState: func(s *storage.Snapshot) { s.LastKnownGoodGenerationID = nil }}},
		{"active journal", readbackMutationStore{changeState: func(s *storage.Snapshot) { id := int64(999); s.ActiveAttemptID = &id }}},
		{"recovery required", readbackMutationStore{changeState: func(s *storage.Snapshot) { s.RecoveryRequired = true }}},
		{"attempt phase", readbackMutationStore{changeAttempt: func(a *storage.Attempt) { a.Phase = storage.PhaseVerifying }}},
		{"attempt identity", readbackMutationStore{changeAttempt: func(a *storage.Attempt) { a.GenerationID++ }}},
		{"generation corruption", readbackMutationStore{changeArtifacts: func(a *storage.GenerationArtifacts) { a.ConfigJSON = []byte("{}") }}},
		{"source map corruption", readbackMutationStore{changeArtifacts: func(a *storage.GenerationArtifacts) { a.SourceMapJSON = []byte("{}") }}},
		{"manifest no longer bound", readbackMutationStore{changeArtifacts: func(a *storage.GenerationArtifacts) {
			var payload map[string]any
			if err := json.Unmarshal(a.ManifestJSON, &payload); err != nil {
				t.Fatal(err)
			}
			payload["declaration_revision"] = float64(999)
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			a.ManifestJSON = data
			sum := sha256.Sum256(data)
			a.ManifestSHA256 = hex.EncodeToString(sum[:])
		}}},
	}
	beforeCoreEvents := len(core.events)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.change
			mutated.checkedApplyReadbackStore = store
			if err := verifyCheckedApplyReadback(ctx, mutated, preview.Receipt, attempt); !errors.Is(err, ErrCheckedApplyReadbackUncertain) {
				t.Fatalf("readback corruption not rejected: %v", err)
			}
		})
	}
	if len(core.events) != beforeCoreEvents {
		t.Fatalf("readback unexpectedly re-invoked core: %v", core.events)
	}
}

func TestProfileAcceptedSnapshotStageToCheckedApplyWithDurableReadback(t *testing.T) {
	ctx := context.Background()
	store, snapshotID, revision, nodeID := previewFixture(t, true)
	defer store.Close()
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
	handler := New(runtimepath.Paths{}).handler(store, runtime)

	// The accepted local sing-box source is only a snapshot until the human
	// confirms the exact candidate and overlay digests.
	before, err := store.Snapshot(ctx)
	if err != nil || before.Revision != 0 || before.AppliedGenerationID != nil {
		t.Fatalf("unexpected original runtime state: %+v %v", before, err)
	}
	pre := routeEditCall(t, handler, http.MethodPost, "/v1/profiles/profile-a/declaration/preview",
		apiv1.ProfileDeclarationPreviewRequest{SnapshotID: snapshotID, ExpectedDeclarationRevision: revision})
	if pre.Code != http.StatusOK {
		t.Fatalf("profile preview=%d body=%s", pre.Code, pre.Body.String())
	}
	var profilePreview apiv1.ProfileDeclarationPreviewResponse
	if err := json.NewDecoder(pre.Body).Decode(&profilePreview); err != nil {
		t.Fatal(err)
	}
	if profilePreview.RetainedNodeCount != 1 || profilePreview.AddedNodeCount != 0 || len(profilePreview.CandidateSHA256) != 64 ||
		profilePreview.SourceRevision == 0 || profilePreview.CoreValidated || profilePreview.Applied ||
		strings.Contains(pre.Body.String(), "SUPER_PRIVATE_PASSWORD") {
		t.Fatalf("unsafe source declaration preview: %+v", profilePreview)
	}
	stageRequest := apiv1.ProfileDeclarationStageRequest{
		SnapshotID: snapshotID, ExpectedSourceRevision: profilePreview.SourceRevision,
		ExpectedDeclarationRevision: revision, CandidateSHA256: profilePreview.CandidateSHA256,
		RuntimeOverlaySHA256: profilePreview.RuntimeOverlaySHA256,
	}
	stage := routeEditCall(t, handler, http.MethodPost, "/v1/profiles/profile-a/declaration/stage", stageRequest)
	if stage.Code != http.StatusCreated {
		t.Fatalf("stage=%d body=%s", stage.Code, stage.Body.String())
	}
	var staged apiv1.ProfileDeclarationStageResponse
	if err := json.NewDecoder(stage.Body).Decode(&staged); err != nil {
		t.Fatal(err)
	}
	if staged.DeclarationRevision != revision+1 || staged.DeclarationSHA256 != profilePreview.CandidateSHA256 ||
		staged.Applied || staged.CoreValidated || len(core.events) != 0 {
		t.Fatalf("stage unexpectedly applied core: %+v, events=%v", staged, core.events)
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil || !strings.Contains(string(current.DocumentJSON), nodeID) {
		t.Fatalf("staged declaration did not materialize stable node ID: %+v %v", current, err)
	}
	afterStage, err := store.Snapshot(ctx)
	if err != nil || afterStage.Revision != 0 || afterStage.AppliedGenerationID != nil {
		t.Fatalf("stage changed runtime state: %+v %v", afterStage, err)
	}

	applyPreview := checkedPreviewTest(t, handler)
	if applyPreview.Receipt.DeclarationRevision != staged.DeclarationRevision ||
		applyPreview.Receipt.DeclarationSHA256 != staged.DeclarationSHA256 ||
		!applyPreview.CompilerValidated || applyPreview.CoreValidated || applyPreview.Applied {
		t.Fatalf("checked apply does not bind staged node declaration: %+v", applyPreview)
	}
	confirm := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", applyPreview.Receipt)
	if confirm.Code != http.StatusOK || strings.Contains(confirm.Body.String(), "SUPER_PRIVATE_PASSWORD") {
		t.Fatalf("confirmed apply=%d body=%s", confirm.Code, confirm.Body.String())
	}
	var applied apiv1.CheckedApplyResponse
	if err := json.NewDecoder(confirm.Body).Decode(&applied); err != nil {
		t.Fatal(err)
	}
	if !applied.CoreChecked || !applied.Verified || !applied.Applied ||
		applied.DeclarationRevision != staged.DeclarationRevision ||
		applied.ConfigSHA256 != applyPreview.Receipt.NativeConfigSHA256 ||
		strings.Join(core.events, ",") != "check,activate,verify" {
		t.Fatalf("staged->confirmed apply invalid: %+v, core=%v", applied, core.events)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil || snapshot.Revision != applied.TargetConfigRevision ||
		snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != applied.GenerationID ||
		snapshot.LastKnownGoodGenerationID == nil || *snapshot.LastKnownGoodGenerationID != applied.GenerationID ||
		snapshot.RecoveryRequired || snapshot.ActiveAttemptID != nil {
		t.Fatalf("checked apply did not persist LKG: %+v %v", snapshot, err)
	}
	artifacts, err := store.GenerationArtifacts(ctx, applied.GenerationID)
	if err != nil ||
		!strings.Contains(string(artifacts.ConfigJSON), `"server_port":9080`) ||
		!strings.Contains(string(artifacts.ConfigJSON), `"password":"SUPER_PRIVATE_PASSWORD"`) {
		t.Fatalf("confirmed generation did not include the imported selected node: %v", err)
	}
	if err := verifyCheckedApplyReadback(ctx, store, applyPreview.Receipt, storage.Attempt{
		ID: applied.AttemptID, GenerationID: applied.GenerationID,
		BaseRevision: applied.BaseConfigRevision, TargetRevision: applied.TargetConfigRevision,
		ConfigSHA256: applied.ConfigSHA256,
	}); err != nil {
		t.Fatalf("independent readback failed: %v", err)
	}
	replayed := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", applyPreview.Receipt)
	staleStage := routeEditCall(t, handler, http.MethodPost, "/v1/profiles/profile-a/declaration/stage", stageRequest)
	if replayed.Code != http.StatusConflict || staleStage.Code != http.StatusConflict || len(core.events) != 3 {
		t.Fatalf("replay mutated core: apply=%d stage=%d events=%v", replayed.Code, staleStage.Code, core.events)
	}
	still, err := store.Snapshot(ctx)
	if err != nil || still.AppliedGenerationID == nil || *still.AppliedGenerationID != applied.GenerationID {
		t.Fatalf("rejected replay disturbed LKG: %+v %v", still, err)
	}
}
