//go:build integration && linux

package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

// MVP-1C: real pinned core, all network services confined to 127.0.0.1.
// Uses guarded public first-run preview/stage rather than test-only
// declaration seeding. This is a real imported-node proof, NOT CN or MVP
// acceptance: the explicitly acknowledged mode is proxy-only without CN.
func TestManagedCoreRealMVPImportedHTTPFlow(t *testing.T) {
	assertOrdinaryUserCoreEnvironment(t)
	corePath := os.Getenv("KARING_TUI_TEST_CORE")
	if corePath == "" {
		t.Skip("KARING_TUI_TEST_CORE is not set")
	}
	const (
		profileID = "mvp-http-profile"
		sourceKey = "edge-http"
		secret    = "MVP_HTTP_SECRET_NEVER_IN_API"
	)
	target, targetHits, closeTarget := startRouteOutcomeTarget(t)
	defer closeTarget()
	proxy, proxyHits, closeProxy := startMVPForwardingHTTPProxy(t, target, "mvp-user", secret)
	defer closeProxy()
	updatedProxy, updatedProxyHits, closeUpdatedProxy := startMVPForwardingHTTPProxy(t, target, "mvp-user", secret)
	defer closeUpdatedProxy()

	var switched, broken atomic.Bool
	sourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		proxyPort := proxy.Port()
		if switched.Load() {
			proxyPort = updatedProxy.Port()
		}
		if broken.Load() {
			// Existing HTTP node has no supported TLS field. A malformed
			// refresh must never advance snapshot, declaration or LKG.
			_, _ = io.WriteString(w, fmt.Sprintf(`{"outbounds":[{"type":"http","tag":%q,"server":"127.0.0.1","server_port":%d,"tls":{"enabled":true}}]}`, sourceKey, proxyPort))
			return
		}
		_, _ = io.WriteString(w, fmt.Sprintf(`{
			"outbounds":[{"type":"http","tag":%q,"server":"127.0.0.1","server_port":%d,"username":"mvp-user","password":%q}],
			"route":{"rules":[{"domain_suffix":["untrusted-mvp-rule.invalid"],"outbound":"direct"}],"final":"direct"}
		}`, sourceKey, proxyPort, secret))
	}))
	defer sourceServer.Close()

	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ports := reserveLoopbackPorts(t, 4)
	inbounds := domain.InboundSet{
		Listen:   netip.MustParseAddr("127.0.0.1"),
		RulePort: ports[0], DirectPort: ports[1], SelectedPort: ports[2],
	}
	const controlSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	policy := core.DefaultPolicy()
	policy.ReadyTimeout = 5 * time.Second
	policy.StopTimeout = 3 * time.Second
	policy.InitialBackoff = 50 * time.Millisecond
	policy.MaxBackoff = 200 * time.Millisecond
	managed, err := NewManagedCore(store, ManagedCoreOptions{
		Executable: corePath, StateRoot: filepath.Join(stateDir, "core"),
		ControlEndpoint: fmt.Sprintf("http://127.0.0.1:%d", ports[3]),
		ControlSecret:   controlSecret, Inbounds: inbounds, Policy: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       inbounds,
		ControlAddress: netip.AddrPortFrom(inbounds.Listen, ports[3]),
		ControlSecret:  controlSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := NewDeclarationCompileCoordinator(store, compiler)
	if err != nil {
		t.Fatal(err)
	}
	runtime, done, cancel, err := startServerRuntimeWithDeclarations(context.Background(), store, managed, declarations)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("supervisor shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("supervisor shutdown timed out")
		}
	}()
	api := httptest.NewServer(New(runtimepath.Paths{}).handler(store, runtime))
	defer api.Close()

	source := apiv1.ProfileSourceSpec{
		Format: "sing-box", LocationKind: "url", Location: sourceServer.URL,
		Enabled: true, Fetch: apiv1.ProfileSourceFetchPolicy{Mode: "direct"},
	}
	status, response := mvpJSONRequest(t, api.URL, http.MethodPut, "/v1/profiles/"+profileID,
		apiv1.ProfileSourcePutRequest{Source: source})
	if status != http.StatusOK {
		t.Fatalf("put source status=%d body=%s", status, response)
	}
	var created apiv1.ProfileSourceResponse
	if err := json.Unmarshal(response, &created); err != nil {
		t.Fatal(err)
	}
	status, response = mvpJSONRequest(t, api.URL, http.MethodPost, "/v1/profiles/"+profileID+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusOK || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("source refresh status=%d response unsafe or rejected", status)
	}
	var refreshed apiv1.ProfileRefreshResponse
	if err := json.Unmarshal(response, &refreshed); err != nil {
		t.Fatal(err)
	}
	if refreshed.NodeCount != 1 || refreshed.CurrentSnapshotID == nil {
		t.Fatalf("imported snapshot not accepted: %+v", refreshed)
	}
	ignoredRule := false
	for _, d := range refreshed.Diagnostics {
		if d.Path == "route" && d.Code == "ignored_by_product_policy" {
			ignoredRule = true
		}
	}
	if !ignoredRule {
		t.Fatalf("subscription route was not explicitly reported as ignored: %+v", refreshed.Diagnostics)
	}
	nodeID, err := profile.StableNodeID(profileID, sourceKey)
	if err != nil {
		t.Fatal(err)
	}
	status, response = mvpJSONRequest(t, api.URL, http.MethodGet, "/v1/profiles/"+profileID+"/nodes", nil)
	var page apiv1.ProfileNodeListResponse
	if err := json.Unmarshal(response, &page); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || page.Total != 1 || len(page.Nodes) != 1 || page.Nodes[0].NodeID != nodeID {
		t.Fatalf("imported stable node not listed: %d %+v", status, page)
	}

	// The first-run source is initialized through the guarded public API,
	// not by writing a synthetic V1 declaration directly into SQLite.
	initRequest := apiv1.InitialProfileDeclarationPreviewRequest{
		SnapshotID:      *refreshed.CurrentSnapshotID,
		SelectedNodeID:  nodeID,
		ResolverAddress: "127.0.0.1:9",
	}
	status, response = mvpJSONRequest(t, api.URL, http.MethodPost,
		"/v1/profiles/"+profileID+"/declaration/initial/preview", initRequest)
	if status != http.StatusOK || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("initial declaration preview status=%d or leaked credentials", status)
	}
	var preview apiv1.InitialProfileDeclarationPreviewResponse
	if err := json.Unmarshal(response, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.SourceRevision != created.Revision ||
		preview.BaseDeclarationRevision != 0 ||
		preview.SelectedNodeID != nodeID ||
		preview.EffectiveNodeCount != 1 ||
		preview.CNRulesReady || preview.CoreValidated || preview.Applied ||
		len(preview.CandidateSHA256) != 64 || len(preview.RuntimeOverlaySHA256) != 64 {
		t.Fatalf("unsafe first-run source preview: %+v", preview)
	}
	stageReceipt := apiv1.InitialProfileDeclarationStageRequest{
		SnapshotID:               *refreshed.CurrentSnapshotID,
		ExpectedSourceRevision:   preview.SourceRevision,
		SelectedNodeID:           nodeID,
		ResolverAddress:          initRequest.ResolverAddress,
		CandidateSHA256:          preview.CandidateSHA256,
		RuntimeOverlaySHA256:     preview.RuntimeOverlaySHA256,
		AcknowledgeProxyOnlyNoCN: true,
	}
	status, response = mvpJSONRequest(t, api.URL, http.MethodPost,
		"/v1/profiles/"+profileID+"/declaration/initial/stage", stageReceipt)
	if status != http.StatusCreated || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("initial declaration stage status=%d or leaked credentials", status)
	}
	var staged apiv1.InitialProfileDeclarationStageResponse
	if err := json.Unmarshal(response, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.DeclarationRevision != 1 ||
		staged.DeclarationSHA256 != preview.CandidateSHA256 ||
		staged.Applied || staged.CoreValidated || staged.CNRulesReady {
		t.Fatalf("imported source not bound to initial declaration: %+v", staged)
	}
	status, response = mvpJSONRequest(t, api.URL, http.MethodGet, "/v1/config/apply/preview", nil)
	if status != http.StatusOK || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("apply preview status=%d or leaked credentials", status)
	}
	var applyPreview apiv1.CheckedApplyPreviewResponse
	if err := json.Unmarshal(response, &applyPreview); err != nil {
		t.Fatal(err)
	}
	if applyPreview.Receipt.DeclarationRevision != staged.DeclarationRevision ||
		applyPreview.Receipt.DeclarationSHA256 != staged.DeclarationSHA256 ||
		!applyPreview.CompilerValidated || applyPreview.CoreValidated || applyPreview.Applied {
		t.Fatalf("checked apply preview not bound to staged revision: %+v", applyPreview)
	}
	status, response = mvpJSONRequest(t, api.URL, http.MethodPost, "/v1/config/apply/confirm", applyPreview.Receipt)
	if status != http.StatusOK || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("real-core apply failed or leaked credentials: status=%d stderr=%s", status, managed.StderrTail())
	}
	var applied apiv1.CheckedApplyResponse
	if err := json.Unmarshal(response, &applied); err != nil {
		t.Fatal(err)
	}
	if !applied.CoreChecked || !applied.Verified || !applied.Applied ||
		applied.DeclarationRevision != staged.DeclarationRevision ||
		applied.ConfigSHA256 != applyPreview.Receipt.NativeConfigSHA256 {
		t.Fatalf("real core was not checked and applied: %+v", applied)
	}
	artifacts, err := store.GenerationArtifacts(ctx, applied.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(artifacts.ConfigJSON, []byte(secret)) ||
		bytes.Contains(artifacts.ConfigJSON, []byte("untrusted-mvp-rule.invalid")) {
		t.Fatal("applied generation omitted imported authentication or injected subscription routing")
	}
	appliedState, err := store.Snapshot(ctx)
	if err != nil || appliedState.AppliedGenerationID == nil ||
		*appliedState.AppliedGenerationID != applied.GenerationID ||
		appliedState.LastKnownGoodGenerationID == nil ||
		*appliedState.LastKnownGoodGenerationID != applied.GenerationID {
		t.Fatalf("real Core apply did not persist confirmed LKG: %+v %v", appliedState, err)
	}
	startCtx, stopStart := context.WithTimeout(ctx, 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		stopStart()
		t.Fatalf("start imported Core generation: %v; stderr=%s", err, managed.StderrTail())
	}
	stopStart()
	running := waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})

	// Exercise a protected user selection API instead of setting a fake
	// in-memory selector. This must bind to the applied declaration.
	status, response = mvpJSONRequest(t, api.URL, http.MethodGet, "/v1/selection/current", nil)
	if status != http.StatusOK {
		t.Fatalf("selection readback status=%d", status)
	}
	var selection apiv1.CurrentSelectionResponse
	if err := json.Unmarshal(response, &selection); err != nil {
		t.Fatal(err)
	}
	selectedTarget := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: profileID, NodeID: nodeID}
	status, response = mvpJSONRequest(t, api.URL, http.MethodPut, "/v1/selection/current/checked",
		apiv1.CurrentSelectionCheckedRequest{
			Target:                      selectedTarget,
			ExpectedSelectionRevision:   selection.SelectionRevision,
			ExpectedConfigRevision:      selection.ConfigRevision,
			ExpectedGenerationID:        selection.AppliedGenerationID,
			ExpectedDeclarationRevision: selection.DeclarationRevision,
			ExpectedDeclarationSHA256:   selection.DeclarationSHA256,
		})
	if status != http.StatusOK || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("checked selection status=%d or leaked credentials", status)
	}
	var selected apiv1.CurrentSelectionResponse
	if err := json.Unmarshal(response, &selected); err != nil {
		t.Fatal(err)
	}
	if !selected.Persisted || !selected.Applied || selected.LiveRuntimeTag != selected.RuntimeTag {
		t.Fatalf("selected source node was not applied to live Core: %+v", selected)
	}

	rule := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)
	selectedInbound := netip.AddrPortFrom(inbounds.Listen, inbounds.SelectedPort)
	direct := netip.AddrPortFrom(inbounds.Listen, inbounds.DirectPort)
	for _, addr := range []netip.AddrPort{rule, selectedInbound} {
		connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := socks5Connect(connectCtx, addr, target)
		if err != nil {
			cancel()
			t.Fatalf("real SOCKS5 to selected imported HTTP node: %v; stderr=%s", err, managed.StderrTail())
		}
		mvpAssertMarker(t, conn)
		cancel()
		assertRouteOutcomeSignal(t, proxyHits, 2*time.Second, "imported upstream HTTP proxy")
		assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "loopback echo through imported HTTP proxy")
	}
	// Real HTTP CONNECT through Mixed Rule inbound; it must also traverse
	// the imported upstream and not silently take the DIRECT path.
	mvpHTTPConnectMarker(t, rule, target)
	assertRouteOutcomeSignal(t, proxyHits, 2*time.Second, "HTTP CONNECT imported upstream")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "HTTP CONNECT target")
	connectCtx, directCancel := context.WithTimeout(ctx, 5*time.Second)
	directConn, err := socks5Connect(connectCtx, direct, target)
	if err != nil {
		directCancel()
		t.Fatalf("Direct inbound failed: %v", err)
	}
	mvpAssertMarker(t, directConn)
	directCancel()
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "direct target")
	assertNoRouteOutcomeSignal(t, proxyHits, 100*time.Millisecond, "DIRECT bypass should not call imported proxy")

	// MVP-1C repeat-update proof: the same stable node identity is backed by
	// an entirely different loopback proxy after an accepted subscription
	// refresh. Until the user explicitly stages and applies that snapshot,
	// the currently running Core MUST keep forwarding via the older proxy.
	switched.Store(true)
	status, response = mvpJSONRequest(t, api.URL, http.MethodPost,
		"/v1/profiles/"+profileID+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusOK || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("valid changed-source refresh rejected or leaked credentials: status=%d", status)
	}
	var updatedSnapshot apiv1.ProfileRefreshResponse
	if err := json.Unmarshal(response, &updatedSnapshot); err != nil {
		t.Fatal(err)
	}
	if updatedSnapshot.ProfileID != profileID || updatedSnapshot.SourceRevision != created.Revision ||
		updatedSnapshot.NotModified || updatedSnapshot.NodeCount != 1 ||
		updatedSnapshot.CurrentSnapshotID == nil ||
		*updatedSnapshot.CurrentSnapshotID <= *refreshed.CurrentSnapshotID {
		t.Fatalf("accepted changed source did not create a new snapshot: %+v", updatedSnapshot)
	}
	status, response = mvpJSONRequest(t, api.URL, http.MethodGet,
		"/v1/profiles/"+profileID+"/nodes", nil)
	var updatedPage apiv1.ProfileNodeListResponse
	if err := json.Unmarshal(response, &updatedPage); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || updatedPage.Total != 1 ||
		len(updatedPage.Nodes) != 1 || updatedPage.Nodes[0].NodeID != nodeID ||
		updatedPage.SnapshotID == nil ||
		*updatedPage.SnapshotID != *updatedSnapshot.CurrentSnapshotID {
		t.Fatalf("refreshed snapshot changed stable NodeID: %+v", updatedPage)
	}

	status, response = mvpJSONRequest(t, api.URL, http.MethodPost,
		"/v1/profiles/"+profileID+"/declaration/preview",
		apiv1.ProfileDeclarationPreviewRequest{
			SnapshotID:                  *updatedSnapshot.CurrentSnapshotID,
			ExpectedDeclarationRevision: staged.DeclarationRevision,
		})
	if status != http.StatusOK || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("changed snapshot declaration preview failed or leaked credentials: status=%d", status)
	}
	var updatedPreview apiv1.ProfileDeclarationPreviewResponse
	if err := json.Unmarshal(response, &updatedPreview); err != nil {
		t.Fatal(err)
	}
	if updatedPreview.ProfileID != profileID ||
		updatedPreview.SnapshotID != *updatedSnapshot.CurrentSnapshotID ||
		updatedPreview.SourceRevision != created.Revision ||
		updatedPreview.BaseDeclarationRevision != staged.DeclarationRevision ||
		updatedPreview.SnapshotNodeCount != 1 || updatedPreview.EffectiveNodeCount != 1 ||
		updatedPreview.AddedNodeCount != 0 || updatedPreview.RemovedNodeCount != 0 ||
		updatedPreview.RetainedNodeCount != 1 ||
		len(updatedPreview.RetainedNodeIDs) != 1 || updatedPreview.RetainedNodeIDs[0] != nodeID ||
		updatedPreview.AddedIDsTruncated || updatedPreview.RemovedIDsTruncated ||
		updatedPreview.RetainedIDsTruncated || updatedPreview.CoreValidated || updatedPreview.Applied ||
		updatedPreview.CandidateSHA256 == staged.DeclarationSHA256 ||
		len(updatedPreview.CandidateSHA256) != 64 || len(updatedPreview.RuntimeOverlaySHA256) != 64 {
		t.Fatalf("changed snapshot preview did not describe a stable-node rebind: %+v", updatedPreview)
	}
	updatedReceipt := apiv1.ProfileDeclarationStageRequest{
		SnapshotID:                  *updatedSnapshot.CurrentSnapshotID,
		ExpectedSourceRevision:      updatedPreview.SourceRevision,
		ExpectedDeclarationRevision: updatedPreview.BaseDeclarationRevision,
		CandidateSHA256:             updatedPreview.CandidateSHA256,
		RuntimeOverlaySHA256:        updatedPreview.RuntimeOverlaySHA256,
	}
	wrongDigest := updatedReceipt
	wrongDigest.CandidateSHA256 = strings.Repeat("0", 64)
	status, _ = mvpJSONRequest(t, api.URL, http.MethodPost,
		"/v1/profiles/"+profileID+"/declaration/stage", wrongDigest)
	if status != http.StatusConflict {
		t.Fatalf("changed-source stage accepted wrong preview digest: %d", status)
	}
	status, response = mvpJSONRequest(t, api.URL, http.MethodPost,
		"/v1/profiles/"+profileID+"/declaration/stage", updatedReceipt)
	if status != http.StatusCreated || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("new snapshot stage failed or disclosed credentials: %d", status)
	}
	var restaged apiv1.ProfileDeclarationStageResponse
	if err := json.Unmarshal(response, &restaged); err != nil {
		t.Fatal(err)
	}
	if restaged.DeclarationRevision != staged.DeclarationRevision+1 ||
		restaged.DeclarationSHA256 != updatedPreview.CandidateSHA256 ||
		restaged.SourceRevision != created.Revision ||
		restaged.SnapshotID != *updatedSnapshot.CurrentSnapshotID ||
		restaged.Applied || restaged.CoreValidated {
		t.Fatalf("confirmed snapshot stage returned inconsistent receipt: %+v", restaged)
	}
	unapplied, err := store.Snapshot(ctx)
	if err != nil || unapplied.Revision != appliedState.Revision ||
		unapplied.AppliedGenerationID == nil ||
		*unapplied.AppliedGenerationID != applied.GenerationID ||
		unapplied.LastKnownGoodGenerationID == nil ||
		*unapplied.LastKnownGoodGenerationID != applied.GenerationID {
		t.Fatalf("stage modified active Core/LKG before explicit Apply: %+v %v", unapplied, err)
	}
	// Even an accepted staged declaration is NOT traffic activation.
	holdCtx, holdCancel := context.WithTimeout(ctx, 5*time.Second)
	holdConn, holdErr := socks5Connect(holdCtx, rule, target)
	if holdErr != nil {
		holdCancel()
		t.Fatalf("running Core changed before checked Apply: %v", holdErr)
	}
	mvpAssertMarker(t, holdConn)
	holdCancel()
	assertRouteOutcomeSignal(t, proxyHits, 2*time.Second, "old proxy retained after stage")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "old proxy target after stage")
	assertNoRouteOutcomeSignal(t, updatedProxyHits, 200*time.Millisecond, "unapplied new upstream")
	status, _ = mvpJSONRequest(t, api.URL, http.MethodPost,
		"/v1/profiles/"+profileID+"/declaration/stage", updatedReceipt)
	if status != http.StatusConflict {
		t.Fatalf("same accepted stage could be replayed: %d", status)
	}

	// The protected checked-apply receipt must now refer to the new staged
	// declaration. The running Core's node detour is changed only by this
	// separate explicit application, never by snapshot refresh/stage.
	status, response = mvpJSONRequest(t, api.URL, http.MethodGet,
		"/v1/config/apply/preview", nil)
	if status != http.StatusOK || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("second checked-apply preview rejected or leaked credentials: %d", status)
	}
	var updatedApplyPreview apiv1.CheckedApplyPreviewResponse
	if err := json.Unmarshal(response, &updatedApplyPreview); err != nil {
		t.Fatal(err)
	}
	if updatedApplyPreview.Receipt.DeclarationRevision != restaged.DeclarationRevision ||
		updatedApplyPreview.Receipt.DeclarationSHA256 != restaged.DeclarationSHA256 ||
		updatedApplyPreview.Receipt.ExpectedConfigRevision != applied.TargetConfigRevision ||
		!updatedApplyPreview.CompilerValidated || updatedApplyPreview.CoreValidated ||
		updatedApplyPreview.Applied {
		t.Fatalf("rebind preview not bound to staged/current Core generation: %+v", updatedApplyPreview)
	}
	status, response = mvpJSONRequest(t, api.URL, http.MethodPost,
		"/v1/config/apply/confirm", updatedApplyPreview.Receipt)
	if status != http.StatusOK || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("second real-Core apply failed or leaked credentials: status=%d stderr=%s",
			status, managed.StderrTail())
	}
	var updatedApplied apiv1.CheckedApplyResponse
	if err := json.Unmarshal(response, &updatedApplied); err != nil {
		t.Fatal(err)
	}
	if !updatedApplied.CoreChecked || !updatedApplied.Verified || !updatedApplied.Applied ||
		updatedApplied.DeclarationRevision != restaged.DeclarationRevision ||
		updatedApplied.DeclarationSHA256 != restaged.DeclarationSHA256 ||
		updatedApplied.ConfigSHA256 != updatedApplyPreview.Receipt.NativeConfigSHA256 ||
		updatedApplied.GenerationID == applied.GenerationID ||
		updatedApplied.TargetConfigRevision != applied.TargetConfigRevision+1 {
		t.Fatalf("updated subscription was not checked/applied as a new generation: %+v", updatedApplied)
	}
	updatedArtifacts, err := store.GenerationArtifacts(ctx, updatedApplied.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(updatedArtifacts.ConfigJSON, []byte(secret)) ||
		bytes.Contains(updatedArtifacts.ConfigJSON, []byte("untrusted-mvp-rule.invalid")) ||
		bytes.Contains(updatedArtifacts.ConfigJSON, []byte(fmt.Sprintf("\"server_port\":%d", proxy.Port()))) {
		t.Fatal("updated applied generation omitted authentication, kept old proxy or injected subscription rules")
	}
	updatedState, err := store.Snapshot(ctx)
	if err != nil || updatedState.AppliedGenerationID == nil ||
		*updatedState.AppliedGenerationID != updatedApplied.GenerationID ||
		updatedState.LastKnownGoodGenerationID == nil ||
		*updatedState.LastKnownGoodGenerationID != updatedApplied.GenerationID ||
		updatedState.Revision != updatedApplied.TargetConfigRevision {
		t.Fatalf("rebind not persisted as active/LKG: %+v %v", updatedState, err)
	}
	running = waitManagedCoreState(t, managed, 6*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	for _, inbound := range []netip.AddrPort{rule, selectedInbound} {
		reboundCtx, reboundCancel := context.WithTimeout(ctx, 5*time.Second)
		rebound, reboundErr := socks5Connect(reboundCtx, inbound, target)
		if reboundErr != nil {
			reboundCancel()
			t.Fatalf("updated imported stable node could not traverse real Core: %v", reboundErr)
		}
		mvpAssertMarker(t, rebound)
		reboundCancel()
		assertRouteOutcomeSignal(t, updatedProxyHits, 2*time.Second, "updated bound proxy")
		assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "updated bound proxy target")
		assertNoRouteOutcomeSignal(t, proxyHits, 200*time.Millisecond, "retired proxy after apply")
	}
	mvpHTTPConnectMarker(t, rule, target)
	assertRouteOutcomeSignal(t, updatedProxyHits, 2*time.Second, "rebound HTTP CONNECT proxy")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "rebound HTTP CONNECT target")
	assertNoRouteOutcomeSignal(t, proxyHits, 200*time.Millisecond, "retired proxy HTTP CONNECT")

	// From here the NEW generation (not the initial import) is the LKG that
	// malformed source updates and process restarts are required to preserve.
	refreshed = updatedSnapshot
	applied = updatedApplied
	appliedState = updatedState

	broken.Store(true)
	status, response = mvpJSONRequest(t, api.URL, http.MethodPost, "/v1/profiles/"+profileID+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusUnprocessableEntity || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("unsupported source update was accepted or leaked credentials: status=%d", status)
	}
	afterSource, err := store.ProfileSource(ctx, profileID)
	if err != nil || afterSource.CurrentSnapshotID == nil ||
		*afterSource.CurrentSnapshotID != *refreshed.CurrentSnapshotID ||
		afterSource.ConsecutiveFailures == 0 {
		t.Fatalf("invalid update displaced accepted source: %+v %v", afterSource, err)
	}
	after, err := store.Snapshot(ctx)
	if err != nil || after.Revision != appliedState.Revision ||
		after.AppliedGenerationID == nil || *after.AppliedGenerationID != applied.GenerationID ||
		after.LastKnownGoodGenerationID == nil || *after.LastKnownGoodGenerationID != applied.GenerationID ||
		after.RecoveryRequired || after.ActiveAttemptID != nil || managed.Snapshot().PID != running.PID {
		t.Fatalf("invalid subscription disturbed running LKG: %+v %v", after, err)
	}
	staleStatus, _ := mvpJSONRequest(t, api.URL, http.MethodPost, "/v1/profiles/"+profileID+"/declaration/initial/stage", stageReceipt)
	if staleStatus != http.StatusConflict {
		t.Fatalf("stale stage unexpectedly committed after apply: %d", staleStatus)
	}
	connectCtx, againCancel := context.WithTimeout(ctx, 5*time.Second)
	conn, err := socks5Connect(connectCtx, rule, target)
	if err != nil {
		againCancel()
		t.Fatalf("running LKG lost traffic after bad refresh: %v", err)
	}
	mvpAssertMarker(t, conn)
	againCancel()
	assertRouteOutcomeSignal(t, updatedProxyHits, 2*time.Second, "new LKG upstream after bad refresh")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "old target after bad refresh")

	stopCtx, stopCancel := context.WithTimeout(ctx, 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatal(err)
	}
	stopCancel()
	restartCtx, restartCancel := context.WithTimeout(ctx, 15*time.Second)
	if err := runtime.Start(restartCtx); err != nil {
		restartCancel()
		t.Fatalf("offline restart of accepted generation failed: %v", err)
	}
	restartCancel()
	waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	connectCtx, restartTrafficCancel := context.WithTimeout(ctx, 5*time.Second)
	conn, err = socks5Connect(connectCtx, rule, target)
	if err != nil {
		restartTrafficCancel()
		t.Fatalf("LKG traffic after restart: %v", err)
	}
	mvpAssertMarker(t, conn)
	restartTrafficCancel()
	assertRouteOutcomeSignal(t, updatedProxyHits, 2*time.Second, "new LKG upstream after restart")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "old target after restart")
	finalState, err := store.Snapshot(ctx)
	if err != nil || finalState.AppliedGenerationID == nil ||
		*finalState.AppliedGenerationID != applied.GenerationID ||
		finalState.LastKnownGoodGenerationID == nil || *finalState.LastKnownGoodGenerationID != applied.GenerationID {
		t.Fatalf("restart changed LKG generation: %+v %v", finalState, err)
	}
}

func mvpJSONRequest(t *testing.T, baseURL, method, path string, payload any) (int, []byte) {
	t.Helper()
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequest(method, baseURL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Timeout: 90 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, content
}

func startMVPForwardingHTTPProxy(
	t *testing.T, target netip.AddrPort, username, password string,
) (netip.AddrPort, <-chan struct{}, func()) {
	t.Helper()
	hits := make(chan struct{}, 16)
	credentials := "Basic " + basicAuthHeader(username, password)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This test upstream can reach ONLY the local echo target.
		if r.Method != http.MethodConnect || r.Host != target.String() ||
			r.Header.Get("Proxy-Authorization") != credentials {
			http.Error(w, "unapproved CONNECT", http.StatusForbidden)
			return
		}
		backend, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(r.Context(), "tcp", target.String())
		if err != nil {
			http.Error(w, "echo unavailable", http.StatusBadGateway)
			return
		}
		defer backend.Close()
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking unavailable", http.StatusInternalServerError)
			return
		}
		client, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}
		select {
		case hits <- struct{}{}:
		default:
		}
		_, _ = io.Copy(client, backend)
	}))
	addr, err := netip.ParseAddrPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return addr, hits, server.Close
}

func basicAuthHeader(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

func mvpAssertMarker(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	var marker [2]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil || marker != [2]byte{'o', 'k'} {
		t.Fatalf("proxy tunnel did not reach local echo: marker=%v err=%v", marker, err)
	}
}

func mvpHTTPConnectMarker(t *testing.T, inbound, target netip.AddrPort) {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 4 * time.Second}).Dial("tcp", inbound.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil || !(strings.HasPrefix(status, "HTTP/1.1 200 ") || strings.HasPrefix(status, "HTTP/1.0 200 ")) {
		t.Fatalf("HTTP CONNECT through imported node failed: %q %v", status, err)
	}
	for n := 0; n < 32; n++ {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			var marker [2]byte
			if _, err := io.ReadFull(reader, marker[:]); err != nil || marker != [2]byte{'o', 'k'} {
				t.Fatalf("HTTP CONNECT tunnel did not echo: marker=%v err=%v", marker, err)
			}
			return
		}
	}
	t.Fatal("HTTP CONNECT returned unbounded headers")
}
