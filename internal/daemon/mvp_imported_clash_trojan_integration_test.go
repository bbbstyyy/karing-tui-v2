//go:build integration && linux

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

// MVP-1C/1D: a real pinned Core client, from a user-imported Clash YAML Trojan
// through first-run preview/stage, explicit Core Check/Apply, TCP-over-TLS,
// verified password and a loopback echo. No external routing/CN/TUN is involved.
func TestManagedCoreRealMVPImportedClashYAMLTrojanFlow(t *testing.T) {
	assertOrdinaryUserCoreEnvironment(t)
	corePath := os.Getenv("KARING_TUI_TEST_CORE")
	if corePath == "" {
		t.Skip("KARING_TUI_TEST_CORE is not set")
	}
	const profileID = "mvp-clash-trojan"
	target, targetHits, closeTarget := startRouteOutcomeTarget(t)
	defer closeTarget()
	trojan, rootCert, upstreamHits, closeTrojan := startMVPLocalTrojanTLS(t, target)
	defer closeTrojan()
	// A second real peer has a different semantic Clash identity. The old
	// selected node must not be silently rebound to its endpoint on refresh.
	replacementTrojan, replacementRoot, replacementHits, closeReplacement := startMVPLocalTrojanTLS(t, target)
	defer closeReplacement()
	// The pinned Core is a separate child process. Its normal TLS verifier
	// must trust only this temporary local fixture certificate, NOT skip
	// verification through an insecure=true outbound setting.
	// Both peers independently authenticate TLS; do not disable verification.
	// Trust only the two local fixture roots for this isolated test child.
	rootA, err := os.ReadFile(rootCert)
	if err != nil {
		t.Fatal(err)
	}
	rootB, err := os.ReadFile(replacementRoot)
	if err != nil {
		t.Fatal(err)
	}
	rootBundle := filepath.Join(t.TempDir(), "trojan-rebind-roots.pem")
	if err := os.WriteFile(rootBundle, append(rootA, rootB...), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", rootBundle)

	var broken, renamed, selectedRemoved atomic.Bool
	sourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/x-yaml; charset=utf-8")
		if broken.Load() {
			_, _ = fmt.Fprintf(w, "proxies:\n  - name: Rejected\n    type: trojan\n    server: 127.0.0.1\n    port: %d\n    password: %s\n    skip-cert-verify: true\n", trojan.Port(), mvpTrojanSecret)
			return
		}
		name, port := "Accepted", trojan.Port()
		if renamed.Load() {
			name = "Renamed"
		}
		if selectedRemoved.Load() {
			name, port = "Replacement", replacementTrojan.Port()
		}
		_, _ = fmt.Fprintf(w, "proxies:\n  - name: %s\n    type: trojan\n    server: 127.0.0.1\n    port: %d\n    password: %s\n    sni: %s\n    skip-cert-verify: false\nproxy-groups:\n  - name: Untrusted Rule\n    type: select\n    proxies: [DIRECT]\nrules:\n  - MATCH,DIRECT\n", name, port, mvpTrojanSecret, mvpTrojanServerName)
	}))
	defer sourceServer.Close()

	ctx := context.Background()
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
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
		Executable:      corePath,
		StateRoot:       filepath.Join(stateDir, "core"),
		ControlEndpoint: fmt.Sprintf("http://127.0.0.1:%d", ports[3]),
		ControlSecret:   controlSecret,
		Inbounds:        inbounds,
		Policy:          policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	nativeCompiler, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       inbounds,
		ControlAddress: netip.AddrPortFrom(inbounds.Listen, ports[3]),
		ControlSecret:  controlSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewDeclarationCompileCoordinator(store, nativeCompiler)
	if err != nil {
		t.Fatal(err)
	}
	runtime, done, shutdown, err := startServerRuntimeWithDeclarations(context.Background(), store, managed, coordinator)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		shutdown()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("managed core shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("managed core supervisor shutdown timed out")
		}
	}()
	api := httptest.NewServer(New(runtimepath.Paths{}).handler(store, runtime))
	defer api.Close()
	// The SAME actual daemon and pinned Core are also reachable through the
	// supported Unix client transport used by the public TUI.
	unixSocket := mvpTUIUnixServerForRuntime(t, store, runtime)
	const sourcePath = "/v1/profiles/" + profileID
	source := apiv1.ProfileSourceSpec{
		Format: "clash-yaml", LocationKind: "url", Location: sourceServer.URL,
		Enabled: true, Fetch: apiv1.ProfileSourceFetchPolicy{Mode: "direct"},
	}
	status, reply := mvpJSONRequest(t, api.URL, http.MethodPut, sourcePath,
		apiv1.ProfileSourcePutRequest{Source: source})
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("Clash YAML Trojan source creation rejected or leaked identity: status %d", status)
	}
	var created apiv1.ProfileSourceResponse
	if err := json.Unmarshal(reply, &created); err != nil {
		t.Fatal(err)
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost, sourcePath+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("Clash YAML Trojan source refresh rejected or leaked identity: status %d", status)
	}
	var refreshed apiv1.ProfileRefreshResponse
	if err := json.Unmarshal(reply, &refreshed); err != nil {
		t.Fatal(err)
	}
	if refreshed.NodeCount != 1 || refreshed.CurrentSnapshotID == nil {
		t.Fatal("Trojan source did not produce one accepted snapshot")
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodGet, sourcePath+"/nodes", nil)
	var page apiv1.ProfileNodeListResponse
	if err := json.Unmarshal(reply, &page); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || page.Total != 1 || len(page.Nodes) != 1 ||
		page.Nodes[0].Disabled || page.Nodes[0].NodeID == "" {
		t.Fatal("Trojan imported node missing from user-visible accepted source")
	}
	nodeID := page.Nodes[0].NodeID
	init := apiv1.InitialProfileDeclarationPreviewRequest{
		SnapshotID:      *refreshed.CurrentSnapshotID,
		SelectedNodeID:  nodeID,
		ResolverAddress: "127.0.0.1:9",
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost,
		sourcePath+"/declaration/initial/preview", init)
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("Trojan first-run preview rejected or leaked identity: status %d", status)
	}
	var preview apiv1.InitialProfileDeclarationPreviewResponse
	if err := json.Unmarshal(reply, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.SourceRevision != created.Revision ||
		preview.SelectedNodeID != nodeID || preview.EffectiveNodeCount != 1 ||
		preview.BaseDeclarationRevision != 0 || preview.CNRulesReady ||
		preview.CoreValidated || preview.Applied || len(preview.CandidateSHA256) != 64 {
		t.Fatalf("invalid Trojan initial preview: %+v", preview)
	}
	receipt := apiv1.InitialProfileDeclarationStageRequest{
		SnapshotID:               *refreshed.CurrentSnapshotID,
		ExpectedSourceRevision:   preview.SourceRevision,
		SelectedNodeID:           nodeID,
		ResolverAddress:          init.ResolverAddress,
		CandidateSHA256:          preview.CandidateSHA256,
		RuntimeOverlaySHA256:     preview.RuntimeOverlaySHA256,
		AcknowledgeProxyOnlyNoCN: true,
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost,
		sourcePath+"/declaration/initial/stage", receipt)
	if status != http.StatusCreated || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("Trojan first-run stage rejected or leaked identity: status %d", status)
	}
	var staged apiv1.InitialProfileDeclarationStageResponse
	if err := json.Unmarshal(reply, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.DeclarationRevision != 1 ||
		staged.DeclarationSHA256 != preview.CandidateSHA256 ||
		staged.CNRulesReady || staged.Applied || staged.CoreValidated {
		t.Fatal("Trojan stage did not preserve explicit no-CN/no-apply state")
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodGet, "/v1/config/apply/preview", nil)
	if status != http.StatusOK {
		t.Fatalf("Trojan checked apply preview rejected: %d", status)
	}
	var applyPreview apiv1.CheckedApplyPreviewResponse
	if err := json.Unmarshal(reply, &applyPreview); err != nil {
		t.Fatal(err)
	}
	if !applyPreview.CompilerValidated || applyPreview.CoreValidated ||
		applyPreview.Applied || applyPreview.Receipt.DeclarationRevision != 1 {
		t.Fatal("Trojan checked apply preview was not bound to the staged declaration")
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost,
		"/v1/config/apply/confirm", applyPreview.Receipt)
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("Trojan Core Check/Apply failed or leaked password: status %d stderr=%s", status, managed.StderrTail())
	}
	var applied apiv1.CheckedApplyResponse
	if err := json.Unmarshal(reply, &applied); err != nil {
		t.Fatal(err)
	}
	if !applied.CoreChecked || !applied.Verified || !applied.Applied ||
		applied.DeclarationRevision != staged.DeclarationRevision ||
		applied.ConfigSHA256 != applyPreview.Receipt.NativeConfigSHA256 {
		t.Fatalf("Trojan approved Core did not commit authenticated generation: %+v", applied)
	}
	artifacts, err := store.GenerationArtifacts(ctx, applied.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(artifacts.ConfigJSON, []byte(mvpTrojanSecret)) ||
		!bytes.Contains(artifacts.ConfigJSON, []byte(mvpTrojanServerName)) ||
		bytes.Contains(artifacts.ConfigJSON, []byte(`"insecure":true`)) {
		t.Fatal("native Trojan config dropped password/SNI or weakened certificate verification")
	}

	startCtx, cancelStart := context.WithTimeout(ctx, 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		cancelStart()
		t.Fatalf("Trojan applied runtime failed to start: %v", err)
	}
	cancelStart()
	waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	rule := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)
	selected := netip.AddrPortFrom(inbounds.Listen, inbounds.SelectedPort)
	direct := netip.AddrPortFrom(inbounds.Listen, inbounds.DirectPort)
	for _, inbound := range []netip.AddrPort{rule, selected} {
		connectCtx, disconnect := context.WithTimeout(ctx, 5*time.Second)
		conn, err := socks5Connect(connectCtx, inbound, target)
		if err != nil {
			disconnect()
			t.Fatalf("Trojan TLS SOCKS tunnel refused: %v; core=%s", err, managed.StderrTail())
		}
		mvpAssertMarker(t, conn)
		disconnect()
		assertRouteOutcomeSignal(t, upstreamHits, 2*time.Second, "verified Trojan TLS/password upstream")
		assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "Trojan tunneled echo")
	}
	mvpHTTPConnectMarker(t, rule, target)
	assertRouteOutcomeSignal(t, upstreamHits, 2*time.Second, "Trojan through HTTP CONNECT")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "Trojan CONNECT echo")

	connectCtx, disconnect := context.WithTimeout(ctx, 5*time.Second)
	conn, err := socks5Connect(connectCtx, direct, target)
	if err != nil {
		disconnect()
		t.Fatalf("DIRECT inbound refused: %v", err)
	}
	mvpAssertMarker(t, conn)
	disconnect()
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "DIRECT target")
	assertNoRouteOutcomeSignal(t, upstreamHits, 100*time.Millisecond, "DIRECT accidentally routed to Trojan")

	// A valid TLS peer must reject an unrecognized password even when transport
	// and target match; a rejected authorization cannot reach the target.
	assertMVPLocalTrojanRejectsBadPassword(t, trojan, rootCert, target)
	assertNoRouteOutcomeSignal(t, upstreamHits, 100*time.Millisecond, "wrong Trojan password")
	assertNoRouteOutcomeSignal(t, targetHits, 100*time.Millisecond, "wrong password target")

	// The real selected Trojan keeps serving throughout two ACCEPTED source
	// updates. A display-name-only change preserves the semantic Clash
	// identity, whereas changing the endpoint deliberately removes that
	// selected ID. Neither refresh may stage/activate a replacement for us.
	renamed.Store(true)
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost, sourcePath+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("safe Clash label refresh rejected or leaked password: status %d", status)
	}
	var renamedSnapshot apiv1.ProfileRefreshResponse
	if err := json.Unmarshal(reply, &renamedSnapshot); err != nil {
		t.Fatal(err)
	}
	if renamedSnapshot.CurrentSnapshotID == nil || renamedSnapshot.NotModified ||
		renamedSnapshot.NodeCount != 1 ||
		*renamedSnapshot.CurrentSnapshotID <= *refreshed.CurrentSnapshotID {
		t.Fatalf("Clash label refresh did not create a new accepted snapshot: %+v", renamedSnapshot)
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodGet, sourcePath+"/nodes", nil)
	var renamedPage apiv1.ProfileNodeListResponse
	if err := json.Unmarshal(reply, &renamedPage); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || renamedPage.Total != 1 ||
		len(renamedPage.Nodes) != 1 || renamedPage.Nodes[0].NodeID != nodeID ||
		renamedPage.SnapshotID == nil ||
		*renamedPage.SnapshotID != *renamedSnapshot.CurrentSnapshotID {
		t.Fatalf("display-only Clash rename mutated semantic NodeID: %+v", renamedPage)
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost,
		sourcePath+"/declaration/preview", apiv1.ProfileDeclarationPreviewRequest{
			SnapshotID:                  *renamedSnapshot.CurrentSnapshotID,
			ExpectedDeclarationRevision: staged.DeclarationRevision,
		})
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("renamed stable node preview failed or leaked password: status %d", status)
	}
	var renamePreview apiv1.ProfileDeclarationPreviewResponse
	if err := json.Unmarshal(reply, &renamePreview); err != nil {
		t.Fatal(err)
	}
	if renamePreview.BaseDeclarationRevision != staged.DeclarationRevision ||
		renamePreview.SourceRevision != created.Revision ||
		renamePreview.SnapshotID != *renamedSnapshot.CurrentSnapshotID ||
		renamePreview.SnapshotNodeCount != 1 || renamePreview.EffectiveNodeCount != 1 ||
		renamePreview.AddedNodeCount != 0 || renamePreview.RemovedNodeCount != 0 ||
		renamePreview.RetainedNodeCount != 1 || len(renamePreview.RetainedNodeIDs) != 1 ||
		renamePreview.RetainedNodeIDs[0] != nodeID || renamePreview.CoreValidated ||
		renamePreview.Applied || len(renamePreview.CandidateSHA256) != 64 {
		t.Fatalf("Clash rename produced unexpected prospective node diff: %+v", renamePreview)
	}

	// A changed endpoint has a different semantic NodeID by design: it is
	// NOT a harmless rename. An entirely valid fresh subscription may therefore
	// be accepted, but staging it must fail closed while the current selection
	// still points to the removed (and running) original Trojan.
	selectedRemoved.Store(true)
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost, sourcePath+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("valid replacement Clash source was not accepted: status %d", status)
	}
	var removedSnapshot apiv1.ProfileRefreshResponse
	if err := json.Unmarshal(reply, &removedSnapshot); err != nil {
		t.Fatal(err)
	}
	if removedSnapshot.CurrentSnapshotID == nil || removedSnapshot.NotModified ||
		removedSnapshot.NodeCount != 1 ||
		*removedSnapshot.CurrentSnapshotID <= *renamedSnapshot.CurrentSnapshotID {
		t.Fatalf("valid replacement snapshot not stored: %+v", removedSnapshot)
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodGet, sourcePath+"/nodes", nil)
	var removedPage apiv1.ProfileNodeListResponse
	if err := json.Unmarshal(reply, &removedPage); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || removedPage.Total != 1 ||
		len(removedPage.Nodes) != 1 || removedPage.Nodes[0].NodeID == nodeID ||
		removedPage.Nodes[0].NodeID == "" || removedPage.SnapshotID == nil ||
		*removedPage.SnapshotID != *removedSnapshot.CurrentSnapshotID {
		t.Fatalf("removed selected node remained in accepted source: %+v", removedPage)
	}
	// A preview from the previous accepted snapshot is stale even though the
	// old declaration revision has not changed.
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost,
		sourcePath+"/declaration/preview", apiv1.ProfileDeclarationPreviewRequest{
			SnapshotID:                  *renamedSnapshot.CurrentSnapshotID,
			ExpectedDeclarationRevision: staged.DeclarationRevision,
		})
	if status != http.StatusConflict || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("stale rename snapshot preview bypassed source CAS: %d", status)
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost,
		sourcePath+"/declaration/preview", apiv1.ProfileDeclarationPreviewRequest{
			SnapshotID:                  *removedSnapshot.CurrentSnapshotID,
			ExpectedDeclarationRevision: staged.DeclarationRevision,
		})
	if status != http.StatusUnprocessableEntity || bytes.Contains(reply, []byte(mvpTrojanSecret)) ||
		bytes.Contains(reply, []byte(nodeID)) {
		t.Fatalf("selected-node removal was stageable or leaked identity: %d", status)
	}
	// Even replaying a once-valid digest from an older snapshot cannot be used
	// as an escape hatch to commit an invalid candidate.
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost,
		sourcePath+"/declaration/stage", apiv1.ProfileDeclarationStageRequest{
			SnapshotID:                  *removedSnapshot.CurrentSnapshotID,
			ExpectedSourceRevision:      created.Revision,
			ExpectedDeclarationRevision: staged.DeclarationRevision,
			CandidateSHA256:             renamePreview.CandidateSHA256,
			RuntimeOverlaySHA256:        renamePreview.RuntimeOverlaySHA256,
		})
	if status != http.StatusUnprocessableEntity || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("removed-selected snapshot stage bypassed declaration validation: %d", status)
	}
	stillStaged, err := store.CurrentDeclaration(ctx)
	if err != nil || stillStaged.Revision != staged.DeclarationRevision ||
		stillStaged.SHA256 != staged.DeclarationSHA256 {
		t.Fatalf("failed replacement modified durable declaration: %+v %v", stillStaged, err)
	}
	stillRunning, err := store.Snapshot(ctx)
	if err != nil || stillRunning.AppliedGenerationID == nil ||
		*stillRunning.AppliedGenerationID != applied.GenerationID ||
		stillRunning.LastKnownGoodGenerationID == nil ||
		*stillRunning.LastKnownGoodGenerationID != applied.GenerationID ||
		stillRunning.RecoveryRequired || stillRunning.ActiveAttemptID != nil {
		t.Fatalf("accepted unstageable source disrupted Applied/LKG: %+v %v", stillRunning, err)
	}
	for _, inbound := range []netip.AddrPort{rule, selected} {
		probeCtx, stopProbe := context.WithTimeout(ctx, 5*time.Second)
		probe, probeErr := socks5Connect(probeCtx, inbound, target)
		if probeErr != nil {
			stopProbe()
			t.Fatalf("selected node removal disrupted live Trojan Core traffic: %v", probeErr)
		}
		mvpAssertMarker(t, probe)
		stopProbe()
		assertRouteOutcomeSignal(t, upstreamHits, 2*time.Second, "old selected Trojan still live")
		assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "old Trojan echo after selected removal")
		assertNoRouteOutcomeSignal(t, replacementHits, 100*time.Millisecond, "unconfirmed replacement peer")
	}

	// This time drive the exact accepted replacement with Bubble Tea
	// keystrokes over a *real Unix Socket*. Both the checked Stage and
	// subsequent checked Apply must be separate user confirmations.
	newSelected := removedPage.Nodes[0].NodeID
	ui := mvpTUIOpenAcceptedNodesForProfile(t, unixSocket, profileID, newSelected)
	ui, uiCmd := mvpTUIUpdate(t, ui, mvpTUIKey('m'))
	if uiCmd == nil {
		t.Fatal("TUI did not start read-only explicit replacement preview")
	}
	beforePreview, err := store.CurrentDeclaration(ctx)
	if err != nil || beforePreview.Revision != staged.DeclarationRevision ||
		beforePreview.SHA256 != staged.DeclarationSHA256 {
		t.Fatalf("TUI preview changed declaration before confirmation: %+v %v", beforePreview, err)
	}
	ui = mvpTUIRun(t, ui, uiCmd)
	review := []byte(ui.View())
	for _, expected := range []string{
		"EXPLICIT replacement CurrentSelected ID:",
		"Node diff: +1 added  -1 removed",
		"Stage is NOT Core Check/Apply",
		"y: CONFIRM Stage only",
	} {
		if !bytes.Contains(review, []byte(expected)) {
			t.Fatalf("TUI replacement review omitted %q: %s", expected, review)
		}
	}
	// A stable node ID can exceed 64 columns: the entire identity must be
	// visible in exact bounded lines, not truncated or merged with secrets.
	for offset := 0; offset < len(newSelected); offset += 64 {
		end := min(offset+64, len(newSelected))
		if !bytes.Contains(review, []byte("  "+newSelected[offset:end]+"\n")) {
			t.Fatal("TUI replacement review truncated selected stable identity")
		}
	}
	if bytes.Contains(review, []byte(mvpTrojanSecret)) ||
		bytes.Contains(review, []byte(nodeID)) {
		t.Fatal("TUI explicit approval leaked secret or retired identity")
	}
	ui, uiCmd = mvpTUIUpdate(t, ui, mvpTUIKey('y'))
	if uiCmd == nil {
		t.Fatal("TUI did not require separate selected Stage confirmation")
	}
	ui = mvpTUIRun(t, ui, uiCmd)
	if !bytes.Contains([]byte(ui.View()), []byte("Verified staged declaration rev")) ||
		!bytes.Contains([]byte(ui.View()), []byte("Applied/LKG unchanged")) {
		t.Fatalf("TUI selected Stage lacked readback confirmation: %s", ui.View())
	}
	rebound, err := store.CurrentDeclaration(ctx)
	if err != nil || rebound.Revision != staged.DeclarationRevision+1 ||
		rebound.SHA256 == staged.DeclarationSHA256 {
		t.Fatalf("TUI Stage did not commit one new immutable declaration: %+v %v", rebound, err)
	}
	proposed, err := declaration.ParseV1(rebound.DocumentJSON)
	if err != nil || len(proposed.Nodes) != 1 ||
		proposed.Selection.Current.Default.NodeID != newSelected ||
		proposed.Nodes[0].NodeID != newSelected {
		t.Fatalf("TUI Stage did not choose the exact admitted replacement: %v", err)
	}
	unchangedCore, err := store.Snapshot(ctx)
	if err != nil || unchangedCore.AppliedGenerationID == nil ||
		unchangedCore.LastKnownGoodGenerationID == nil ||
		*unchangedCore.AppliedGenerationID != applied.GenerationID ||
		*unchangedCore.LastKnownGoodGenerationID != applied.GenerationID {
		t.Fatalf("TUI Stage switched active Core before Apply: %+v %v", unchangedCore, err)
	}
	holdCtx, holdCancel := context.WithTimeout(ctx, 5*time.Second)
	holdConn, holdErr := socks5Connect(holdCtx, rule, target)
	if holdErr != nil {
		holdCancel()
		t.Fatal(holdErr)
	}
	mvpAssertMarker(t, holdConn)
	holdCancel()
	assertRouteOutcomeSignal(t, upstreamHits, 2*time.Second, "old Trojan while TUI Stage pending Apply")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "old Trojan still serves echo before Apply")
	assertNoRouteOutcomeSignal(t, replacementHits, 100*time.Millisecond, "TUI Stage cannot activate new Trojan")

	// Separately inspect the pending declaration and explicitly confirm an
	// actual Core Check/Activate/Verify/Commit via the same Unix TUI client.
	ui, uiCmd = mvpTUIUpdate(t, ui, mvpTUIKey('1'))
	ui = mvpTUIRun(t, ui, uiCmd)
	ui, uiCmd = mvpTUIUpdate(t, ui, mvpTUIKey('a'))
	if uiCmd == nil {
		t.Fatal("TUI did not offer checked Core Apply preview")
	}
	beforeApply, err := store.Snapshot(ctx)
	if err != nil || beforeApply.AppliedGenerationID == nil ||
		*beforeApply.AppliedGenerationID != applied.GenerationID {
		t.Fatalf("TUI checked Apply preview changed generation: %+v %v", beforeApply, err)
	}
	ui = mvpTUIRun(t, ui, uiCmd)
	applyView := []byte(ui.View())
	for _, marker := range []string{
		"CURRENT DECLARATION: COMPILER PREVIEW ONLY",
		"APPLY MAY RESTART CORE",
		"Core check has NOT run",
	} {
		if !bytes.Contains(applyView, []byte(marker)) {
			t.Fatalf("TUI did not expose checked Apply risks %q: %s", marker, applyView)
		}
	}
	ui, uiCmd = mvpTUIUpdate(t, ui, mvpTUIKey('y'))
	if uiCmd == nil {
		t.Fatal("TUI checked Apply was not separately confirmed")
	}
	ui = mvpTUIRun(t, ui, uiCmd)
	if !bytes.Contains([]byte(ui.View()), []byte("Applied and verified: declaration rev")) ||
		bytes.Contains([]byte(ui.View()), []byte(mvpTrojanSecret)) {
		t.Fatalf("TUI Apply did not verify durable generation or leaked a secret: %s", ui.View())
	}
	afterApply, err := store.Snapshot(ctx)
	if err != nil || afterApply.AppliedGenerationID == nil ||
		afterApply.LastKnownGoodGenerationID == nil ||
		*afterApply.AppliedGenerationID == applied.GenerationID ||
		*afterApply.AppliedGenerationID != *afterApply.LastKnownGoodGenerationID ||
		afterApply.Revision != beforeApply.Revision+1 {
		t.Fatalf("TUI Apply did not durably activate new Core: %+v %v", afterApply, err)
	}
	newGeneration := *afterApply.AppliedGenerationID
	rebuilt, err := store.GenerationArtifacts(ctx, newGeneration)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(rebuilt.ConfigJSON, []byte(mvpTrojanSecret)) ||
		bytes.Contains(rebuilt.ConfigJSON, []byte("\"insecure\":true")) {
		t.Fatal("TUI selected Apply lost Trojan password or disabled TLS verification")
	}
	waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	for _, inbound := range []netip.AddrPort{rule, selected} {
		checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
		checkConn, checkErr := socks5Connect(checkCtx, inbound, target)
		if checkErr != nil {
			checkCancel()
			t.Fatalf("real TUI selected Trojan Core rejected proxy traffic: %v", checkErr)
		}
		mvpAssertMarker(t, checkConn)
		checkCancel()
		assertRouteOutcomeSignal(t, replacementHits, 2*time.Second, "TUI replacement Trojan authenticated TLS")
		assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "TUI replacement Trojan tunneled echo")
		assertNoRouteOutcomeSignal(t, upstreamHits, 100*time.Millisecond, "retired Trojan after TUI Apply")
	}
	mvpHTTPConnectMarker(t, rule, target)
	assertRouteOutcomeSignal(t, replacementHits, 2*time.Second, "TUI replacement Trojan HTTP CONNECT")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "TUI replacement Trojan CONNECT echo")
	assertNoRouteOutcomeSignal(t, upstreamHits, 100*time.Millisecond, "retired Trojan CONNECT")
	// This is now the ONLY accepted LKG for the following bad refresh and
	// offline stop/start; no implicit Core update happened on source refresh.
	applied.GenerationID = newGeneration
	upstreamHits = replacementHits

	// The bad update below must retain the most recently accepted snapshot
	// (the replacement) even though the running LKG legitimately differs.
	refreshed = removedSnapshot

	broken.Store(true)
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost, sourcePath+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusUnprocessableEntity || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("unsupported Trojan update was accepted or leaked password: status %d", status)
	}
	afterSource, err := store.ProfileSource(ctx, profileID)
	if err != nil || afterSource.CurrentSnapshotID == nil ||
		*afterSource.CurrentSnapshotID != *refreshed.CurrentSnapshotID ||
		afterSource.ConsecutiveFailures == 0 {
		t.Fatalf("bad Trojan source replaced accepted snapshot: %v", err)
	}
	after, err := store.Snapshot(ctx)
	if err != nil || after.AppliedGenerationID == nil ||
		*after.AppliedGenerationID != applied.GenerationID ||
		after.LastKnownGoodGenerationID == nil ||
		*after.LastKnownGoodGenerationID != applied.GenerationID ||
		after.RecoveryRequired || after.ActiveAttemptID != nil {
		t.Fatalf("bad Trojan source damaged LKG: %v", err)
	}
	status, _ = mvpJSONRequest(t, api.URL, http.MethodPost,
		sourcePath+"/declaration/initial/stage", receipt)
	if status != http.StatusConflict {
		t.Fatalf("Trojan old initial stage replay was accepted: %d", status)
	}
	connectCtx, disconnect = context.WithTimeout(ctx, 5*time.Second)
	conn, err = socks5Connect(connectCtx, rule, target)
	if err != nil {
		disconnect()
		t.Fatalf("bad subscription disrupted active Trojan tunnel: %v", err)
	}
	mvpAssertMarker(t, conn)
	disconnect()
	assertRouteOutcomeSignal(t, upstreamHits, 2*time.Second, "LKG Trojan tunnel after bad refresh")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "LKG Trojan echo after bad refresh")

	stopCtx, cancelStop := context.WithTimeout(ctx, 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		cancelStop()
		t.Fatal(err)
	}
	cancelStop()
	restartCtx, cancelRestart := context.WithTimeout(ctx, 15*time.Second)
	if err := runtime.Start(restartCtx); err != nil {
		cancelRestart()
		t.Fatalf("offline Trojan restart failed: %v", err)
	}
	cancelRestart()
	waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	connectCtx, disconnect = context.WithTimeout(ctx, 5*time.Second)
	conn, err = socks5Connect(connectCtx, rule, target)
	if err != nil {
		disconnect()
		t.Fatalf("Trojan LKG lost real traffic after restart: %v", err)
	}
	mvpAssertMarker(t, conn)
	disconnect()
	assertRouteOutcomeSignal(t, upstreamHits, 2*time.Second, "post-restart Trojan TLS tunnel")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "post-restart Trojan echo")
}
