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
// A fixture seeds the initial V1 routing/selection declaration because the
// first-run user-facing declaration constructor is not yet implemented. This
// is an end-to-end imported-node proof, NOT MV-02 user acceptance or CN proof.
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

	var broken atomic.Bool
	sourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if broken.Load() {
			// Existing HTTP node has no supported TLS field. A malformed
			// refresh must never advance snapshot, declaration or LKG.
			_, _ = io.WriteString(w, fmt.Sprintf(`{"outbounds":[{"type":"http","tag":%q,"server":"127.0.0.1","server_port":%d,"tls":{"enabled":true}}]}`, sourceKey, proxy.Port()))
			return
		}
		_, _ = io.WriteString(w, fmt.Sprintf(`{
			"outbounds":[{"type":"http","tag":%q,"server":"127.0.0.1","server_port":%d,"username":"mvp-user","password":%q}],
			"route":{"rules":[{"domain_suffix":["untrusted-mvp-rule.invalid"],"outbound":"direct"}],"final":"direct"}
		}`, sourceKey, proxy.Port(), secret))
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

	// The base is a test-only V1 declaration. The source payload must
	// replace its intentionally stale HTTP port and missing authentication.
	base, err := store.CommitDeclaration(ctx, 0, mvpHTTPBaseDeclaration(profileID, nodeID), "integration:mvp-base")
	if err != nil {
		t.Fatal(err)
	}
	status, response = mvpJSONRequest(t, api.URL, http.MethodPost,
		"/v1/profiles/"+profileID+"/declaration/preview",
		apiv1.ProfileDeclarationPreviewRequest{
			SnapshotID: *refreshed.CurrentSnapshotID, ExpectedDeclarationRevision: base.Revision,
		})
	if status != http.StatusOK || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("profile preview status=%d or leaked credentials", status)
	}
	var preview apiv1.ProfileDeclarationPreviewResponse
	if err := json.Unmarshal(response, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.RetainedNodeCount != 1 || len(preview.RetainedNodeIDs) != 1 ||
		preview.RetainedNodeIDs[0] != nodeID ||
		preview.AddedNodeCount != 0 || preview.RemovedNodeCount != 0 ||
		preview.SourceRevision != created.Revision || preview.CandidateSHA256 == base.SHA256 ||
		preview.CoreValidated || preview.Applied {
		t.Fatalf("unsafe profile snapshot preview: %+v", preview)
	}
	stageReceipt := apiv1.ProfileDeclarationStageRequest{
		SnapshotID:                  *refreshed.CurrentSnapshotID,
		ExpectedSourceRevision:      preview.SourceRevision,
		ExpectedDeclarationRevision: base.Revision,
		CandidateSHA256:             preview.CandidateSHA256,
		RuntimeOverlaySHA256:        preview.RuntimeOverlaySHA256,
	}
	status, response = mvpJSONRequest(t, api.URL, http.MethodPost, "/v1/profiles/"+profileID+"/declaration/stage", stageReceipt)
	if status != http.StatusCreated || bytes.Contains(response, []byte(secret)) {
		t.Fatalf("stage status=%d or exposed source credentials", status)
	}
	var staged apiv1.ProfileDeclarationStageResponse
	if err := json.Unmarshal(response, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.DeclarationRevision != base.Revision+1 ||
		staged.DeclarationSHA256 != preview.CandidateSHA256 || staged.Applied {
		t.Fatalf("staged revision not bound to imported node: %+v", staged)
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
	staleStatus, _ := mvpJSONRequest(t, api.URL, http.MethodPost, "/v1/profiles/"+profileID+"/declaration/stage", stageReceipt)
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
	assertRouteOutcomeSignal(t, proxyHits, 2*time.Second, "old upstream after bad refresh")
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
	assertRouteOutcomeSignal(t, proxyHits, 2*time.Second, "old upstream after restart")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "old target after restart")
	finalState, err := store.Snapshot(ctx)
	if err != nil || finalState.AppliedGenerationID == nil ||
		*finalState.AppliedGenerationID != applied.GenerationID ||
		finalState.LastKnownGoodGenerationID == nil || *finalState.LastKnownGoodGenerationID != applied.GenerationID {
		t.Fatalf("restart changed LKG generation: %+v %v", finalState, err)
	}
}

func mvpHTTPBaseDeclaration(profileID, nodeID string) []byte {
	return []byte(fmt.Sprintf(`{
		"schema_version":1,"log_level":"warn",
		"nodes":[{"profile_id":%q,"node_id":%q,"type":"http","server":"127.0.0.1","port":1,"http":{}}],
		"selection":{"current":{"members":[{"kind":"specific_node","profile_id":%q,"node_id":%q}],
			"default":{"kind":"specific_node","profile_id":%q,"node_id":%q}},"custom":[]},
		"routing":{"custom":[],"geosite":[],"geoip":[],"acl":[],"final":{"kind":"current_selected"}},
		"dns":{"profiles":[{"id":"mvp-dns","role":"outbound","transport":"udp",
			"server":"127.0.0.1","port":9}],"outbound_profile_id":"mvp-dns"}
	}`, profileID, nodeID, profileID, nodeID, profileID, nodeID))
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
