//go:build integration && linux

package daemon

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
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

// MVP-1C/1D: a real pinned Core client, from a user-imported Trojan URI
// through first-run preview/stage, explicit Core Check/Apply, TCP-over-TLS,
// verified password and a loopback echo. No external routing/CN/TUN is involved.
func TestManagedCoreRealMVPImportedTrojanTLSFlow(t *testing.T) {
	assertOrdinaryUserCoreEnvironment(t)
	corePath := os.Getenv("KARING_TUI_TEST_CORE")
	if corePath == "" {
		t.Skip("KARING_TUI_TEST_CORE is not set")
	}
	const profileID = "mvp-trojan-real"
	target, targetHits, closeTarget := startRouteOutcomeTarget(t)
	defer closeTarget()
	trojan, rootCert, upstreamHits, closeTrojan := startMVPLocalTrojanTLS(t, target)
	defer closeTrojan()
	// The pinned Core is a separate child process. Its normal TLS verifier
	// must trust only this temporary local fixture certificate, NOT skip
	// verification through an insecure=true outbound setting.
	t.Setenv("SSL_CERT_FILE", rootCert)

	var broken atomic.Bool
	sourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if broken.Load() {
			_, _ = fmt.Fprintf(w,
				"trojan://%s@127.0.0.1:%d?security=reality&type=grpc#Rejected\n",
				mvpTrojanSecret, trojan.Port())
			return
		}
		_, _ = fmt.Fprintf(w,
			"trojan://%s@127.0.0.1:%d?security=tls&type=tcp&sni=%s#Imported\n",
			mvpTrojanSecret, trojan.Port(), mvpTrojanServerName)
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
	const sourcePath = "/v1/profiles/" + profileID
	source := apiv1.ProfileSourceSpec{
		Format: "uri-list", LocationKind: "url", Location: sourceServer.URL,
		Enabled: true, Fetch: apiv1.ProfileSourceFetchPolicy{Mode: "direct"},
	}
	status, reply := mvpJSONRequest(t, api.URL, http.MethodPut, sourcePath,
		apiv1.ProfileSourcePutRequest{Source: source})
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("Trojan URI source creation rejected or leaked identity: status %d", status)
	}
	var created apiv1.ProfileSourceResponse
	if err := json.Unmarshal(reply, &created); err != nil {
		t.Fatal(err)
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost, sourcePath+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpTrojanSecret)) {
		t.Fatalf("Trojan URI source refresh rejected or leaked identity: status %d", status)
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

func assertMVPLocalTrojanRejectsBadPassword(t *testing.T, endpoint netip.AddrPort, caPath string, target netip.AddrPort) {
	t.Helper()
	certificate, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certificate) {
		t.Fatal("Trojan test certificate cannot be trusted")
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", endpoint.String(), &tls.Config{
		MinVersion: tls.VersionTLS12, ServerName: mvpTrojanServerName, RootCAs: pool,
	})
	if err != nil {
		t.Fatalf("Trojan negative-auth TLS handshake failed: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	// Valid-looking 56-hex-digit SHA224 header, but for the WRONG password.
	wrong := bytes.Repeat([]byte{'0'}, 56)
	frame := append(wrong, '\r', '\n', 0x01, 0x01)
	address := target.Addr().As4()
	frame = append(frame, address[:]...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], target.Port())
	frame = append(frame, port[:]...)
	frame = append(frame, '\r', '\n')
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	var marker [1]byte
	n, readErr := conn.Read(marker[:])
	if n != 0 || readErr == nil {
		t.Fatal("invalid Trojan password unexpectedly accepted a tunnel")
	}
}
