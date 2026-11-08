//go:build integration && linux

package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
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

// MVP-1C: a real pinned Core client using a user-imported SIP002
// Shadowsocks aes-256-gcm URI, guarded first-run stage, checked Core Apply,
// authenticated AEAD TCP forwarding and a local echo. No external network,
// TUN, subscription routing or CN claims.
func TestManagedCoreRealMVPImportedShadowsocksAEADFlow(t *testing.T) {
	assertOrdinaryUserCoreEnvironment(t)
	corePath := os.Getenv("KARING_TUI_TEST_CORE")
	if corePath == "" {
		t.Skip("KARING_TUI_TEST_CORE is not set")
	}
	const profileID = "mvp-ss-real"
	target, targetHits, closeTarget := startRouteOutcomeTarget(t)
	defer closeTarget()
	ss, upstreamHits, closeSS := startMVPLocalShadowsocksAEAD(t, target)
	defer closeSS()

	var broken atomic.Bool
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(mvpSSMethod + ":" + mvpSSPassword))
	sourceServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if broken.Load() {
			_, _ = fmt.Fprintf(w, "ss://%s@127.0.0.1:%d?transport=grpc#Rejected\n", userinfo, ss.Port())
			return
		}
		_, _ = fmt.Fprintf(w, "ss://%s@127.0.0.1:%d#Imported\n", userinfo, ss.Port())
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
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpSSPassword)) {
		t.Fatalf("Shadowsocks URI source creation rejected or leaked identity: status %d", status)
	}
	var created apiv1.ProfileSourceResponse
	if err := json.Unmarshal(reply, &created); err != nil {
		t.Fatal(err)
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost, sourcePath+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpSSPassword)) {
		t.Fatalf("Shadowsocks URI source refresh rejected or leaked identity: status %d", status)
	}
	var refreshed apiv1.ProfileRefreshResponse
	if err := json.Unmarshal(reply, &refreshed); err != nil {
		t.Fatal(err)
	}
	if refreshed.NodeCount != 1 || refreshed.CurrentSnapshotID == nil {
		t.Fatal("Shadowsocks source did not produce one accepted snapshot")
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodGet, sourcePath+"/nodes", nil)
	var page apiv1.ProfileNodeListResponse
	if err := json.Unmarshal(reply, &page); err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || page.Total != 1 || len(page.Nodes) != 1 ||
		page.Nodes[0].Disabled || page.Nodes[0].NodeID == "" {
		t.Fatal("Shadowsocks imported node missing from user-visible accepted source")
	}
	nodeID := page.Nodes[0].NodeID
	init := apiv1.InitialProfileDeclarationPreviewRequest{
		SnapshotID:      *refreshed.CurrentSnapshotID,
		SelectedNodeID:  nodeID,
		ResolverAddress: "127.0.0.1:9",
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost,
		sourcePath+"/declaration/initial/preview", init)
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpSSPassword)) {
		t.Fatalf("Shadowsocks first-run preview rejected or leaked identity: status %d", status)
	}
	var preview apiv1.InitialProfileDeclarationPreviewResponse
	if err := json.Unmarshal(reply, &preview); err != nil {
		t.Fatal(err)
	}
	if preview.SourceRevision != created.Revision ||
		preview.SelectedNodeID != nodeID || preview.EffectiveNodeCount != 1 ||
		preview.BaseDeclarationRevision != 0 || preview.CNRulesReady ||
		preview.CoreValidated || preview.Applied || len(preview.CandidateSHA256) != 64 {
		t.Fatalf("invalid Shadowsocks initial preview: %+v", preview)
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
	if status != http.StatusCreated || bytes.Contains(reply, []byte(mvpSSPassword)) {
		t.Fatalf("Shadowsocks first-run stage rejected or leaked identity: status %d", status)
	}
	var staged apiv1.InitialProfileDeclarationStageResponse
	if err := json.Unmarshal(reply, &staged); err != nil {
		t.Fatal(err)
	}
	if staged.DeclarationRevision != 1 ||
		staged.DeclarationSHA256 != preview.CandidateSHA256 ||
		staged.CNRulesReady || staged.Applied || staged.CoreValidated {
		t.Fatal("Shadowsocks stage did not preserve explicit no-CN/no-apply state")
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodGet, "/v1/config/apply/preview", nil)
	if status != http.StatusOK {
		t.Fatalf("Shadowsocks checked apply preview rejected: %d", status)
	}
	var applyPreview apiv1.CheckedApplyPreviewResponse
	if err := json.Unmarshal(reply, &applyPreview); err != nil {
		t.Fatal(err)
	}
	if !applyPreview.CompilerValidated || applyPreview.CoreValidated ||
		applyPreview.Applied || applyPreview.Receipt.DeclarationRevision != 1 {
		t.Fatal("Shadowsocks checked apply preview was not bound to the staged declaration")
	}
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost,
		"/v1/config/apply/confirm", applyPreview.Receipt)
	if status != http.StatusOK || bytes.Contains(reply, []byte(mvpSSPassword)) {
		t.Fatalf("Shadowsocks Core Check/Apply failed or leaked password: status %d stderr=%s", status, managed.StderrTail())
	}
	var applied apiv1.CheckedApplyResponse
	if err := json.Unmarshal(reply, &applied); err != nil {
		t.Fatal(err)
	}
	if !applied.CoreChecked || !applied.Verified || !applied.Applied ||
		applied.DeclarationRevision != staged.DeclarationRevision ||
		applied.ConfigSHA256 != applyPreview.Receipt.NativeConfigSHA256 {
		t.Fatalf("Shadowsocks approved Core did not commit authenticated generation: %+v", applied)
	}
	artifacts, err := store.GenerationArtifacts(ctx, applied.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(artifacts.ConfigJSON, []byte(mvpSSPassword)) ||
		!bytes.Contains(artifacts.ConfigJSON, []byte(mvpSSMethod)) ||
		!bytes.Contains(artifacts.ConfigJSON, []byte(`"type":"shadowsocks"`)) {
		t.Fatal("native Shadowsocks config omitted supported method, password or outbound type")
	}

	startCtx, cancelStart := context.WithTimeout(ctx, 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		cancelStart()
		t.Fatalf("Shadowsocks applied runtime failed to start: %v", err)
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
			t.Fatalf("Shadowsocks AEAD SOCKS tunnel refused: %v; core=%s", err, managed.StderrTail())
		}
		mvpAssertMarker(t, conn)
		disconnect()
		assertRouteOutcomeSignal(t, upstreamHits, 2*time.Second, "verified Shadowsocks AEAD/password upstream")
		assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "Shadowsocks tunneled echo")
	}
	mvpHTTPConnectMarker(t, rule, target)
	assertRouteOutcomeSignal(t, upstreamHits, 2*time.Second, "Shadowsocks through HTTP CONNECT")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "Shadowsocks CONNECT echo")

	connectCtx, disconnect := context.WithTimeout(ctx, 5*time.Second)
	conn, err := socks5Connect(connectCtx, direct, target)
	if err != nil {
		disconnect()
		t.Fatalf("DIRECT inbound refused: %v", err)
	}
	mvpAssertMarker(t, conn)
	disconnect()
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "DIRECT target")
	assertNoRouteOutcomeSignal(t, upstreamHits, 100*time.Millisecond, "DIRECT accidentally routed to Shadowsocks")

	// A valid AEAD peer must reject an unrecognized password even when transport
	// and target match; a rejected authorization cannot reach the target.
	assertMVPLocalShadowsocksRejectsBadPassword(t, ss, target)
	assertNoRouteOutcomeSignal(t, upstreamHits, 100*time.Millisecond, "wrong Shadowsocks password")
	assertNoRouteOutcomeSignal(t, targetHits, 100*time.Millisecond, "wrong password target")

	broken.Store(true)
	status, reply = mvpJSONRequest(t, api.URL, http.MethodPost, sourcePath+"/refresh",
		apiv1.ProfileRefreshRequest{ExpectedSourceRevision: created.Revision})
	if status != http.StatusUnprocessableEntity || bytes.Contains(reply, []byte(mvpSSPassword)) {
		t.Fatalf("unsupported Shadowsocks update was accepted or leaked password: status %d", status)
	}
	afterSource, err := store.ProfileSource(ctx, profileID)
	if err != nil || afterSource.CurrentSnapshotID == nil ||
		*afterSource.CurrentSnapshotID != *refreshed.CurrentSnapshotID ||
		afterSource.ConsecutiveFailures == 0 {
		t.Fatalf("bad Shadowsocks source replaced accepted snapshot: %v", err)
	}
	after, err := store.Snapshot(ctx)
	if err != nil || after.AppliedGenerationID == nil ||
		*after.AppliedGenerationID != applied.GenerationID ||
		after.LastKnownGoodGenerationID == nil ||
		*after.LastKnownGoodGenerationID != applied.GenerationID ||
		after.RecoveryRequired || after.ActiveAttemptID != nil {
		t.Fatalf("bad Shadowsocks source damaged LKG: %v", err)
	}
	status, _ = mvpJSONRequest(t, api.URL, http.MethodPost,
		sourcePath+"/declaration/initial/stage", receipt)
	if status != http.StatusConflict {
		t.Fatalf("Shadowsocks old initial stage replay was accepted: %d", status)
	}
	connectCtx, disconnect = context.WithTimeout(ctx, 5*time.Second)
	conn, err = socks5Connect(connectCtx, rule, target)
	if err != nil {
		disconnect()
		t.Fatalf("bad subscription disrupted active Shadowsocks tunnel: %v", err)
	}
	mvpAssertMarker(t, conn)
	disconnect()
	assertRouteOutcomeSignal(t, upstreamHits, 2*time.Second, "LKG Shadowsocks tunnel after bad refresh")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "LKG Shadowsocks echo after bad refresh")

	stopCtx, cancelStop := context.WithTimeout(ctx, 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		cancelStop()
		t.Fatal(err)
	}
	cancelStop()
	restartCtx, cancelRestart := context.WithTimeout(ctx, 15*time.Second)
	if err := runtime.Start(restartCtx); err != nil {
		cancelRestart()
		t.Fatalf("offline Shadowsocks restart failed: %v", err)
	}
	cancelRestart()
	waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	connectCtx, disconnect = context.WithTimeout(ctx, 5*time.Second)
	conn, err = socks5Connect(connectCtx, rule, target)
	if err != nil {
		disconnect()
		t.Fatalf("Shadowsocks LKG lost real traffic after restart: %v", err)
	}
	mvpAssertMarker(t, conn)
	disconnect()
	assertRouteOutcomeSignal(t, upstreamHits, 2*time.Second, "post-restart Shadowsocks AEAD tunnel")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "post-restart Shadowsocks echo")
}

func assertMVPLocalShadowsocksRejectsBadPassword(t *testing.T, endpoint netip.AddrPort, target netip.AddrPort) {
	t.Helper()
	conn, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp4", endpoint.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	var salt [mvpSSKeySize]byte
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatal(err)
	}
	ip := target.Addr().As4()
	header := append([]byte{0x01}, ip[:]...)
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], target.Port())
	header = append(header, port[:]...)
	frame, ok := mvpSSEncryptedFrame(mvpSSMasterKey("WRONG_SHADOWSOCKS_PASSWORD"), salt[:], header)
	if !ok {
		t.Fatal("cannot prepare negative-auth Shadowsocks frame")
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatal(err)
	}
	var marker [1]byte
	n, readErr := conn.Read(marker[:])
	if n != 0 || readErr == nil {
		t.Fatal("invalid Shadowsocks key unexpectedly obtained an authenticated tunnel")
	}
}
