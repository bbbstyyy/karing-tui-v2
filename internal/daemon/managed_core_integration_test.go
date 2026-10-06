//go:build integration && linux

package daemon

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestManagedCoreRealIntegration(t *testing.T) {
	corePath := os.Getenv("KARING_TUI_TEST_CORE")
	if corePath == "" {
		t.Skip("KARING_TUI_TEST_CORE is not set")
	}

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
		Listen:       netip.MustParseAddr("127.0.0.1"),
		RulePort:     ports[0],
		DirectPort:   ports[1],
		SelectedPort: ports[2],
	}
	const secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	controlEndpoint := fmt.Sprintf("http://127.0.0.1:%d", ports[3])

	policy := core.DefaultPolicy()
	policy.InitialBackoff = 50 * time.Millisecond
	policy.MaxBackoff = 200 * time.Millisecond
	policy.FailureWindow = 10 * time.Second
	policy.MaxFailures = 4
	policy.ReadyTimeout = 5 * time.Second
	policy.StopTimeout = 3 * time.Second

	managed, err := NewManagedCore(store, ManagedCoreOptions{
		Executable:      corePath,
		StateRoot:       filepath.Join(stateDir, "core"),
		ControlEndpoint: controlEndpoint,
		ControlSecret:   secret,
		Inbounds:        inbounds,
		Policy:          policy,
		LogCapacity:     64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	runtime, runDone, runCancel, err := startServerRuntime(context.Background(), store, managed)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		runCancel()
		select {
		case err := <-runDone:
			if err != nil {
				t.Errorf("managed core supervisor shutdown: %v; stderr=%s", err, managed.StderrTail())
			}
		case <-time.After(5 * time.Second):
			t.Errorf("managed core supervisor did not shut down")
		}
	}()
	if !runtime.ManagedApplyReady() {
		t.Fatal("managed apply runtime was not composed")
	}

	firstArtifact := integrationCoreArtifact(t, inbounds, ports[3], secret, "warn")
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 40*time.Second)
	firstAttempt, err := runtime.ApplyNativeArtifact(applyCtx, 0, firstArtifact)
	applyCancel()
	if err != nil {
		t.Fatalf("first real-core apply: %v; stderr=%s", err, managed.StderrTail())
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != firstAttempt.GenerationID {
		t.Fatalf("first apply did not commit expected state: %+v", snapshot)
	}
	if got := managed.Snapshot(); got.State != core.StateStopped || got.DesiredRunning {
		t.Fatalf("apply while stopped did not restore stopped intent: %+v", got)
	}
	firstGeneration, err := store.GenerationArtifacts(ctx, firstAttempt.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstGeneration.ManifestJSON) == 0 || firstGeneration.ManifestSHA256 == "" ||
		len(firstGeneration.SourceMapJSON) == 0 || firstGeneration.SourceMapSHA256 == "" {
		t.Fatalf("strict compiler apply did not persist metadata: %+v", firstGeneration)
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start committed generation: %v; stderr=%s", err, managed.StderrTail())
	}
	startCancel()
	running := waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})
	firstPID := running.PID

	if err := syscall.Kill(-firstPID, syscall.SIGKILL); err != nil {
		t.Fatalf("crash owned core process group: %v", err)
	}
	restarted := waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0 && snapshot.PID != firstPID
	})
	if restarted.ConsecutiveFails == 0 {
		t.Fatalf("unexpected restart snapshot without recorded failure: %+v", restarted)
	}

	badConfig := []byte(`{"inbounds":[{"type":"definitely-invalid"}]}`)
	badCtx, badCancel := context.WithTimeout(context.Background(), 20*time.Second)
	_, badErr := runtime.ApplyCompiled(badCtx, 1, badConfig)
	badCancel()
	if badErr == nil {
		t.Fatal("invalid candidate unexpectedly applied")
	}
	snapshot, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != firstAttempt.GenerationID {
		t.Fatalf("failed check changed confirmed generation: %+v", snapshot)
	}
	afterBad := managed.Snapshot()
	if afterBad.State != core.StateRunning || afterBad.PID != restarted.PID {
		t.Fatalf("failed pre-activation check disturbed running core: before=%+v after=%+v", restarted, afterBad)
	}

	secondArtifact := integrationCoreArtifact(t, inbounds, ports[3], secret, "error")
	secondCtx, secondCancel := context.WithTimeout(context.Background(), 40*time.Second)
	secondAttempt, err := runtime.ApplyNativeArtifact(secondCtx, 1, secondArtifact)
	secondCancel()
	if err != nil {
		t.Fatalf("second real-core apply: %v; stderr=%s", err, managed.StderrTail())
	}
	snapshot, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 2 || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != secondAttempt.GenerationID {
		t.Fatalf("second apply did not advance confirmed generation: %+v", snapshot)
	}
	afterSecond := managed.Snapshot()
	if afterSecond.State != core.StateRunning || afterSecond.PID <= 0 || afterSecond.PID == restarted.PID {
		t.Fatalf("second apply did not replace running generation: before=%+v after=%+v", restarted, afterSecond)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatalf("explicit stop: %v", err)
	}
	stopCancel()
	waitManagedCoreState(t, managed, 3*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateStopped && !snapshot.DesiredRunning && snapshot.PID == 0
	})
	time.Sleep(2 * policy.MaxBackoff)
	if got := managed.Snapshot(); got.State != core.StateStopped || got.DesiredRunning || got.PID != 0 {
		t.Fatalf("core restarted after explicit stop: %+v", got)
	}

	persisted, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.CoreDesiredState != storage.CoreDesiredStopped {
		t.Fatalf("explicit stop intent was not durable: %+v", persisted)
	}
	if persisted.RecoveryRequired {
		t.Fatalf("successful integration flow unexpectedly requires recovery: %+v", persisted)
	}
}

func reserveLoopbackPorts(t *testing.T, count int) []uint16 {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	ports := make([]uint16, 0, count)
	for i := 0; i < count; i++ {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		port := listener.Addr().(*net.TCPAddr).Port
		ports = append(ports, uint16(port))
	}
	for _, listener := range listeners {
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return ports
}

func integrationCoreArtifact(t *testing.T, inbounds domain.InboundSet, controlPort uint16, secret, logLevel string) compiler.NativeConfigArtifact {
	t.Helper()

	nodePort := uint16(9)
	if logLevel == "error" {
		nodePort = 10
	}
	node := domain.Node{
		ProfileID: "integration-profile",
		NodeID:    "integration-node",
		Kind:      domain.NodeHTTP,
		Server:    "integration-proxy.invalid",
		Port:      nodePort,
		HTTP:      &domain.HTTPNodeOptions{},
	}
	nodeKey := compiler.NodeTargetKey{ProfileID: node.ProfileID, NodeID: node.NodeID}
	targets, err := compiler.NewTargetCatalog(nil, []compiler.NodeTargetKey{nodeKey})
	if err != nil {
		t.Fatal(err)
	}
	nodeRef := domain.TargetRef{
		Kind:      domain.TargetSpecificNode,
		ProfileID: node.ProfileID,
		NodeID:    node.NodeID,
	}

	routing, err := compiler.CompileRouting(domain.RoutingPlan{
		Final: domain.TargetRef{Kind: domain.TargetDirect},
	}, targets)
	if err != nil {
		t.Fatal(err)
	}
	ruleSetCatalog, err := compiler.NewRuleSetCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := compiler.BindRuleSetArtifacts(routing, ruleSetCatalog)
	if err != nil {
		t.Fatal(err)
	}
	bound, err = compiler.BindStagedRuleSetPaths(bound, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}

	selection, err := compiler.CompileSelectionGroups(domain.SelectionPlan{
		Current: domain.CurrentSelection{
			Members: []domain.TargetRef{nodeRef},
			Default: nodeRef,
		},
	}, targets, routing.OutboundTags)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := compiler.CompileBasicNodeOutbounds([]domain.Node{node}, targets, selection.NodeTargets)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := compiler.CompileRuntimeDNS(domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{
				ID:        "integration-outbound-dns",
				Role:      domain.DNSRoleOutbound,
				Transport: domain.DNSTransportUDP,
				Server:    "127.0.0.1",
				Port:      9,
			},
			{
				ID:        "integration-direct-dns",
				Role:      domain.DNSRoleDirect,
				Transport: domain.DNSTransportUDP,
				Server:    "127.0.0.1",
				Port:      9,
			},
			{
				ID:        "integration-proxy-dns",
				Role:      domain.DNSRoleProxy,
				Transport: domain.DNSTransportUDP,
				Server:    "127.0.0.1",
				Port:      9,
			},
		},
		OutboundProfileID: "integration-outbound-dns",
		DirectProfileID:   "integration-direct-dns",
		ProxyProfileID:    "integration-proxy-dns",
	}, targets)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err = compiler.BindNodeDomainResolver(nodes, dns)
	if err != nil {
		t.Fatal(err)
	}
	bound, err = compiler.BindProxyTargetDNSRouting(bound, dns)
	if err != nil {
		t.Fatal(err)
	}

	artifact, err := compiler.CompileNativeConfig(compiler.NativeConfigInput{
		Inbounds:       inbounds,
		ControlAddress: netip.AddrPortFrom(inbounds.Listen, controlPort),
		ControlSecret:  secret,
		LogLevel:       logLevel,
		Targets:        targets,
		Routing:        bound,
		Selection:      selection,
		Nodes:          nodes,
		DNS:            dns,
	})
	if err != nil {
		t.Fatal(err)
	}
	declarationRevision := uint64(1)
	declarationSHA256 := "1111111111111111111111111111111111111111111111111111111111111111"
	if logLevel == "error" {
		declarationRevision = 2
		declarationSHA256 = "2222222222222222222222222222222222222222222222222222222222222222"
	}
	artifact, err = artifact.BindDeclaration(declarationRevision, declarationSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func waitManagedCoreState(t *testing.T, managed *ManagedCore, timeout time.Duration, accept func(core.Snapshot) bool) core.Snapshot {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		snapshot := managed.Snapshot()
		if accept(snapshot) {
			return snapshot
		}
		if snapshot.State == core.StateFailed {
			t.Fatalf("managed core entered failed state: %+v; stderr=%s", snapshot, managed.StderrTail())
		}
		time.Sleep(20 * time.Millisecond)
	}
	snapshot := managed.Snapshot()
	t.Fatalf("managed core state timeout: %+v; stderr=%s", snapshot, managed.StderrTail())
	return core.Snapshot{}
}
