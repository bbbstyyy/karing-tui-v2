//go:build integration && linux

package daemon

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestManagedCoreRealRoutingModes(t *testing.T) {
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

	proxyAddress, proxyHits, closeProxy := startRejectingHTTPProxy(t)
	defer closeProxy()
	blockedAddress, blockedHits, closeBlocked := startRouteOutcomeTarget(t)
	defer closeBlocked()
	privateAddress, privateHits, closePrivate := startRouteOutcomeTarget(t)
	defer closePrivate()

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
	schemaCompiler, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       inbounds,
		ControlAddress: netip.AddrPortFrom(inbounds.Listen, ports[3]),
		ControlSecret:  secret,
	})
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := NewDeclarationCompileCoordinator(store, schemaCompiler)
	if err != nil {
		t.Fatal(err)
	}
	runtime, runDone, runCancel, err := startServerRuntimeWithDeclarations(context.Background(), store, managed, declarations)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		runCancel()
		select {
		case err := <-runDone:
			if err != nil {
				t.Errorf("routing-mode supervisor shutdown: %v; stderr=%s", err, managed.StderrTail())
			}
		case <-time.After(5 * time.Second):
			t.Errorf("routing-mode supervisor did not shut down")
		}
	}()

	committed, err := store.CommitDeclaration(
		ctx,
		0,
		routingModeDeclaration(proxyAddress.Port(), blockedAddress.Port()),
		"integration:routing-modes-private-direct",
	)
	if err != nil {
		t.Fatal(err)
	}
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 40*time.Second)
	_, _, err = runtime.ApplyDeclarationRevision(applyCtx, committed.Revision, 0)
	applyCancel()
	if err != nil {
		t.Fatalf("apply routing-mode declaration: %v; stderr=%s", err, managed.StderrTail())
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start routing-mode generation: %v; stderr=%s", err, managed.StderrTail())
	}
	startCancel()
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})

	mode, err := NewRoutingModeCoordinator(store, runtime)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := mode.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Mode != storage.RoutingModeRule || initial.PrivateDirect ||
		!initial.Applied || initial.LiveMode != storage.RoutingModeRule ||
		initial.LivePrivateDirect == nil || *initial.LivePrivateDirect {
		t.Fatalf("initial routing policy = %+v", initial)
	}

	ruleAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)
	directAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.DirectPort)
	selectedAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.SelectedPort)

	// Rule + privateDirect=false falls through to FINAL CurrentSelected.
	assertRoutingModeProxyReject(
		t, ruleAddress, privateAddress, privateHits, proxyHits, managed,
		"Rule/privateDirect=false private target",
	)

	// Turn privateDirect on without changing public Rule mode.
	privateOn := true
	switchCtx, switchCancel := context.WithTimeout(context.Background(), 5*time.Second)
	rulePrivate, err := mode.SetPolicy(switchCtx, storage.RoutingModeRule, &privateOn)
	switchCancel()
	if err != nil {
		t.Fatalf("enable privateDirect in Rule mode: %v; stderr=%s", err, managed.StderrTail())
	}
	if !rulePrivate.Applied || !rulePrivate.PrivateDirect ||
		rulePrivate.LiveMode != storage.RoutingModeRule ||
		rulePrivate.LivePrivateDirect == nil || !*rulePrivate.LivePrivateDirect {
		t.Fatalf("Rule/privateDirect=true state = %+v", rulePrivate)
	}
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(privateHits)
	assertRoutingModeDirectReach(
		t, ruleAddress, privateAddress, privateHits, proxyHits, managed,
		"Rule/privateDirect=true private target",
	)

	// L1 custom BLOCK still wins before Rule privateDirect.
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(blockedHits)
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := socks5Connect(connectCtx, ruleAddress, blockedAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("Rule privateDirect unexpectedly bypassed L1 BLOCK")
	}
	assertNoRouteOutcomeSignal(t, blockedHits, 150*time.Millisecond, "Rule privateDirect blocked target")
	assertNoRouteOutcomeSignal(t, proxyHits, 150*time.Millisecond, "Rule privateDirect blocked proxy")

	// Global + privateDirect=false bypasses the five-layer tree through CurrentSelected.
	privateOff := false
	switchCtx, switchCancel = context.WithTimeout(context.Background(), 5*time.Second)
	globalNoPrivate, err := mode.SetPolicy(switchCtx, storage.RoutingModeGlobal, &privateOff)
	switchCancel()
	if err != nil {
		t.Fatalf("switch to Global/privateDirect=false: %v; stderr=%s", err, managed.StderrTail())
	}
	if !globalNoPrivate.Applied || globalNoPrivate.PrivateDirect ||
		globalNoPrivate.LiveMode != storage.RoutingModeGlobal ||
		globalNoPrivate.LivePrivateDirect == nil || *globalNoPrivate.LivePrivateDirect {
		t.Fatalf("Global/privateDirect=false state = %+v", globalNoPrivate)
	}
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(privateHits)
	assertRoutingModeProxyReject(
		t, ruleAddress, privateAddress, privateHits, proxyHits, managed,
		"Global/privateDirect=false private target",
	)

	// Repeated upstream/proxy failures are data-plane failures, not core-process
	// failures. They must not consume the supervisor restart budget.
	stable := managed.Snapshot()
	for attempt := 0; attempt < 4; attempt++ {
		drainRouteOutcomeSignal(proxyHits)
		drainRouteOutcomeSignal(privateHits)
		assertRoutingModeProxyReject(
			t,
			ruleAddress,
			privateAddress,
			privateHits,
			proxyHits,
			managed,
			fmt.Sprintf("Global external failure %d", attempt+1),
		)
	}
	afterExternalFailure := managed.Snapshot()
	if afterExternalFailure.State != core.StateRunning ||
		afterExternalFailure.PID != stable.PID ||
		afterExternalFailure.ConsecutiveFails != stable.ConsecutiveFails ||
		afterExternalFailure.CircuitOpen != stable.CircuitOpen {
		t.Fatalf(
			"external proxy failures disturbed core supervisor: before=%+v after=%+v",
			stable,
			afterExternalFailure,
		)
	}

	// Enabling privateDirect while staying Global makes the same private target DIRECT.
	switchCtx, switchCancel = context.WithTimeout(context.Background(), 5*time.Second)
	globalPrivate, err := mode.SetPolicy(switchCtx, "", &privateOn)
	switchCancel()
	if err != nil {
		t.Fatalf("enable privateDirect in Global mode: %v; stderr=%s", err, managed.StderrTail())
	}
	if !globalPrivate.Applied || globalPrivate.Mode != storage.RoutingModeGlobal ||
		!globalPrivate.PrivateDirect || globalPrivate.LivePrivateDirect == nil ||
		!*globalPrivate.LivePrivateDirect {
		t.Fatalf("Global/privateDirect=true state = %+v", globalPrivate)
	}
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(privateHits)
	assertRoutingModeDirectReach(
		t, ruleAddress, privateAddress, privateHits, proxyHits, managed,
		"Global/privateDirect=true private target",
	)

	// Direct inbound remains an explicit bypass even while the Rule entry is Global.
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(blockedHits)
	assertRoutingModeDirectReach(
		t, directAddress, blockedAddress, blockedHits, proxyHits, managed,
		"Direct inbound under Global mode",
	)

	// Direct mode bypasses the Rule tree regardless of the retained privateDirect preference.
	switchCtx, switchCancel = context.WithTimeout(context.Background(), 5*time.Second)
	directMode, err := mode.SetPolicy(switchCtx, storage.RoutingModeDirect, &privateOff)
	switchCancel()
	if err != nil {
		t.Fatalf("switch to Direct mode: %v; stderr=%s", err, managed.StderrTail())
	}
	if !directMode.Applied || directMode.LiveMode != storage.RoutingModeDirect ||
		directMode.PrivateDirect || directMode.LivePrivateDirect == nil || *directMode.LivePrivateDirect {
		t.Fatalf("Direct mode state = %+v", directMode)
	}
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(blockedHits)
	assertRoutingModeDirectReach(
		t, ruleAddress, blockedAddress, blockedHits, proxyHits, managed,
		"Rule inbound in Direct mode",
	)

	// Selected inbound remains bound to CurrentSelected in Direct mode.
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(privateHits)
	assertRoutingModeProxyReject(
		t, selectedAddress, privateAddress, privateHits, proxyHits, managed,
		"Selected inbound under Direct mode",
	)

	// Persist Global/privateDirect=true, restart the same generation, and require exact readback.
	switchCtx, switchCancel = context.WithTimeout(context.Background(), 5*time.Second)
	if _, err := mode.SetPolicy(switchCtx, storage.RoutingModeGlobal, &privateOn); err != nil {
		switchCancel()
		t.Fatalf("persist Global/privateDirect=true before restart: %v", err)
	}
	switchCancel()

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatalf("stop routing-mode core: %v", err)
	}
	stopCancel()
	waitManagedCoreState(t, managed, 3*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateStopped && snapshot.PID == 0
	})

	restartCtx, restartCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(restartCtx); err != nil {
		restartCancel()
		t.Fatalf("restart routing-mode generation: %v; stderr=%s", err, managed.StderrTail())
	}
	restartCancel()
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})

	restored, err := mode.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if restored.Mode != storage.RoutingModeGlobal || !restored.PrivateDirect ||
		!restored.Applied || restored.LiveMode != storage.RoutingModeGlobal ||
		restored.LivePrivateDirect == nil || !*restored.LivePrivateDirect {
		t.Fatalf("restored routing policy = %+v", restored)
	}
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(privateHits)
	assertRoutingModeDirectReach(
		t, ruleAddress, privateAddress, privateHits, proxyHits, managed,
		"restored Global/privateDirect=true private target",
	)

	finalStopCtx, finalStopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(finalStopCtx); err != nil {
		finalStopCancel()
		t.Fatalf("final stop routing-mode core: %v", err)
	}
	finalStopCancel()
}

func assertRoutingModeProxyReject(
	t *testing.T,
	inbound netip.AddrPort,
	target netip.AddrPort,
	targetHits <-chan struct{},
	proxyHits <-chan struct{},
	managed *ManagedCore,
	label string,
) {
	t.Helper()
	connectCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := socks5Connect(connectCtx, inbound, target)
	cancel()
	if err == nil {
		_ = conn.Close()
		t.Fatalf("%s unexpectedly avoided rejecting CurrentSelected proxy", label)
	}
	assertRouteOutcomeSignal(t, proxyHits, 2*time.Second, label+" proxy")
	assertNoRouteOutcomeSignal(t, targetHits, 150*time.Millisecond, label+" target")
}

func assertRoutingModeDirectReach(
	t *testing.T,
	inbound netip.AddrPort,
	target netip.AddrPort,
	targetHits <-chan struct{},
	proxyHits <-chan struct{},
	managed *ManagedCore,
	label string,
) {
	t.Helper()
	connectCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := socks5Connect(connectCtx, inbound, target)
	cancel()
	if err != nil {
		t.Fatalf("%s did not reach target: %v; stderr=%s", label, err, managed.StderrTail())
	}
	var marker [2]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read %s marker: %v", label, err)
	}
	_ = conn.Close()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("%s marker = %q", label, marker)
	}
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, label+" target")
	assertNoRouteOutcomeSignal(t, proxyHits, 150*time.Millisecond, label+" proxy")
}

func routingModeDeclaration(proxyPort, blockedPort uint16) []byte {
	return []byte(fmt.Sprintf(`{
  "schema_version":1,
  "log_level":"warn",
  "nodes":[{
    "profile_id":"routing-mode-profile",
    "node_id":"selected",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{
        "kind":"specific_node",
        "profile_id":"routing-mode-profile",
        "node_id":"selected"
      }],
      "default":{
        "kind":"specific_node",
        "profile_id":"routing-mode-profile",
        "node_id":"selected"
      }
    },
    "custom":[]
  },
  "routing":{
    "custom":[{
      "id":"block-mode-target",
      "order":1,
      "enabled":true,
      "target":{"kind":"block"},
      "match":{
        "op":"atom",
        "predicate":{"kind":"port","port":{"start":%d,"end":%d}}
      }
    }],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":{"kind":"current_selected"}
  },
  "dns":{
    "profiles":[{
      "id":"outbound",
      "role":"outbound",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":9
    }],
    "outbound_profile_id":"outbound"
  }
}`, proxyPort, blockedPort, blockedPort))
}
