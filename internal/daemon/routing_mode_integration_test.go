//go:build integration && linux

package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
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
	targetAddress, targetHits, closeTarget := startRouteOutcomeTarget(t)
	defer closeTarget()

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
		routingModeDeclaration(proxyAddress.Port(), targetAddress.Port()),
		"integration:routing-modes",
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
	if initial.Mode != storage.RoutingModeRule || !initial.Applied || initial.LiveMode != storage.RoutingModeRule {
		t.Fatalf("initial routing mode = %+v", initial)
	}

	ruleAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)
	directAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.DirectPort)
	selectedAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.SelectedPort)

	// Rule mode honors the configured BLOCK group.
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := socks5Connect(connectCtx, ruleAddress, targetAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("Rule mode unexpectedly bypassed BLOCK group")
	}
	assertNoRouteOutcomeSignal(t, targetHits, 150*time.Millisecond, "Rule mode direct target")
	assertNoRouteOutcomeSignal(t, proxyHits, 150*time.Millisecond, "Rule mode selected proxy")

	// Global mode bypasses the five-layer Rule tree through CurrentSelected.
	switchCtx, switchCancel := context.WithTimeout(context.Background(), 5*time.Second)
	global, err := mode.Set(switchCtx, storage.RoutingModeGlobal)
	switchCancel()
	if err != nil {
		t.Fatalf("switch to Global mode: %v; stderr=%s", err, managed.StderrTail())
	}
	if !global.Applied || global.LiveMode != storage.RoutingModeGlobal {
		t.Fatalf("Global mode state = %+v", global)
	}
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(targetHits)
	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5Connect(connectCtx, ruleAddress, targetAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("Global mode unexpectedly reached target through rejecting CurrentSelected proxy")
	}
	assertRouteOutcomeSignal(t, proxyHits, 2*time.Second, "Global mode CurrentSelected proxy")
	assertNoRouteOutcomeSignal(t, targetHits, 150*time.Millisecond, "Global mode direct target")

	// Direct entry remains an explicit bypass even while the Rule entry is Global.
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(targetHits)
	assertRoutingModeDirectReach(t, directAddress, targetAddress, targetHits, proxyHits, managed, "Direct inbound under Global mode")

	// Direct mode bypasses the Rule tree on the Rule entry.
	switchCtx, switchCancel = context.WithTimeout(context.Background(), 5*time.Second)
	directMode, err := mode.Set(switchCtx, storage.RoutingModeDirect)
	switchCancel()
	if err != nil {
		t.Fatalf("switch to Direct mode: %v; stderr=%s", err, managed.StderrTail())
	}
	if !directMode.Applied || directMode.LiveMode != storage.RoutingModeDirect {
		t.Fatalf("Direct mode state = %+v", directMode)
	}
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(targetHits)
	assertRoutingModeDirectReach(t, ruleAddress, targetAddress, targetHits, proxyHits, managed, "Rule inbound in Direct mode")

	// Selected entry remains bound to CurrentSelected even in Direct mode.
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(targetHits)
	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5Connect(connectCtx, selectedAddress, targetAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("Selected inbound unexpectedly followed Direct mode")
	}
	assertRouteOutcomeSignal(t, proxyHits, 2*time.Second, "Selected inbound under Direct mode")
	assertNoRouteOutcomeSignal(t, targetHits, 150*time.Millisecond, "Selected inbound direct target")

	// Persist Global, restart the same generation, and require exact readback.
	switchCtx, switchCancel = context.WithTimeout(context.Background(), 5*time.Second)
	if _, err := mode.Set(switchCtx, storage.RoutingModeGlobal); err != nil {
		switchCancel()
		t.Fatalf("persist Global mode before restart: %v", err)
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
	if restored.Mode != storage.RoutingModeGlobal || !restored.Applied ||
		restored.LiveMode != storage.RoutingModeGlobal {
		t.Fatalf("restored routing mode = %+v", restored)
	}
	drainRouteOutcomeSignal(proxyHits)
	drainRouteOutcomeSignal(targetHits)
	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5Connect(connectCtx, ruleAddress, targetAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("restored Global mode unexpectedly reached target")
	}
	assertRouteOutcomeSignal(t, proxyHits, 2*time.Second, "restored Global mode proxy")
	assertNoRouteOutcomeSignal(t, targetHits, 150*time.Millisecond, "restored Global mode direct target")

	finalStopCtx, finalStopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(finalStopCtx); err != nil {
		finalStopCancel()
		t.Fatalf("final stop routing-mode core: %v", err)
	}
	finalStopCancel()
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
    "final":{"kind":"direct"}
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
