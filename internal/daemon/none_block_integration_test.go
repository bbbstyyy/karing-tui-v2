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

func TestManagedCoreRealNoneBlockFinalSemantics(t *testing.T) {
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

	proxyAddress, _, proxyHits, closeProxy := startTargetOutcomeHTTPProxy(t, "unused.invalid:4", true)
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
				t.Errorf("NONE/BLOCK supervisor shutdown: %v; stderr=%s", err, managed.StderrTail())
			}
		case <-time.After(5 * time.Second):
			t.Errorf("NONE/BLOCK supervisor did not shut down")
		}
	}()

	declarationRevision := uint64(0)
	configRevision := uint64(0)
	apply := func(source string, blockEnabled, proxyEnabled bool) {
		t.Helper()
		document := noneBlockFinalDeclaration(
			proxyAddress.Port(),
			targetAddress.Port(),
			blockEnabled,
			proxyEnabled,
		)
		committed, err := store.CommitDeclaration(
			ctx,
			declarationRevision,
			document,
			"integration:none-block-"+source,
		)
		if err != nil {
			t.Fatal(err)
		}
		applyCtx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		attempt, _, err := runtime.ApplyDeclarationRevision(applyCtx, committed.Revision, configRevision)
		cancel()
		if err != nil {
			t.Fatalf("apply NONE/BLOCK %s declaration: %v; stderr=%s", source, err, managed.StderrTail())
		}
		declarationRevision = committed.Revision
		configRevision = attempt.TargetRevision
	}

	apply("none", false, true)
	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start NONE/BLOCK generation: %v; stderr=%s", err, managed.StderrTail())
	}
	startCancel()
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})

	ruleAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)
	assertNoneBlockProxyOutcome(t, ruleAddress, targetAddress, targetHits, proxyHits, managed)

	apply("block", true, true)
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})
	drainFiveLayerSignals(targetHits, proxyHits)
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := socks5Connect(connectCtx, ruleAddress, targetAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("enabled BLOCK group unexpectedly fell through")
	}
	assertNoRouteOutcomeSignal(t, proxyHits, 150*time.Millisecond, "BLOCK downstream proxy")
	assertNoRouteOutcomeSignal(t, targetHits, 150*time.Millisecond, "BLOCK target")

	apply("final", false, false)
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})
	drainFiveLayerSignals(targetHits, proxyHits)
	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5Connect(connectCtx, ruleAddress, targetAddress)
	connectCancel()
	if err != nil {
		t.Fatalf("disabled groups did not fall through to FINAL/DIRECT: %v; stderr=%s", err, managed.StderrTail())
	}
	var marker [2]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read FINAL/DIRECT marker: %v", err)
	}
	_ = conn.Close()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("FINAL/DIRECT marker = %q", marker)
	}
	assertNoRouteOutcomeSignal(t, proxyHits, 150*time.Millisecond, "FINAL/DIRECT proxy")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "FINAL/DIRECT target")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatalf("stop NONE/BLOCK core: %v", err)
	}
	stopCancel()
	waitManagedCoreState(t, managed, 3*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateStopped && snapshot.PID == 0
	})
}

func assertNoneBlockProxyOutcome(
	t *testing.T,
	inbound netip.AddrPort,
	target netip.AddrPort,
	targetHits <-chan struct{},
	proxyHits <-chan struct{},
	managed *ManagedCore,
) {
	t.Helper()
	drainFiveLayerSignals(targetHits, proxyHits)
	connectCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	conn, err := socks5Connect(connectCtx, inbound, target)
	cancel()
	if err != nil {
		t.Fatalf("disabled/NONE group did not continue to next proxy group: %v; stderr=%s", err, managed.StderrTail())
	}
	var marker [2]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read NONE fallthrough target marker: %v", err)
	}
	_ = conn.Close()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("NONE fallthrough target marker = %q", marker)
	}
	assertRouteOutcomeSignal(t, proxyHits, 2*time.Second, "NONE fallthrough proxy")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "NONE fallthrough target")
}

func noneBlockFinalDeclaration(
	proxyPort uint16,
	targetPort uint16,
	blockEnabled bool,
	proxyEnabled bool,
) []byte {
	return []byte(fmt.Sprintf(`{
  "schema_version":1,
  "log_level":"warn",
  "nodes":[{
    "profile_id":"none-block",
    "node_id":"proxy",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{
        "kind":"specific_node",
        "profile_id":"none-block",
        "node_id":"proxy"
      }],
      "default":{
        "kind":"specific_node",
        "profile_id":"none-block",
        "node_id":"proxy"
      }
    },
    "custom":[]
  },
  "routing":{
    "custom":[{
      "id":"maybe-block",
      "order":1,
      "enabled":%t,
      "target":{"kind":"block"},
      "match":{"op":"atom","predicate":{"kind":"port","port":{"start":%d,"end":%d}}}
    },{
      "id":"next-proxy",
      "order":2,
      "enabled":%t,
      "target":{"kind":"specific_node","profile_id":"none-block","node_id":"proxy"},
      "match":{"op":"atom","predicate":{"kind":"port","port":{"start":%d,"end":%d}}}
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
}`,
		proxyPort,
		blockEnabled,
		targetPort,
		targetPort,
		proxyEnabled,
		targetPort,
		targetPort,
	))
}
