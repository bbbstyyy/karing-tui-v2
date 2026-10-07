//go:build integration && linux

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestManagedCoreRealFiveLayerPrecedence(t *testing.T) {
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

	proxyA, _, proxyAHits, closeProxyA := startTargetOutcomeHTTPProxy(t, "unused.invalid:1", true)
	defer closeProxyA()
	proxyB, _, proxyBHits, closeProxyB := startTargetOutcomeHTTPProxy(t, "unused.invalid:2", true)
	defer closeProxyB()
	proxyC, _, proxyCHits, closeProxyC := startTargetOutcomeHTTPProxy(t, "unused.invalid:3", true)
	defer closeProxyC()
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

	ruleSets, err := coreartifact.NewStore(filepath.Join(stateDir, "core"))
	if err != nil {
		t.Fatal(err)
	}
	ruleSetContent := []byte(`{"version":4,"rules":[{"ip_cidr":["127.0.0.1/32"]}]}`)
	ruleSetSHA256 := fmt.Sprintf("%x", sha256.Sum256(ruleSetContent))
	if _, _, err := ruleSets.PutRuleSet(ctx, bytes.NewReader(ruleSetContent), ruleSetSHA256, "source"); err != nil {
		t.Fatal(err)
	}

	schemaCompiler, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       inbounds,
		ControlAddress: netip.AddrPortFrom(inbounds.Listen, ports[3]),
		ControlSecret:  secret,
		RuleSets:       ruleSets,
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
				t.Errorf("five-layer supervisor shutdown: %v; stderr=%s", err, managed.StderrTail())
			}
		case <-time.After(5 * time.Second):
			t.Errorf("five-layer supervisor did not shut down")
		}
	}()

	declarationRevision := uint64(0)
	configRevision := uint64(0)
	apply := func(name string, customEnabled, geositeEnabled, geoIPEnabled, aclEnabled bool) {
		t.Helper()
		document := fiveLayerDeclaration(
			ruleSetSHA256,
			proxyA.Port(),
			proxyB.Port(),
			proxyC.Port(),
			targetAddress.Port(),
			customEnabled,
			geositeEnabled,
			geoIPEnabled,
			aclEnabled,
		)
		committed, err := store.CommitDeclaration(
			ctx,
			declarationRevision,
			document,
			"integration:five-layer-"+name,
		)
		if err != nil {
			t.Fatal(err)
		}
		applyCtx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		attempt, _, err := runtime.ApplyDeclarationRevision(applyCtx, committed.Revision, configRevision)
		cancel()
		if err != nil {
			t.Fatalf("apply five-layer %s declaration: %v; stderr=%s", name, err, managed.StderrTail())
		}
		declarationRevision = committed.Revision
		configRevision = attempt.TargetRevision
	}

	apply("custom", true, true, true, true)
	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start five-layer generation: %v; stderr=%s", err, managed.StderrTail())
	}
	startCancel()
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})

	ruleAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)
	assertFiveLayerProxyOutcome(
		t, "Custom L1 geoip-prefixed rule-set", ruleAddress, targetAddress, targetHits,
		proxyAHits, proxyBHits, proxyCHits, managed,
	)

	apply("geosite", false, true, true, true)
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})
	assertFiveLayerProxyOutcome(
		t, "GeoSite L2", ruleAddress, targetAddress, targetHits,
		proxyBHits, proxyAHits, proxyCHits, managed,
	)

	apply("geoip", false, false, true, true)
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})
	assertFiveLayerProxyOutcome(
		t, "GeoIP L3", ruleAddress, targetAddress, targetHits,
		proxyCHits, proxyAHits, proxyBHits, managed,
	)

	apply("acl", false, false, false, true)
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})
	drainFiveLayerSignals(targetHits, proxyAHits, proxyBHits, proxyCHits)
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := socks5Connect(connectCtx, ruleAddress, targetAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("ACL L4 BLOCK unexpectedly allowed the five-layer request")
	}
	assertNoRouteOutcomeSignal(t, proxyAHits, 150*time.Millisecond, "ACL BLOCK proxy A")
	assertNoRouteOutcomeSignal(t, proxyBHits, 150*time.Millisecond, "ACL BLOCK proxy B")
	assertNoRouteOutcomeSignal(t, proxyCHits, 150*time.Millisecond, "ACL BLOCK proxy C")
	assertNoRouteOutcomeSignal(t, targetHits, 150*time.Millisecond, "ACL BLOCK target")

	apply("final", false, false, false, false)
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})
	drainFiveLayerSignals(targetHits, proxyAHits, proxyBHits, proxyCHits)
	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5Connect(connectCtx, ruleAddress, targetAddress)
	connectCancel()
	if err != nil {
		t.Fatalf("FINAL DIRECT did not reach target: %v; stderr=%s", err, managed.StderrTail())
	}
	var marker [2]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read FINAL DIRECT target marker: %v", err)
	}
	_ = conn.Close()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("FINAL DIRECT marker = %q", marker)
	}
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "FINAL DIRECT target")
	assertNoRouteOutcomeSignal(t, proxyAHits, 150*time.Millisecond, "FINAL DIRECT proxy A")
	assertNoRouteOutcomeSignal(t, proxyBHits, 150*time.Millisecond, "FINAL DIRECT proxy B")
	assertNoRouteOutcomeSignal(t, proxyCHits, 150*time.Millisecond, "FINAL DIRECT proxy C")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatalf("stop five-layer core: %v", err)
	}
	stopCancel()
	waitManagedCoreState(t, managed, 3*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateStopped && snapshot.PID == 0
	})
}

func assertFiveLayerProxyOutcome(
	t *testing.T,
	label string,
	inbound netip.AddrPort,
	target netip.AddrPort,
	targetHits <-chan struct{},
	expectedProxy <-chan struct{},
	otherProxyA <-chan struct{},
	otherProxyB <-chan struct{},
	managed *ManagedCore,
) {
	t.Helper()
	drainFiveLayerSignals(targetHits, expectedProxy, otherProxyA, otherProxyB)

	connectCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	conn, err := socks5Connect(connectCtx, inbound, target)
	cancel()
	if err != nil {
		t.Fatalf("%s did not reach target: %v; stderr=%s", label, err, managed.StderrTail())
	}
	var marker [2]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read %s target marker: %v", label, err)
	}
	_ = conn.Close()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("%s target marker = %q", label, marker)
	}
	assertRouteOutcomeSignal(t, expectedProxy, 2*time.Second, label+" expected proxy")
	assertNoRouteOutcomeSignal(t, otherProxyA, 150*time.Millisecond, label+" other proxy A")
	assertNoRouteOutcomeSignal(t, otherProxyB, 150*time.Millisecond, label+" other proxy B")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, label+" target")
}

func drainFiveLayerSignals(channels ...<-chan struct{}) {
	for _, ch := range channels {
		for {
			select {
			case <-ch:
			default:
				goto nextChannel
			}
		}
	nextChannel:
	}
}

func fiveLayerDeclaration(
	ruleSetSHA256 string,
	proxyAPort uint16,
	proxyBPort uint16,
	proxyCPort uint16,
	targetPort uint16,
	customEnabled bool,
	geositeEnabled bool,
	geoIPEnabled bool,
	aclEnabled bool,
) []byte {
	return []byte(fmt.Sprintf(`{
  "schema_version":1,
  "log_level":"warn",
  "rule_sets":[{
    "ref":"geoip:layer-conflict",
    "sha256":%q,
    "format":"source"
  }],
  "nodes":[{
    "profile_id":"five-layer",
    "node_id":"proxy-a",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  },{
    "profile_id":"five-layer",
    "node_id":"proxy-b",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  },{
    "profile_id":"five-layer",
    "node_id":"proxy-c",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{
        "kind":"specific_node",
        "profile_id":"five-layer",
        "node_id":"proxy-a"
      }],
      "default":{
        "kind":"specific_node",
        "profile_id":"five-layer",
        "node_id":"proxy-a"
      }
    },
    "custom":[]
  },
  "routing":{
    "custom_enabled":%t,
    "geosite_enabled":%t,
    "geoip_enabled":%t,
    "acl_enabled":%t,
    "custom":[{
      "id":"l1-geoip-named-rule-set",
      "order":1,
      "enabled":true,
      "target":{"kind":"specific_node","profile_id":"five-layer","node_id":"proxy-a"},
      "match":{"op":"atom","predicate":{"kind":"rule_set","value":"geoip:layer-conflict"}}
    }],
    "geosite":[{
      "id":"l2-geosite",
      "order":1,
      "enabled":true,
      "target":{"kind":"specific_node","profile_id":"five-layer","node_id":"proxy-b"},
      "match":{"op":"atom","predicate":{"kind":"port","port":{"start":%d,"end":%d}}}
    }],
    "geoip":[{
      "id":"l3-geoip",
      "order":1,
      "enabled":true,
      "target":{"kind":"specific_node","profile_id":"five-layer","node_id":"proxy-c"},
      "match":{"op":"atom","predicate":{"kind":"port","port":{"start":%d,"end":%d}}}
    }],
    "acl":[{
      "id":"l4-acl",
      "order":1,
      "enabled":true,
      "target":{"kind":"block"},
      "match":{"op":"atom","predicate":{"kind":"port","port":{"start":%d,"end":%d}}}
    }],
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
		ruleSetSHA256,
		proxyAPort,
		proxyBPort,
		proxyCPort,
		customEnabled,
		geositeEnabled,
		geoIPEnabled,
		aclEnabled,
		targetPort,
		targetPort,
		targetPort,
		targetPort,
		targetPort,
		targetPort,
	))
}
