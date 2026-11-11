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

func TestManagedCoreRealBooleanRouting(t *testing.T) {
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

	blockedAddress, blockedHits, closeBlocked := startRouteOutcomeTarget(t)
	defer closeBlocked()
	allowedAddress, allowedHits, closeAllowed := startRouteOutcomeTarget(t)
	defer closeAllowed()

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
				t.Errorf("boolean-route supervisor shutdown: %v; stderr=%s", err, managed.StderrTail())
			}
		case <-time.After(5 * time.Second):
			t.Errorf("boolean-route supervisor did not shut down")
		}
	}()

	lowPort, highPort := blockedAddress.Port(), allowedAddress.Port()
	if lowPort > highPort {
		lowPort, highPort = highPort, lowPort
	}
	document := booleanRouteDeclaration(
		lowPort,
		highPort,
		allowedAddress.Port(),
	)
	committed, err := store.CommitDeclaration(ctx, 0, document, "integration:boolean-routing")
	if err != nil {
		t.Fatal(err)
	}
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 40*time.Second)
	_, _, err = runtime.ApplyDeclarationRevision(applyCtx, committed.Revision, 0)
	applyCancel()
	if err != nil {
		t.Fatalf("apply boolean-routing declaration: %v; stderr=%s", err, managed.StderrTail())
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start boolean-routing generation: %v; stderr=%s", err, managed.StderrTail())
	}
	startCancel()
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})

	ruleAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := socks5Connect(connectCtx, ruleAddress, blockedAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("AND/OR/NOT BLOCK rule unexpectedly allowed blocked port")
	}
	assertNoRouteOutcomeSignal(t, blockedHits, 150*time.Millisecond, "boolean BLOCK target")

	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5Connect(connectCtx, ruleAddress, allowedAddress)
	connectCancel()
	if err != nil {
		t.Fatalf("NOT allow-port branch did not fall through to FINAL/DIRECT: %v; stderr=%s", err, managed.StderrTail())
	}
	var marker [2]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read boolean allow target marker: %v", err)
	}
	_ = conn.Close()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("boolean allow target marker = %q", marker)
	}
	assertRouteOutcomeSignal(t, allowedHits, 2*time.Second, "boolean FINAL/DIRECT target")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatalf("stop boolean-routing core: %v", err)
	}
	stopCancel()
	waitManagedCoreState(t, managed, 3*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateStopped && snapshot.PID == 0
	})
}

func booleanRouteDeclaration(lowPort, highPort, allowedPort uint16) []byte {
	return []byte(fmt.Sprintf(`{
  "schema_version":1,
  "log_level":"warn",
  "nodes":[{
    "profile_id":"boolean-fixture",
    "node_id":"unused-selected",
    "type":"http",
    "server":"127.0.0.1",
    "port":9,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{
        "kind":"specific_node",
        "profile_id":"boolean-fixture",
        "node_id":"unused-selected"
      }],
      "default":{
        "kind":"specific_node",
        "profile_id":"boolean-fixture",
        "node_id":"unused-selected"
      }
    },
    "custom":[]
  },
  "routing":{
    "custom":[{
      "id":"boolean-block",
      "order":1,
      "enabled":true,
      "target":{"kind":"block"},
      "match":{
        "op":"all",
        "children":[{
          "op":"any",
          "children":[{
            "op":"atom",
            "predicate":{"kind":"network","network":"tcp"}
          },{
            "op":"atom",
            "predicate":{"kind":"network","network":"udp"}
          }]
        },{
          "op":"atom",
          "predicate":{"kind":"port","port":{"start":%d,"end":%d}}
        },{
          "op":"not",
          "children":[{
            "op":"atom",
            "predicate":{"kind":"port","port":{"start":%d,"end":%d}}
          }]
        }]
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
}`, lowPort, highPort, allowedPort, allowedPort))
}
