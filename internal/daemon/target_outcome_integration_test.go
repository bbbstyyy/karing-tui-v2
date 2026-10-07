//go:build integration && linux

package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestManagedCoreRealTargetOutcomes(t *testing.T) {
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

	healthAddress, closeHealth := startTargetOutcomeHealth(t)
	defer closeHealth()
	targetAddress, targetHits, closeTarget := startRouteOutcomeTarget(t)
	defer closeTarget()

	goodProxy, goodHealthHits, goodConnectHits, closeGoodProxy := startTargetOutcomeHTTPProxy(t, healthAddress.String(), true)
	defer closeGoodProxy()
	badProxy, badHealthHits, badConnectHits, closeBadProxy := startTargetOutcomeHTTPProxy(t, healthAddress.String(), false)
	defer closeBadProxy()

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
				t.Errorf("target-outcome supervisor shutdown: %v; stderr=%s", err, managed.StderrTail())
			}
		case <-time.After(5 * time.Second):
			t.Errorf("target-outcome supervisor did not shut down")
		}
	}()

	declarationRevision := uint64(0)
	configRevision := uint64(0)
	apply := func(name string, document []byte) {
		t.Helper()
		committed, err := store.CommitDeclaration(
			ctx,
			declarationRevision,
			document,
			"integration:target-"+name,
		)
		if err != nil {
			t.Fatal(err)
		}
		applyCtx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		attempt, _, err := runtime.ApplyDeclarationRevision(applyCtx, committed.Revision, configRevision)
		cancel()
		if err != nil {
			t.Fatalf("apply %s target declaration: %v; stderr=%s", name, err, managed.StderrTail())
		}
		declarationRevision = committed.Revision
		configRevision = attempt.TargetRevision
	}

	healthURL := "http://" + healthAddress.String() + "/generate_204"
	apply("global-urltest", targetOutcomeDeclaration(
		goodProxy.Port(),
		badProxy.Port(),
		healthURL,
		"global_urltest",
		"",
	))

	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start global URLTest generation: %v; stderr=%s", err, managed.StderrTail())
	}
	startCancel()
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})
	assertRouteOutcomeSignal(t, badHealthHits, 5*time.Second, "Global URLTest failing candidate probe")
	assertRouteOutcomeSignal(t, goodHealthHits, 5*time.Second, "Global URLTest healthy candidate probe")
	assertTargetOutcomeConnect(t, inbounds, targetAddress, targetHits, goodConnectHits, badConnectHits, managed, "Global URLTest")

	drainRouteOutcomeSignal(goodHealthHits)
	drainRouteOutcomeSignal(badHealthHits)
	apply("custom-urltest", targetOutcomeDeclaration(
		goodProxy.Port(),
		badProxy.Port(),
		healthURL,
		"custom_urltest",
		"preferred",
	))
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})
	assertRouteOutcomeSignal(t, badHealthHits, 5*time.Second, "Custom URLTest failing candidate probe")
	assertRouteOutcomeSignal(t, goodHealthHits, 5*time.Second, "Custom URLTest healthy candidate probe")
	assertTargetOutcomeConnect(t, inbounds, targetAddress, targetHits, goodConnectHits, badConnectHits, managed, "Custom URLTest")

	apply("specific-node", targetOutcomeDeclaration(
		goodProxy.Port(),
		badProxy.Port(),
		healthURL,
		"specific_node",
		"",
	))
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})
	assertTargetOutcomeConnect(t, inbounds, targetAddress, targetHits, goodConnectHits, badConnectHits, managed, "SpecificNode")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatalf("stop target-outcome core: %v", err)
	}
	stopCancel()
	waitManagedCoreState(t, managed, 3*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateStopped && snapshot.PID == 0
	})
}

func assertTargetOutcomeConnect(
	t *testing.T,
	inbounds domain.InboundSet,
	targetAddress netip.AddrPort,
	targetHits <-chan struct{},
	goodConnectHits <-chan struct{},
	badConnectHits <-chan struct{},
	managed *ManagedCore,
	label string,
) {
	t.Helper()
	connectCtx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	conn, err := socks5Connect(
		connectCtx,
		netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort),
		targetAddress,
	)
	cancel()
	if err != nil {
		t.Fatalf("%s route did not reach target: %v; stderr=%s", label, err, managed.StderrTail())
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
	assertRouteOutcomeSignal(t, goodConnectHits, 2*time.Second, label+" healthy proxy CONNECT")
	assertNoRouteOutcomeSignal(t, badConnectHits, 200*time.Millisecond, label+" failing proxy CONNECT")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, label+" target")
}

func targetOutcomeDeclaration(
	goodProxyPort uint16,
	badProxyPort uint16,
	healthURL string,
	finalKind string,
	customGroupID string,
) []byte {
	global := ""
	custom := "[]"
	final := ""
	members := `[
        {"kind":"specific_node","profile_id":"target-profile","node_id":"bad"},
        {"kind":"specific_node","profile_id":"target-profile","node_id":"good"}
      ]`
	policy := fmt.Sprintf(`{
        "url":%q,
        "interval":"1s",
        "tolerance":1,
        "idle_timeout":"10s"
      }`, healthURL)

	switch finalKind {
	case "global_urltest":
		global = fmt.Sprintf(`,
    "global":{"members":%s,"policy":%s}`, members, policy)
		final = `{"kind":"global_urltest"}`
	case "custom_urltest":
		custom = fmt.Sprintf(
			`[{"id":%q,"members":%s,"policy":%s}]`,
			customGroupID,
			members,
			policy,
		)
		final = fmt.Sprintf(`{"kind":"custom_urltest","group_id":%q}`, customGroupID)
	case "specific_node":
		final = `{"kind":"specific_node","profile_id":"target-profile","node_id":"good"}`
	default:
		panic("unsupported target outcome final kind: " + finalKind)
	}

	return []byte(fmt.Sprintf(`{
  "schema_version":1,
  "log_level":"warn",
  "nodes":[{
    "profile_id":"target-profile",
    "node_id":"bad",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  },{
    "profile_id":"target-profile",
    "node_id":"good",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{"kind":"specific_node","profile_id":"target-profile","node_id":"good"}],
      "default":{"kind":"specific_node","profile_id":"target-profile","node_id":"good"}
    }%s,
    "custom":%s
  },
  "routing":{
    "custom":[],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":%s
  },
  "dns":{
    "profiles":[{
      "id":"outbound-dns",
      "role":"outbound",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":9
    }],
    "outbound_profile_id":"outbound-dns"
  }
}`, badProxyPort, goodProxyPort, global, custom, final))
}

func startTargetOutcomeHealth(t *testing.T) (netip.AddrPort, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	var once sync.Once
	return address, func() {
		once.Do(func() { _ = server.Close() })
	}
}

func startTargetOutcomeHTTPProxy(
	t *testing.T,
	healthHost string,
	pass bool,
) (netip.AddrPort, <-chan struct{}, <-chan struct{}, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	healthHits := make(chan struct{}, 32)
	connectHits := make(chan struct{}, 32)

	signal := func(ch chan struct{}) {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isHealth := r.Host == healthHost
		if isHealth {
			signal(healthHits)
		} else if r.Method == http.MethodConnect {
			signal(connectHits)
		}
		if !pass {
			http.Error(w, "intentional target-outcome proxy failure", http.StatusBadGateway)
			return
		}
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		upstream, err := net.DialTimeout("tcp", r.Host, 3*time.Second)
		if err != nil {
			http.Error(w, "dial target: "+err.Error(), http.StatusBadGateway)
			return
		}
		defer upstream.Close()

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
			return
		}
		downstream, buffered, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer downstream.Close()
		if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := buffered.Flush(); err != nil {
			return
		}

		done := make(chan struct{}, 2)
		go func() {
			_, _ = io.Copy(upstream, downstream)
			done <- struct{}{}
		}()
		go func() {
			_, _ = io.Copy(downstream, upstream)
			done <- struct{}{}
		}()
		<-done
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	var once sync.Once
	closeFn := func() {
		once.Do(func() { _ = server.Close() })
	}
	return address, healthHits, connectHits, closeFn
}

func drainRouteOutcomeSignal(ch <-chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}
