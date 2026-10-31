//go:build integration && linux

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
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
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestManagedCoreRealRouteOutcomes(t *testing.T) {
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

	proxyAAddress, proxyAHits, closeProxyA := startRejectingHTTPProxy(t)
	defer closeProxyA()
	proxyBAddress, proxyBHits, closeProxyB := startRejectingHTTPProxy(t)
	defer closeProxyB()
	fallbackDNSAddress, fallbackDNSHits, closeFallbackDNS := startFallbackDNSServer(t)
	defer closeFallbackDNS()

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
				t.Errorf("managed core supervisor shutdown: %v; stderr=%s", err, managed.StderrTail())
			}
		case <-time.After(5 * time.Second):
			t.Errorf("managed core supervisor did not shut down")
		}
	}()

	committed, err := store.CommitDeclaration(
		ctx,
		0,
		routeOutcomeDeclaration(ruleSetSHA256, proxyAAddress.Port(), proxyBAddress.Port(), fallbackDNSAddress.Port()),
		"integration:route-outcomes",
	)
	if err != nil {
		t.Fatal(err)
	}
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 40*time.Second)
	_, _, err = runtime.ApplyDeclarationRevision(applyCtx, committed.Revision, 0)
	applyCancel()
	if err != nil {
		t.Fatalf("apply route-outcome declaration: %v; stderr=%s", err, managed.StderrTail())
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start route-outcome generation: %v; stderr=%s", err, managed.StderrTail())
	}
	startCancel()
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})

	targetAddress, targetHits, closeTarget := startRouteOutcomeTarget(t)
	defer closeTarget()

	ruleAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)
	directAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.DirectPort)
	selectedAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.SelectedPort)

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := socks5Connect(connectCtx, ruleAddress, targetAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("Rule inbound unexpectedly reached loopback target despite BLOCK rule")
	}
	assertNoRouteOutcomeSignal(t, targetHits, 100*time.Millisecond, "Rule inbound target")
	assertNoRouteOutcomeSignal(t, proxyAHits, 100*time.Millisecond, "Rule inbound selected proxy A")
	assertNoRouteOutcomeSignal(t, proxyBHits, 100*time.Millisecond, "Rule inbound selected proxy B")

	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5Connect(connectCtx, directAddress, targetAddress)
	connectCancel()
	if err != nil {
		t.Fatalf("Direct inbound did not bypass Rule routing: %v; stderr=%s", err, managed.StderrTail())
	}
	var marker [2]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read Direct inbound target marker: %v", err)
	}
	_ = conn.Close()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("Direct inbound target marker = %q", marker)
	}
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "Direct inbound target")
	assertNoRouteOutcomeSignal(t, proxyAHits, 100*time.Millisecond, "Direct inbound selected proxy A")
	assertNoRouteOutcomeSignal(t, proxyBHits, 100*time.Millisecond, "Direct inbound selected proxy B")

	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5ConnectDomain(connectCtx, directAddress, "fallback.integration.test", targetAddress.Port())
	connectCancel()
	if err != nil {
		t.Fatalf("Direct inbound fallback DNS connect failed: %v; stderr=%s", err, managed.StderrTail())
	}
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read fallback DNS target marker: %v", err)
	}
	_ = conn.Close()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("fallback DNS target marker = %q", marker)
	}
	assertRouteOutcomeSignal(t, fallbackDNSHits, 2*time.Second, "Global fallback DNS")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "fallback-resolved Direct target")
	assertNoRouteOutcomeSignal(t, proxyAHits, 100*time.Millisecond, "fallback Direct selected proxy A")
	assertNoRouteOutcomeSignal(t, proxyBHits, 100*time.Millisecond, "fallback Direct selected proxy B")

	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5Connect(connectCtx, selectedAddress, targetAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("Selected inbound unexpectedly bypassed CurrentSelected proxy")
	}
	assertRouteOutcomeSignal(t, proxyAHits, 2*time.Second, "Selected inbound default proxy A")
	assertNoRouteOutcomeSignal(t, proxyBHits, 100*time.Millisecond, "Selected inbound proxy B before switch")
	assertNoRouteOutcomeSignal(t, targetHits, 100*time.Millisecond, "Selected inbound direct target")

	selection, err := NewCurrentSelectionCoordinator(store, runtime)
	if err != nil {
		t.Fatal(err)
	}
	selectionTarget := domain.TargetRef{
		Kind:      domain.TargetSpecificNode,
		ProfileID: "route-outcome-profile",
		NodeID:    "route-outcome-node-b",
	}
	switchCtx, switchCancel := context.WithTimeout(context.Background(), 5*time.Second)
	selectionState, err := selection.Set(switchCtx, selectionTarget)
	switchCancel()
	if err != nil {
		t.Fatalf("switch CurrentSelected to proxy B: %v; stderr=%s", err, managed.StderrTail())
	}
	if !selectionState.Persisted || !selectionState.Applied || selectionState.LiveRuntimeTag != selectionState.RuntimeTag {
		t.Fatalf("selection switch was not durably applied: %+v", selectionState)
	}

	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5Connect(connectCtx, selectedAddress, targetAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("Selected inbound unexpectedly reached target after switch to proxy B")
	}
	assertRouteOutcomeSignal(t, proxyBHits, 2*time.Second, "Selected inbound switched proxy B")
	assertNoRouteOutcomeSignal(t, proxyAHits, 100*time.Millisecond, "Selected inbound stale proxy A after switch")
	assertNoRouteOutcomeSignal(t, targetHits, 100*time.Millisecond, "Selected inbound direct target after switch")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatalf("stop route-outcome core: %v", err)
	}
	stopCancel()
	waitManagedCoreState(t, managed, 3*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateStopped && snapshot.PID == 0
	})

	restartCtx, restartCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(restartCtx); err != nil {
		restartCancel()
		t.Fatalf("restart route-outcome generation with persisted selection: %v; stderr=%s", err, managed.StderrTail())
	}
	restartCancel()
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})

	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5Connect(connectCtx, selectedAddress, targetAddress)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("Selected inbound unexpectedly reached target after restart")
	}
	assertRouteOutcomeSignal(t, proxyBHits, 2*time.Second, "Selected inbound persisted proxy B after restart")
	assertNoRouteOutcomeSignal(t, proxyAHits, 100*time.Millisecond, "Selected inbound reverted to proxy A after restart")
	assertNoRouteOutcomeSignal(t, targetHits, 100*time.Millisecond, "Selected inbound direct target after restart")

	finalStopCtx, finalStopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(finalStopCtx); err != nil {
		finalStopCancel()
		t.Fatalf("final stop route-outcome core: %v", err)
	}
	finalStopCancel()
	waitManagedCoreState(t, managed, 3*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateStopped && snapshot.PID == 0
	})
}

func routeOutcomeDeclaration(ruleSetSHA256 string, proxyAPort, proxyBPort, fallbackDNSPort uint16) []byte {
	return []byte(fmt.Sprintf(`{
  "schema_version":1,
  "log_level":"warn",
  "rule_sets":[{
    "ref":"integration:block-loopback",
    "sha256":%q,
    "format":"source"
  }],
  "nodes":[{
    "profile_id":"route-outcome-profile",
    "node_id":"route-outcome-node-a",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  },{
    "profile_id":"route-outcome-profile",
    "node_id":"route-outcome-node-b",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[
        {"kind":"specific_node","profile_id":"route-outcome-profile","node_id":"route-outcome-node-a"},
        {"kind":"specific_node","profile_id":"route-outcome-profile","node_id":"route-outcome-node-b"}
      ],
      "default":{"kind":"specific_node","profile_id":"route-outcome-profile","node_id":"route-outcome-node-a"}
    },
    "custom":[]
  },
  "routing":{
    "custom":[{
      "id":"block-loopback",
      "order":1,
      "enabled":true,
      "target":{"kind":"block"},
      "match":{"op":"atom","predicate":{"kind":"rule_set","value":"integration:block-loopback"}}
    }],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":{"kind":"direct"}
  },
  "dns":{
    "profiles":[{
      "id":"route-outcome-dns",
      "role":"outbound",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":9
    },{
      "id":"route-outcome-fallback",
      "role":"fallback",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":%d
    }],
    "outbound_profile_id":"route-outcome-dns",
    "fallback_profile_id":"route-outcome-fallback"
  }
}`, ruleSetSHA256, proxyAPort, proxyBPort, fallbackDNSPort))
}

func socks5Connect(ctx context.Context, inbound, target netip.AddrPort) (net.Conn, error) {
	if !target.Addr().Is4() {
		return nil, errors.New("route-outcome SOCKS helper requires an IPv4 target")
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", inbound.String())
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		_ = conn.Close()
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fail(err)
		}
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return fail(err)
	}
	if greeting != [2]byte{0x05, 0x00} {
		return fail(fmt.Errorf("unexpected SOCKS5 greeting response %v", greeting))
	}

	ip := target.Addr().As4()
	request := []byte{
		0x05, 0x01, 0x00, 0x01,
		ip[0], ip[1], ip[2], ip[3],
		byte(target.Port() >> 8), byte(target.Port()),
	}
	if _, err := conn.Write(request); err != nil {
		return fail(err)
	}

	var response [4]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return fail(err)
	}
	if response[0] != 0x05 {
		return fail(fmt.Errorf("unexpected SOCKS5 response version %d", response[0]))
	}
	if response[1] != 0x00 {
		return fail(fmt.Errorf("SOCKS5 CONNECT rejected with code 0x%02x", response[1]))
	}

	var addressBytes int
	switch response[3] {
	case 0x01:
		addressBytes = 4
	case 0x04:
		addressBytes = 16
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return fail(err)
		}
		addressBytes = int(length[0])
	default:
		return fail(fmt.Errorf("unexpected SOCKS5 bound address type 0x%02x", response[3]))
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addressBytes+2)); err != nil {
		return fail(err)
	}
	return conn, nil
}

func socks5ConnectDomain(ctx context.Context, inbound netip.AddrPort, domain string, port uint16) (net.Conn, error) {
	if domain == "" || len(domain) > 255 {
		return nil, errors.New("route-outcome SOCKS domain must contain 1..255 bytes")
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", inbound.String())
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		_ = conn.Close()
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fail(err)
		}
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return fail(err)
	}
	if greeting != [2]byte{0x05, 0x00} {
		return fail(fmt.Errorf("unexpected SOCKS5 greeting response %v", greeting))
	}

	request := make([]byte, 0, 7+len(domain))
	request = append(request, 0x05, 0x01, 0x00, 0x03, byte(len(domain)))
	request = append(request, domain...)
	request = append(request, byte(port>>8), byte(port))
	if _, err := conn.Write(request); err != nil {
		return fail(err)
	}

	var response [4]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return fail(err)
	}
	if response[0] != 0x05 {
		return fail(fmt.Errorf("unexpected SOCKS5 response version %d", response[0]))
	}
	if response[1] != 0x00 {
		return fail(fmt.Errorf("SOCKS5 CONNECT rejected with code 0x%02x", response[1]))
	}

	var addressBytes int
	switch response[3] {
	case 0x01:
		addressBytes = 4
	case 0x04:
		addressBytes = 16
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return fail(err)
		}
		addressBytes = int(length[0])
	default:
		return fail(fmt.Errorf("unexpected SOCKS5 bound address type 0x%02x", response[3]))
	}
	if _, err := io.CopyN(io.Discard, conn, int64(addressBytes+2)); err != nil {
		return fail(err)
	}
	return conn, nil
}

func startFallbackDNSServer(t *testing.T) (netip.AddrPort, <-chan struct{}, func()) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddrPort(conn.LocalAddr().String())
	if err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	hits := make(chan struct{}, 16)
	go func() {
		buffer := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			response, err := fallbackDNSResponse(buffer[:n])
			if err != nil {
				continue
			}
			select {
			case hits <- struct{}{}:
			default:
			}
			_, _ = conn.WriteTo(response, peer)
		}
	}()
	var once sync.Once
	closeFn := func() {
		once.Do(func() { _ = conn.Close() })
	}
	return address, hits, closeFn
}

func fallbackDNSResponse(query []byte) ([]byte, error) {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, errors.New("unsupported DNS query")
	}
	offset := 12
	for {
		if offset >= len(query) {
			return nil, errors.New("truncated DNS question")
		}
		length := int(query[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xc0 != 0 || offset+length > len(query) {
			return nil, errors.New("unsupported DNS question name")
		}
		offset += length
	}
	if offset+4 > len(query) {
		return nil, errors.New("truncated DNS question type")
	}
	questionEnd := offset + 4
	queryType := binary.BigEndian.Uint16(query[offset : offset+2])

	response := make([]byte, 12, 12+(questionEnd-12)+16)
	copy(response[:2], query[:2])
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[4:6], 1)
	answerCount := uint16(0)
	if queryType == 1 {
		answerCount = 1
	}
	binary.BigEndian.PutUint16(response[6:8], answerCount)
	response = append(response, query[12:questionEnd]...)
	if answerCount == 0 {
		return response, nil
	}
	response = append(response,
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		127, 0, 0, 1,
	)
	return response, nil
}

func startRejectingHTTPProxy(t *testing.T) (netip.AddrPort, <-chan struct{}, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits := make(chan struct{}, 8)
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			select {
			case hits <- struct{}{}:
			default:
			}
			http.Error(w, "route-outcome proxy rejects CONNECT", http.StatusBadGateway)
		}),
	}
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
	return address, hits, closeFn
}

func startRouteOutcomeTarget(t *testing.T) (netip.AddrPort, <-chan struct{}, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits := make(chan struct{}, 8)
	var once sync.Once
	closeFn := func() {
		once.Do(func() { _ = listener.Close() })
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case hits <- struct{}{}:
			default:
			}
			_, _ = conn.Write([]byte{'o', 'k'})
			_ = conn.Close()
		}
	}()
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		closeFn()
		t.Fatal(err)
	}
	return address, hits, closeFn
}

func assertRouteOutcomeSignal(t *testing.T, ch <-chan struct{}, timeout time.Duration, label string) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
		t.Fatalf("timed out waiting for %s", label)
	}
}

func assertNoRouteOutcomeSignal(t *testing.T, ch <-chan struct{}, window time.Duration, label string) {
	t.Helper()
	timer := time.NewTimer(window)
	defer timer.Stop()
	select {
	case <-ch:
		t.Fatalf("unexpected %s", label)
	case <-timer.C:
	}
}
