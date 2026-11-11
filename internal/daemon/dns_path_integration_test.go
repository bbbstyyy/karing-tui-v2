//go:build integration && linux

package daemon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestManagedCoreRealDNSPaths(t *testing.T) {
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

	bootstrapAddress, bootstrapQueries, closeBootstrap := startDNSPathUDPServer(t)
	defer closeBootstrap()
	outboundAddress, outboundQueries, closeOutbound := startDNSPathTCPServer(t)
	defer closeOutbound()
	directAddress, directQueries, closeDirect := startDNSPathUDPServer(t)
	defer closeDirect()
	proxyDNSAddress, proxyDNSQueries, closeProxyDNS := startDNSPathTCPServer(t)
	defer closeProxyDNS()
	groupDNSAddress, groupDNSQueries, closeGroupDNS := startDNSPathTCPServer(t)
	defer closeGroupDNS()

	proxyAddress, proxyConnects, closeProxy := startDNSPathHTTPProxy(t)
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
				t.Errorf("DNS-path supervisor shutdown: %v; stderr=%s", err, managed.StderrTail())
			}
		case <-time.After(5 * time.Second):
			t.Errorf("DNS-path supervisor did not shut down")
		}
	}()

	document := dnsPathDeclaration(
		proxyAddress.Port(),
		bootstrapAddress.Port(),
		outboundAddress.Port(),
		directAddress.Port(),
		proxyDNSAddress.Port(),
		groupDNSAddress.Port(),
	)
	committed, err := store.CommitDeclaration(ctx, 0, document, "integration:dns-paths")
	if err != nil {
		t.Fatal(err)
	}
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 40*time.Second)
	_, _, err = runtime.ApplyDeclarationRevision(applyCtx, committed.Revision, 0)
	applyCancel()
	if err != nil {
		t.Fatalf("apply DNS-path declaration: %v; stderr=%s", err, managed.StderrTail())
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start DNS-path generation: %v; stderr=%s", err, managed.StderrTail())
	}
	startCancel()
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})

	ruleAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)
	selectedAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.SelectedPort)

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 6*time.Second)
	conn, err := socks5ConnectDomain(connectCtx, selectedAddress, "selected.integration.test", targetAddress.Port())
	connectCancel()
	if err != nil {
		t.Fatalf("Selected DNS-path connect failed: %v; stderr=%s", err, managed.StderrTail())
	}
	var marker [2]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read Selected DNS-path target marker: %v", err)
	}
	_ = conn.Close()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("Selected DNS-path target marker = %q", marker)
	}

	assertDNSPathQuery(t, bootstrapQueries, "outbound-dns.integration.test", 5*time.Second, "bootstrap DNS")
	assertDNSPathQuery(t, outboundQueries, "proxy.integration.test", 5*time.Second, "outbound node DNS")
	assertDNSPathQuery(t, proxyDNSQueries, "selected.integration.test", 5*time.Second, "proxy target DNS")
	assertDNSPathProxyConnect(t, proxyConnects, proxyDNSAddress.Port(), 5*time.Second, "proxy DNS detour")
	assertDNSPathProxyConnect(t, proxyConnects, targetAddress.Port(), 5*time.Second, "Selected target proxy")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "Selected DNS-path target")

	drainDNSPathQueries(directQueries)
	drainDNSPathQueries(groupDNSQueries)
	drainDNSPathProxyConnects(proxyConnects)
	drainRouteOutcomeSignal(targetHits)

	connectCtx, connectCancel = context.WithTimeout(context.Background(), 6*time.Second)
	conn, err = socks5ConnectDomain(connectCtx, ruleAddress, "group.integration.test", targetAddress.Port())
	connectCancel()
	if err != nil {
		t.Fatalf("Group DNS-path connect failed: %v; stderr=%s", err, managed.StderrTail())
	}
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read Group DNS-path target marker: %v", err)
	}
	_ = conn.Close()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("Group DNS-path target marker = %q", marker)
	}
	assertDNSPathQuery(t, groupDNSQueries, "group.integration.test", 5*time.Second, "group DNS")
	assertDNSPathProxyConnect(t, proxyConnects, groupDNSAddress.Port(), 5*time.Second, "group DNS detour")
	assertNoDNSPathProxyConnectPort(t, proxyConnects, targetAddress.Port(), 250*time.Millisecond, "group DIRECT target")
	assertNoDNSPathQuery(t, directQueries, "group.integration.test", 250*time.Millisecond, "direct DNS after group override")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "Group DNS DIRECT target")

	drainDNSPathQueries(directQueries)
	drainDNSPathProxyConnects(proxyConnects)
	drainRouteOutcomeSignal(targetHits)

	connectCtx, connectCancel = context.WithTimeout(context.Background(), 6*time.Second)
	conn, err = socks5ConnectDomain(connectCtx, ruleAddress, "direct.integration.test", targetAddress.Port())
	connectCancel()
	if err != nil {
		t.Fatalf("Direct DNS-path connect failed: %v; stderr=%s", err, managed.StderrTail())
	}
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		t.Fatalf("read Direct DNS-path target marker: %v", err)
	}
	_ = conn.Close()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("Direct DNS-path target marker = %q", marker)
	}
	assertDNSPathQuery(t, directQueries, "direct.integration.test", 5*time.Second, "direct target DNS")
	assertNoDNSPathProxyConnectPort(t, proxyConnects, targetAddress.Port(), 250*time.Millisecond, "direct target proxy")
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "Direct DNS target")

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatalf("stop DNS-path core: %v", err)
	}
	stopCancel()
	waitManagedCoreState(t, managed, 3*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateStopped && snapshot.PID == 0
	})
}

func dnsPathDeclaration(
	proxyPort uint16,
	bootstrapPort uint16,
	outboundPort uint16,
	directPort uint16,
	proxyDNSPort uint16,
	groupDNSPort uint16,
) []byte {
	return []byte(fmt.Sprintf(`{
  "schema_version":1,
  "log_level":"warn",
  "nodes":[{
    "profile_id":"dns-path-profile",
    "node_id":"proxy",
    "type":"http",
    "server":"proxy.integration.test",
    "port":%d,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{
        "kind":"specific_node",
        "profile_id":"dns-path-profile",
        "node_id":"proxy"
      }],
      "default":{
        "kind":"specific_node",
        "profile_id":"dns-path-profile",
        "node_id":"proxy"
      }
    },
    "custom":[]
  },
  "routing":{
    "custom":[{
      "id":"group-dns-route",
      "order":1,
      "enabled":true,
      "target":{"kind":"direct"},
      "dns_profile_id":"group-dns",
      "match":{
        "op":"atom",
        "predicate":{"kind":"domain","value":"group.integration.test"}
      }
    }],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":{"kind":"direct"}
  },
  "dns":{
    "profiles":[{
      "id":"bootstrap",
      "role":"bootstrap",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":%d
    },{
      "id":"outbound",
      "role":"outbound",
      "transport":"tcp",
      "server":"outbound-dns.integration.test",
      "port":%d,
      "bootstrap_profile_id":"bootstrap"
    },{
      "id":"direct-dns",
      "role":"direct",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":%d
    },{
      "id":"proxy-dns",
      "role":"proxy",
      "transport":"tcp",
      "server":"127.0.0.1",
      "port":%d
    },{
      "id":"group-dns",
      "role":"group",
      "transport":"tcp",
      "server":"127.0.0.1",
      "port":%d,
      "detour_target":{"kind":"current_selected"}
    }],
    "outbound_profile_id":"outbound",
    "direct_profile_id":"direct-dns",
    "proxy_profile_id":"proxy-dns"
  }
}`, proxyPort, bootstrapPort, outboundPort, directPort, proxyDNSPort, groupDNSPort))
}

func startDNSPathUDPServer(t *testing.T) (netip.AddrPort, <-chan string, func()) {
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
	queries := make(chan string, 64)
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			name, response, err := dnsPathResponse(buffer[:n])
			if err != nil {
				continue
			}
			signalDNSPathQuery(queries, name)
			_, _ = conn.WriteTo(response, peer)
		}
	}()
	var once sync.Once
	return address, queries, func() {
		once.Do(func() { _ = conn.Close() })
	}
}

func startDNSPathTCPServer(t *testing.T) (netip.AddrPort, <-chan string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	queries := make(chan string, 64)
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
			go func(conn net.Conn) {
				defer conn.Close()
				for {
					var size [2]byte
					if _, err := io.ReadFull(conn, size[:]); err != nil {
						return
					}
					length := int(binary.BigEndian.Uint16(size[:]))
					if length <= 0 || length > 65535 {
						return
					}
					query := make([]byte, length)
					if _, err := io.ReadFull(conn, query); err != nil {
						return
					}
					name, response, err := dnsPathResponse(query)
					if err != nil {
						return
					}
					signalDNSPathQuery(queries, name)
					var responseSize [2]byte
					binary.BigEndian.PutUint16(responseSize[:], uint16(len(response)))
					if _, err := conn.Write(responseSize[:]); err != nil {
						return
					}
					if _, err := conn.Write(response); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return address, queries, closeFn
}

func dnsPathResponse(query []byte) (string, []byte, error) {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return "", nil, errors.New("unsupported DNS query")
	}
	offset := 12
	labels := make([]string, 0, 4)
	for {
		if offset >= len(query) {
			return "", nil, errors.New("truncated DNS question")
		}
		length := int(query[offset])
		offset++
		if length == 0 {
			break
		}
		if length&0xc0 != 0 || offset+length > len(query) {
			return "", nil, errors.New("unsupported DNS question name")
		}
		labels = append(labels, strings.ToLower(string(query[offset:offset+length])))
		offset += length
	}
	if offset+4 > len(query) {
		return "", nil, errors.New("truncated DNS question type")
	}
	questionEnd := offset + 4
	queryType := binary.BigEndian.Uint16(query[offset : offset+2])
	name := strings.Join(labels, ".")

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
		return name, response, nil
	}
	response = append(response,
		0xc0, 0x0c,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x3c,
		0x00, 0x04,
		127, 0, 0, 1,
	)
	return name, response, nil
}

func signalDNSPathQuery(ch chan string, name string) {
	select {
	case ch <- name:
	default:
	}
}

func startDNSPathHTTPProxy(t *testing.T) (netip.AddrPort, <-chan string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	connects := make(chan string, 64)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", http.StatusMethodNotAllowed)
			return
		}
		select {
		case connects <- r.Host:
		default:
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
	return address, connects, func() {
		once.Do(func() { _ = server.Close() })
	}
}

func assertDNSPathQuery(
	t *testing.T,
	ch <-chan string,
	want string,
	timeout time.Duration,
	label string,
) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case got := <-ch:
			if got == want {
				return
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for %s query %q", label, want)
		}
	}
}

func assertNoDNSPathQuery(
	t *testing.T,
	ch <-chan string,
	want string,
	window time.Duration,
	label string,
) {
	t.Helper()
	timer := time.NewTimer(window)
	defer timer.Stop()
	for {
		select {
		case got := <-ch:
			if got == want {
				t.Fatalf("unexpected %s query %q", label, want)
			}
		case <-timer.C:
			return
		}
	}
}

func assertDNSPathProxyConnect(
	t *testing.T,
	ch <-chan string,
	wantPort uint16,
	timeout time.Duration,
	label string,
) {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case host := <-ch:
			_, portText, err := net.SplitHostPort(host)
			if err != nil {
				continue
			}
			if portText == fmt.Sprint(wantPort) {
				return
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for %s CONNECT to port %d", label, wantPort)
		}
	}
}

func assertNoDNSPathProxyConnectPort(
	t *testing.T,
	ch <-chan string,
	wantPort uint16,
	window time.Duration,
	label string,
) {
	t.Helper()
	timer := time.NewTimer(window)
	defer timer.Stop()
	for {
		select {
		case host := <-ch:
			_, portText, err := net.SplitHostPort(host)
			if err == nil && portText == fmt.Sprint(wantPort) {
				t.Fatalf("unexpected %s CONNECT to %s", label, host)
			}
		case <-timer.C:
			return
		}
	}
}

func drainDNSPathQueries(ch <-chan string) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func drainDNSPathProxyConnects(ch <-chan string) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}
