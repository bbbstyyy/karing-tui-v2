package coreapi

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestMixedInboundProbeRequiresSOCKS5OnAllThreeListeners(t *testing.T) {
	rule, closeRule := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeRule()
	direct, closeDirect := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeDirect()
	selected, closeSelected := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeSelected()

	set := inboundSetFromAddresses(t, rule, direct, selected)
	probe, err := NewMixedInboundProbe(set)
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Ready(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestMixedInboundProbeRejectsWrongProtocolOnExpectedPort(t *testing.T) {
	rule, closeRule := startSOCKS5GreetingServer(t, []byte("HT"))
	defer closeRule()
	direct, closeDirect := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeDirect()
	selected, closeSelected := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeSelected()

	set := inboundSetFromAddresses(t, rule, direct, selected)
	probe, err := NewMixedInboundProbe(set)
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Ready(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("probe error = %v, want protocol mismatch", err)
	}
}

func TestLocalHealthProbeChecksAuthenticatedControlThenMixedListeners(t *testing.T) {
	const secret = "local-secret"
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secret {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"version":"sing-box test","premium":true,"meta":true}`)
	}))
	defer control.Close()

	rule, closeRule := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeRule()
	direct, closeDirect := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeDirect()
	selected, closeSelected := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeSelected()

	probe, err := NewLocalHealthProbe(control.URL, secret, inboundSetFromAddresses(t, rule, direct, selected))
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Ready(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func startSOCKS5GreetingServer(t *testing.T, response []byte) (netip.AddrPort, func()) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

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
				var greeting [3]byte
				_, _ = ioReadFull(conn, greeting[:])
				_, _ = conn.Write(response)
			}(conn)
		}
	}()

	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		closeFn()
		t.Fatal(err)
	}
	return address, closeFn
}

func inboundSetFromAddresses(t *testing.T, rule, direct, selected netip.AddrPort) domain.InboundSet {
	t.Helper()
	if rule.Addr() != direct.Addr() || rule.Addr() != selected.Addr() {
		t.Fatal("test listeners did not share the same loopback address")
	}
	return domain.InboundSet{
		Listen:       rule.Addr(),
		RulePort:     rule.Port(),
		DirectPort:   direct.Port(),
		SelectedPort: selected.Port(),
	}
}

func ioReadFull(conn net.Conn, buffer []byte) (int, error) {
	total := 0
	for total < len(buffer) {
		n, err := conn.Read(buffer[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestLocalHealthProbeRetriesTransientControlStartup(t *testing.T) {
	const secret = "local-secret"

	controlListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	controlAddress := controlListener.Addr().String()
	if err := controlListener.Close(); err != nil {
		t.Fatal(err)
	}

	rule, closeRule := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeRule()
	direct, closeDirect := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeDirect()
	selected, closeSelected := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeSelected()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		time.Sleep(75 * time.Millisecond)
		listener, listenErr := net.Listen("tcp4", controlAddress)
		if listenErr != nil {
			return
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "Bearer "+secret {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"version":"sing-box test","premium":true,"meta":true}`)
		})}
		go func() {
			<-time.After(300 * time.Millisecond)
			_ = server.Close()
		}()
		_ = server.Serve(listener)
	}()

	probe, err := NewLocalHealthProbe("http://"+controlAddress, secret, inboundSetFromAddresses(t, rule, direct, selected))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := probe.Ready(ctx, nil); err != nil {
		t.Fatalf("delayed control readiness failed: %v", err)
	}
	<-serverDone
}

func TestLocalHealthProbeDoesNotRetryDeterministicAuthFailure(t *testing.T) {
	const secret = "expected-secret"
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer control.Close()

	rule, closeRule := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeRule()
	direct, closeDirect := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeDirect()
	selected, closeSelected := startSOCKS5GreetingServer(t, []byte{0x05, 0x00})
	defer closeSelected()

	probe, err := NewLocalHealthProbe(control.URL, secret, inboundSetFromAddresses(t, rule, direct, selected))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	err = probe.Ready(ctx, nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("auth failure = %v, want HTTP 401", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("deterministic auth failure was retried for %s", elapsed)
	}
}
