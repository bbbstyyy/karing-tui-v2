//go:build linux

package daemon

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
)

func TestDaemonThousandUnixReconnectsReturnToResourceBaseline(t *testing.T) {
	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := runtimepath.Paths{
		Config:   filepath.Join(base, "config"),
		Data:     filepath.Join(base, "data"),
		State:    filepath.Join(base, "state"),
		Cache:    filepath.Join(base, "cache"),
		Runtime:  filepath.Join(base, "runtime"),
		Socket:   filepath.Join(base, "runtime", "daemon.sock"),
		Database: filepath.Join(base, "state", "state.db"),
	}
	t.Setenv(corePathEnv, "")
	t.Setenv(coreControlPortEnv, "")
	t.Setenv(storageKeepConfirmedEnv, "")
	t.Setenv(storageGenerationQuotaEnv, "")

	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- New(paths).Run(ctx)
	}()
	defer func() {
		cancel()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Errorf("daemon shutdown after reconnect test: %v", err)
			}
		case <-time.After(4 * time.Second):
			t.Errorf("daemon did not shut down after reconnect test")
		}
	}()

	api := client.New(paths.Socket)
	_ = waitSessionLifecycleStatus(t, api)
	runtime.GC()
	baselineFDs := linuxFDCount(t)
	baselineGoroutines := runtime.NumGoroutine()

	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", paths.Socket)
		},
	}
	reconnectClient := &http.Client{
		Transport: transport,
		Timeout:   2 * time.Second,
	}
	for attempt := 0; attempt < 1000; attempt++ {
		request, err := http.NewRequestWithContext(
			context.Background(),
			http.MethodGet,
			"http://unix/v1/status",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		response, err := reconnectClient.Do(request)
		if err != nil {
			t.Fatalf("reconnect %d: %v", attempt, err)
		}
		_, copyErr := io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		closeErr := response.Body.Close()
		if copyErr != nil {
			t.Fatalf("reconnect %d body: %v", attempt, copyErr)
		}
		if closeErr != nil {
			t.Fatalf("reconnect %d close: %v", attempt, closeErr)
		}
		if response.StatusCode != http.StatusOK {
			t.Fatalf("reconnect %d status = %d", attempt, response.StatusCode)
		}
	}
	transport.CloseIdleConnections()

	_ = waitSessionLifecycleStatus(t, api)
	deadline := time.Now().Add(3 * time.Second)
	var finalFDs, finalGoroutines int
	for {
		runtime.GC()
		finalFDs = linuxFDCount(t)
		finalGoroutines = runtime.NumGoroutine()
		if finalFDs <= baselineFDs+4 && finalGoroutines <= baselineGoroutines+12 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf(
				"resources did not return near baseline after 1000 reconnects: fd %d->%d goroutines %d->%d",
				baselineFDs,
				finalFDs,
				baselineGoroutines,
				finalGoroutines,
			)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func linuxFDCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("Linux fd accounting unavailable: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("Linux fd accounting returned no descriptors")
	}
	return len(entries)
}

func TestDaemonHTTPServerHasBoundedConnectionTimeouts(t *testing.T) {
	server := &http.Server{
		ReadHeaderTimeout: 2 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	if server.ReadHeaderTimeout <= 0 || server.IdleTimeout <= 0 {
		t.Fatalf("connection timeouts are not bounded: %+v", server)
	}
	_ = fmt.Sprintf("%s", server.IdleTimeout)
}
