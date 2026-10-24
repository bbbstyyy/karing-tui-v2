//go:build linux

package daemon

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestProfileFetchOptionsUseAuthoritativeSelectedInbound(t *testing.T) {
	runtime := &serverRuntime{inbounds: domain.DefaultInboundSet()}
	options := profileFetchOptions(runtime)
	want := netip.MustParseAddrPort("127.0.0.1:2082")
	if options.SelectedProxy != want {
		t.Fatalf("selected profile fetch proxy = %v, want %v", options.SelectedProxy, want)
	}
}

func TestProfileFetchOptionsWithoutCoreDoNotInventSelectedProxy(t *testing.T) {
	options := profileFetchOptions(nil)
	if options.SelectedProxy.IsValid() {
		t.Fatalf("nil runtime invented selected proxy %v", options.SelectedProxy)
	}
}

func TestBuildProfileRefreshSchedulerWithoutCoreSupportsDirectFoundation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(ctx, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	scheduler, err := buildProfileRefreshScheduler(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if scheduler == nil {
		t.Fatal("profile refresh scheduler is nil")
	}
}

func TestServerRuntimeSelectedInboundRejectsInvalidUnsetConfiguration(t *testing.T) {
	runtime := &serverRuntime{}
	if selected, ok := runtime.SelectedInbound(); ok || selected.IsValid() {
		t.Fatalf("unset runtime selected inbound = %v ok=%v", selected, ok)
	}
}
