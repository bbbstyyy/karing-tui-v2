package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRoutingModeDefaultsAndPersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if initial.RoutingMode != RoutingModeRule || initial.PrivateDirect {
		t.Fatalf("initial routing policy = mode=%q private_direct=%t, want rule/false", initial.RoutingMode, initial.PrivateDirect)
	}
	if err := store.SetRoutingPolicy(ctx, RoutingModeGlobal, true); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	snapshot, err := reopened.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RoutingMode != RoutingModeGlobal || !snapshot.PrivateDirect {
		t.Fatalf("reopened routing policy = mode=%q private_direct=%t, want global/true", snapshot.RoutingMode, snapshot.PrivateDirect)
	}
	if err := reopened.SetRoutingMode(ctx, RoutingMode("unsupported")); !errors.Is(err, ErrInvalidRoutingMode) {
		t.Fatalf("invalid routing mode error = %v", err)
	}
}
