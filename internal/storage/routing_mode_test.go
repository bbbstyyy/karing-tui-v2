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
	if initial.RoutingMode != RoutingModeRule {
		t.Fatalf("initial routing mode = %q, want rule", initial.RoutingMode)
	}
	if err := store.SetRoutingMode(ctx, RoutingModeGlobal); err != nil {
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
	if snapshot.RoutingMode != RoutingModeGlobal {
		t.Fatalf("reopened routing mode = %q, want global", snapshot.RoutingMode)
	}
	if err := reopened.SetRoutingMode(ctx, RoutingMode("unsupported")); !errors.Is(err, ErrInvalidRoutingMode) {
		t.Fatalf("invalid routing mode error = %v", err)
	}
}
