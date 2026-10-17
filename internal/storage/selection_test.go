package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentSelectionIntentPersistsAcrossReopen(t *testing.T) {
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
	if _, ok, err := store.CurrentSelectionIntent(ctx); err != nil || ok {
		t.Fatalf("empty selection intent = ok:%t err:%v", ok, err)
	}
	want := []byte(`{"kind":"specific_node","profile_id":"profile-a","node_id":"node-a"}`)
	written, err := store.SetCurrentSelectionIntent(ctx, want)
	if err != nil {
		t.Fatal(err)
	}
	if string(written.TargetJSON) != string(want) || written.UpdatedAt.IsZero() {
		t.Fatalf("written selection intent = %+v", written)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, ok, err := reopened.CurrentSelectionIntent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(got.TargetJSON) != string(want) || got.UpdatedAt.IsZero() {
		t.Fatalf("reopened selection intent = ok:%t value:%+v", ok, got)
	}
}

func TestCurrentSelectionIntentRejectsInvalidJSON(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(ctx, filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	if _, err := store.SetCurrentSelectionIntent(ctx, []byte("{")); !errors.Is(err, ErrInvalidSelectionIntent) {
		t.Fatalf("invalid selection intent error = %v", err)
	}
}
