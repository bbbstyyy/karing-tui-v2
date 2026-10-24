package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestSelectionRevisionCASAndLegacyWriteInvalidation(t *testing.T) {
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
	decl, err := store.CommitDeclaration(ctx, 0, []byte("{}"), "test:selection-checked")
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("{\"kind\":\"direct\"}")
	second := []byte("{\"kind\":\"specific_node\",\"profile_id\":\"a\",\"node_id\":\"b\"}")
	got, persisted, err := store.CurrentSelectionIntent(ctx)
	if err != nil || persisted || got.Revision != 0 {
		t.Fatalf("initial revision: %+v persisted:%t err:%v", got, persisted, err)
	}
	expected := SelectionPrecondition{Revision: 0, ConfigRevision: 0, DeclarationRevision: decl.Revision}
	saved, err := store.SetCurrentSelectionIntentChecked(ctx, first, expected)
	if err != nil || saved.Revision != 1 {
		t.Fatalf("checked write = %+v error=%v", saved, err)
	}
	_, err = store.SetCurrentSelectionIntentChecked(ctx, second, expected)
	if !errors.Is(err, ErrSelectionRevisionConflict) {
		t.Fatalf("stale checked write = %v", err)
	}
	legacy, err := store.SetCurrentSelectionIntent(ctx, second)
	if err != nil || legacy.Revision != 2 {
		t.Fatalf("legacy revision increment: %+v %v", legacy, err)
	}
	_, err = store.SetCurrentSelectionIntentChecked(ctx, first, SelectionPrecondition{
		Revision: 1, ConfigRevision: 0, DeclarationRevision: decl.Revision,
	})
	if !errors.Is(err, ErrSelectionRevisionConflict) {
		t.Fatalf("legacy write must invalidate stale CAS: %v", err)
	}
	current, ok, err := store.CurrentSelectionIntent(ctx)
	if err != nil || !ok || current.Revision != 2 || string(current.TargetJSON) != string(second) {
		t.Fatalf("post conflict value = %+v ok=%t err=%v", current, ok, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	current, ok, err = reopened.CurrentSelectionIntent(ctx)
	if err != nil || !ok || current.Revision != 2 || string(current.TargetJSON) != string(second) {
		t.Fatalf("revision not persisted across restart: %+v ok=%t err=%v", current, ok, err)
	}
}

func TestSelectionCASRejectsChangedDeclarationAndActiveApply(t *testing.T) {
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
	decl, err := store.CommitDeclaration(ctx, 0, []byte("{}"), "test:binding-a")
	if err != nil {
		t.Fatal(err)
	}
	expected := SelectionPrecondition{Revision: 0, ConfigRevision: 0, DeclarationRevision: decl.Revision}
	if _, err := store.CommitDeclaration(ctx, decl.Revision, []byte("{\"next\":true}"), "test:binding-b"); err != nil {
		t.Fatal(err)
	}
	_, err = store.SetCurrentSelectionIntentChecked(ctx, []byte("{\"kind\":\"direct\"}"), expected)
	if !errors.Is(err, ErrSelectionRevisionConflict) {
		t.Fatalf("declaration drift was not rejected: %v", err)
	}
	expected.DeclarationRevision++
	attempt, err := store.PrepareApply(ctx, 0, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.SetCurrentSelectionIntentChecked(ctx, []byte("{\"kind\":\"direct\"}"), expected)
	if !errors.Is(err, ErrSelectionRevisionConflict) {
		t.Fatalf("in-flight apply did not block guarded selection: %v", err)
	}
	if err := store.AbortPrepared(ctx, attempt.ID, "test cleanup"); err != nil {
		t.Fatal(err)
	}
	_, err = store.SetCurrentSelectionIntentChecked(ctx, []byte("{\"kind\":\"direct\"}"),
		SelectionPrecondition{Revision: 0, ConfigRevision: 1, DeclarationRevision: expected.DeclarationRevision})
	if !errors.Is(err, ErrSelectionRevisionConflict) {
		t.Fatalf("stale config revision was accepted: %v", err)
	}
	_, ok, err := store.CurrentSelectionIntent(ctx)
	if err != nil || ok {
		t.Fatalf("failed CAS wrote intent: ok=%t err=%v", ok, err)
	}
}

func TestSelectionCASConcurrentWritersExactlyOneWins(t *testing.T) {
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
	decl, err := store.CommitDeclaration(ctx, 0, []byte("{}"), "test:selection-race")
	if err != nil {
		t.Fatal(err)
	}
	expected := SelectionPrecondition{Revision: 0, ConfigRevision: 0, DeclarationRevision: decl.Revision}
	const workers = 10
	var wg sync.WaitGroup
	type outcome struct {
		success bool
		err     error
	}
	results := make(chan outcome, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			item, err := store.SetCurrentSelectionIntentChecked(ctx, []byte("{\"kind\":\"direct\"}"), expected)
			results <- outcome{success: err == nil && item.Revision == 1, err: err}
		}()
	}
	wg.Wait()
	close(results)
	success, conflict := 0, 0
	for result := range results {
		switch {
		case result.success:
			success++
		case errors.Is(result.err, ErrSelectionRevisionConflict):
			conflict++
		default:
			t.Fatalf("unexpected CAS outcome: %+v", result)
		}
	}
	if success != 1 || conflict != workers-1 {
		t.Fatalf("CAS winners=%d conflicts=%d", success, conflict)
	}
}
