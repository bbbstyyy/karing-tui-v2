package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestDeclarationRevisionChainIsImmutableAndCASProtected(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	current, err := store.CurrentDeclaration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != 0 || len(current.DocumentJSON) != 0 || current.ParentRevision != nil {
		t.Fatalf("initial declaration = %+v", current)
	}

	firstJSON := []byte(`{"preset":"cn","overrides":[]}`)
	first, err := store.CommitDeclaration(ctx, 0, firstJSON, "preset-init")
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 1 || first.ParentRevision != nil || first.Source != "preset-init" {
		t.Fatalf("first declaration = %+v", first)
	}
	if first.SHA256 != sha256String(firstJSON) {
		t.Fatalf("first hash = %q, want %q", first.SHA256, sha256String(firstJSON))
	}

	first.DocumentJSON[0] = 'x'
	storedFirst, err := store.Declaration(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(storedFirst.DocumentJSON) != string(firstJSON) {
		t.Fatalf("caller mutation changed persisted declaration: %q", storedFirst.DocumentJSON)
	}

	secondJSON := []byte(`{"preset":"cn","overrides":[{"group_id":"cn.google"}]}`)
	second, err := store.CommitDeclaration(ctx, 1, secondJSON, "api")
	if err != nil {
		t.Fatal(err)
	}
	if second.Revision != 2 || second.ParentRevision == nil || *second.ParentRevision != 1 {
		t.Fatalf("second declaration = %+v", second)
	}
	current, err = store.CurrentDeclaration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != 2 || string(current.DocumentJSON) != string(secondJSON) {
		t.Fatalf("current declaration = %+v", current)
	}

	storedFirst, err = store.Declaration(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(storedFirst.DocumentJSON) != string(firstJSON) {
		t.Fatal("historical declaration changed after later commit")
	}

	if _, err := store.CommitDeclaration(ctx, 1, []byte(`{"stale":true}`), "api"); !errors.Is(err, ErrDeclarationRevisionConflict) {
		t.Fatalf("stale declaration error = %v", err)
	}
}

func TestDeclarationRevisionValidationDoesNotChangeCurrentState(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	cases := []struct {
		name     string
		document []byte
		source   string
		want     error
	}{
		{name: "empty document", source: "api", want: ErrInvalidDeclaration},
		{name: "invalid json", document: []byte("{"), source: "api", want: ErrInvalidDeclaration},
		{name: "empty source", document: []byte(`{}`), want: ErrInvalidDeclaration},
		{name: "padded source", document: []byte(`{}`), source: " api", want: ErrInvalidDeclaration},
		{name: "unsafe source", document: []byte(`{}`), source: "api\nuser", want: ErrInvalidDeclaration},
		{name: "long source", document: []byte(`{}`), source: strings.Repeat("a", 129), want: ErrInvalidDeclaration},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := store.CommitDeclaration(ctx, 0, tc.document, tc.source); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			current, err := store.CurrentDeclaration(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if current.Revision != 0 {
				t.Fatalf("invalid declaration changed current revision: %+v", current)
			}
		})
	}
}

func TestDeclarationRevisionRejectsOversizedDocument(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	document := make([]byte, MaxDeclarationBytes+1)
	document[0] = '{'
	for i := 1; i < len(document)-1; i++ {
		document[i] = ' '
	}
	document[len(document)-1] = '}'
	if _, err := store.CommitDeclaration(ctx, 0, document, "api"); !errors.Is(err, ErrDeclarationTooLarge) {
		t.Fatalf("oversized declaration error = %v", err)
	}
}

func TestDeclarationRevisionPersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	store, path := newTestStore(t, ctx)
	document := []byte(`{"cn":{"region":"cn"}}`)
	committed, err := store.CommitDeclaration(ctx, 0, document, "preset-init")
	if err != nil {
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

	current, err := reopened.CurrentDeclaration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != committed.Revision ||
		current.SHA256 != committed.SHA256 ||
		current.Source != committed.Source ||
		string(current.DocumentJSON) != string(document) {
		t.Fatalf("reopened declaration = %+v, committed = %+v", current, committed)
	}
}

func TestDeclarationLookupRejectsMissingRevision(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()

	if _, err := store.Declaration(ctx, 99); !errors.Is(err, ErrDeclarationNotFound) {
		t.Fatalf("missing declaration error = %v", err)
	}
	zero, err := store.Declaration(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if zero.Revision != 0 || len(zero.DocumentJSON) != 0 {
		t.Fatalf("zero declaration = %+v", zero)
	}
}
