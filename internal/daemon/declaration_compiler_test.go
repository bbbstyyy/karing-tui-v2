package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	corecompiler "github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type fakeDeclarationRevisionStore struct {
	revision       storage.DeclarationRevision
	err            error
	calls          int
	selection      storage.SelectionIntent
	hasSelection   bool
	selectionError error
}

func (s *fakeDeclarationRevisionStore) CurrentSelectionIntent(context.Context) (storage.SelectionIntent, bool, error) {
	if s.selectionError != nil {
		return storage.SelectionIntent{}, false, s.selectionError
	}
	return s.selection, s.hasSelection, nil
}

func (s *fakeDeclarationRevisionStore) Declaration(_ context.Context, revision uint64) (storage.DeclarationRevision, error) {
	s.calls++
	if s.err != nil {
		return storage.DeclarationRevision{}, s.err
	}
	out := s.revision
	out.DocumentJSON = append([]byte(nil), s.revision.DocumentJSON...)
	return out, nil
}

type fakeDeclarationCompilerEngine struct {
	artifact      corecompiler.NativeConfigArtifact
	err           error
	calls         int
	overrideCalls int
	document      []byte
	target        domain.TargetRef
}

func (e *fakeDeclarationCompilerEngine) CompileDeclaration(_ context.Context, document []byte) (corecompiler.NativeConfigArtifact, error) {
	e.calls++
	e.document = append([]byte(nil), document...)
	if len(document) != 0 {
		document[0] ^= 1
	}
	if e.err != nil {
		return corecompiler.NativeConfigArtifact{}, e.err
	}
	return e.artifact, nil
}

func (e *fakeDeclarationCompilerEngine) CompileDeclarationWithCurrentSelection(
	_ context.Context,
	document []byte,
	target domain.TargetRef,
) (corecompiler.NativeConfigArtifact, error) {
	e.overrideCalls++
	e.document = append([]byte(nil), document...)
	e.target = target
	if e.err != nil {
		return corecompiler.NativeConfigArtifact{}, e.err
	}
	return e.artifact, nil
}

func TestDeclarationCompileCoordinatorBindsExactStoredRevision(t *testing.T) {
	document := []byte(`{"schema_version":1}`)
	sum := sha256.Sum256(document)
	hash := hex.EncodeToString(sum[:])
	store := &fakeDeclarationRevisionStore{revision: storage.DeclarationRevision{
		Revision:     7,
		DocumentJSON: append([]byte(nil), document...),
		SHA256:       hash,
	}}
	engine := &fakeDeclarationCompilerEngine{artifact: declarationCompilerTestArtifact()}
	coordinator, err := NewDeclarationCompileCoordinator(store, engine)
	if err != nil {
		t.Fatal(err)
	}

	artifact, err := coordinator.CompileRevision(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if store.calls != 1 || engine.calls != 1 {
		t.Fatalf("unexpected calls: store=%d compiler=%d", store.calls, engine.calls)
	}
	if string(engine.document) != string(document) {
		t.Fatalf("compiler received %q, want %q", engine.document, document)
	}
	if string(store.revision.DocumentJSON) != string(document) {
		t.Fatal("compiler mutation escaped into stored declaration fixture")
	}
	if artifact.Manifest.DeclarationRevision != 7 || artifact.Manifest.DeclarationSHA256 != hash {
		t.Fatalf("unexpected declaration binding: %+v", artifact.Manifest)
	}
	if err := artifact.ValidateDeclarationBinding(true); err != nil {
		t.Fatal(err)
	}
}

func TestDeclarationCompileCoordinatorRejectsStoredHashMismatchBeforeCompiler(t *testing.T) {
	store := &fakeDeclarationRevisionStore{revision: storage.DeclarationRevision{
		Revision:     2,
		DocumentJSON: []byte(`{"schema_version":1}`),
		SHA256:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}}
	engine := &fakeDeclarationCompilerEngine{artifact: declarationCompilerTestArtifact()}
	coordinator, err := NewDeclarationCompileCoordinator(store, engine)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := coordinator.CompileRevision(context.Background(), 2); !errors.Is(err, ErrDeclarationIntegrity) {
		t.Fatalf("integrity error = %v", err)
	}
	if engine.calls != 0 {
		t.Fatalf("compiler called for corrupt declaration: %d", engine.calls)
	}
}

func TestDeclarationCompileCoordinatorRejectsSyntheticRevision(t *testing.T) {
	store := &fakeDeclarationRevisionStore{}
	engine := &fakeDeclarationCompilerEngine{artifact: declarationCompilerTestArtifact()}
	coordinator, err := NewDeclarationCompileCoordinator(store, engine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.CompileRevision(context.Background(), 0); !errors.Is(err, ErrDeclarationIntegrity) {
		t.Fatalf("revision zero error = %v", err)
	}
	if store.calls != 0 || engine.calls != 0 {
		t.Fatalf("revision zero reached dependencies: store=%d compiler=%d", store.calls, engine.calls)
	}
}

func TestDeclarationCompileCoordinatorPropagatesCompilerFailureWithoutBinding(t *testing.T) {
	document := []byte(`{"schema_version":1}`)
	sum := sha256.Sum256(document)
	store := &fakeDeclarationRevisionStore{revision: storage.DeclarationRevision{
		Revision:     3,
		DocumentJSON: document,
		SHA256:       hex.EncodeToString(sum[:]),
	}}
	engine := &fakeDeclarationCompilerEngine{err: errors.New("unsupported declaration field")}
	coordinator, err := NewDeclarationCompileCoordinator(store, engine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.CompileRevision(context.Background(), 3); err == nil {
		t.Fatal("compiler failure unexpectedly succeeded")
	}
}

func TestNewDeclarationCompileCoordinatorRejectsNilDependencies(t *testing.T) {
	engine := &fakeDeclarationCompilerEngine{}
	store := &fakeDeclarationRevisionStore{}
	if _, err := NewDeclarationCompileCoordinator(nil, engine); err == nil {
		t.Fatal("nil store unexpectedly accepted")
	}
	if _, err := NewDeclarationCompileCoordinator(store, nil); err == nil {
		t.Fatal("nil compiler unexpectedly accepted")
	}
}

func declarationCompilerTestArtifact() corecompiler.NativeConfigArtifact {
	config := []byte(`{}`)
	sum := sha256.Sum256(config)
	hash := hex.EncodeToString(sum[:])
	return corecompiler.NativeConfigArtifact{
		JSON:   config,
		SHA256: hash,
		Manifest: corecompiler.NativeManifest{
			SchemaID:     corecompiler.NativeSchemaID,
			ConfigSHA256: hash,
		},
		SourceMap: []corecompiler.RouteSourceMapEntry{},
	}
}


func TestDeclarationCompileCoordinatorAppliesPersistedCurrentSelection(t *testing.T) {
	document := []byte(`{"schema_version":1}`)
	sum := sha256.Sum256(document)
	target := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	targetJSON := []byte(`{"kind":"specific_node","profile_id":"profile-a","node_id":"node-a"}`)
	store := &fakeDeclarationRevisionStore{
		revision: storage.DeclarationRevision{
			Revision:     4,
			DocumentJSON: append([]byte(nil), document...),
			SHA256:       hex.EncodeToString(sum[:]),
		},
		selection:    storage.SelectionIntent{TargetJSON: targetJSON},
		hasSelection: true,
	}
	engine := &fakeDeclarationCompilerEngine{artifact: declarationCompilerTestArtifact()}
	coordinator, err := NewDeclarationCompileCoordinator(store, engine)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.CompileRevision(context.Background(), 4); err != nil {
		t.Fatal(err)
	}
	if engine.calls != 0 || engine.overrideCalls != 1 {
		t.Fatalf("compiler calls = normal:%d override:%d", engine.calls, engine.overrideCalls)
	}
	if engine.target != target {
		t.Fatalf("selection target = %+v, want %+v", engine.target, target)
	}
}
