package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	corecompiler "github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrDeclarationIntegrity = errors.New("declaration revision integrity check failed")

type declarationRevisionStore interface {
	Declaration(context.Context, uint64) (storage.DeclarationRevision, error)
	CurrentSelectionIntent(context.Context) (storage.SelectionIntent, bool, error)
}

type declarationCompilerEngine interface {
	CompileDeclaration(context.Context, []byte) (corecompiler.NativeConfigArtifact, error)
	CompileDeclarationWithCurrentSelection(context.Context, []byte, domain.TargetRef) (corecompiler.NativeConfigArtifact, error)
}

type DeclarationCompileCoordinator struct {
	store    declarationRevisionStore
	compiler declarationCompilerEngine
}

func NewDeclarationCompileCoordinator(
	store declarationRevisionStore,
	compiler declarationCompilerEngine,
) (*DeclarationCompileCoordinator, error) {
	if store == nil {
		return nil, errors.New("declaration revision store is nil")
	}
	if compiler == nil {
		return nil, errors.New("declaration compiler engine is nil")
	}
	return &DeclarationCompileCoordinator{store: store, compiler: compiler}, nil
}

func (c *DeclarationCompileCoordinator) CompileRevision(
	ctx context.Context,
	revision uint64,
) (corecompiler.NativeConfigArtifact, error) {
	if revision == 0 {
		return corecompiler.NativeConfigArtifact{}, fmt.Errorf("%w: revision zero is synthetic and cannot be compiled", ErrDeclarationIntegrity)
	}
	stored, err := c.store.Declaration(ctx, revision)
	if err != nil {
		return corecompiler.NativeConfigArtifact{}, err
	}
	if stored.Revision != revision {
		return corecompiler.NativeConfigArtifact{}, fmt.Errorf(
			"%w: requested revision %d, store returned %d",
			ErrDeclarationIntegrity,
			revision,
			stored.Revision,
		)
	}
	if len(stored.DocumentJSON) == 0 || stored.SHA256 == "" {
		return corecompiler.NativeConfigArtifact{}, fmt.Errorf("%w: revision %d is incomplete", ErrDeclarationIntegrity, revision)
	}
	sum := sha256.Sum256(stored.DocumentJSON)
	actual := hex.EncodeToString(sum[:])
	if actual != stored.SHA256 {
		return corecompiler.NativeConfigArtifact{}, fmt.Errorf(
			"%w: revision %d SHA-256 mismatch: got %s want %s",
			ErrDeclarationIntegrity,
			revision,
			actual,
			stored.SHA256,
		)
	}

	document := append([]byte(nil), stored.DocumentJSON...)
	intent, hasIntent, err := c.store.CurrentSelectionIntent(ctx)
	if err != nil {
		return corecompiler.NativeConfigArtifact{}, fmt.Errorf("read current selection intent: %w", err)
	}
	var artifact corecompiler.NativeConfigArtifact
	if hasIntent {
		var target domain.TargetRef
		decoder := json.NewDecoder(bytes.NewReader(intent.TargetJSON))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&target); err != nil {
			return corecompiler.NativeConfigArtifact{}, fmt.Errorf("decode current selection intent: %w", err)
		}
		if err := requireJSONEOF(decoder); err != nil {
			return corecompiler.NativeConfigArtifact{}, fmt.Errorf("decode current selection intent: %w", err)
		}
		artifact, err = c.compiler.CompileDeclarationWithCurrentSelection(ctx, document, target)
	} else {
		artifact, err = c.compiler.CompileDeclaration(ctx, document)
	}
	if err != nil {
		return corecompiler.NativeConfigArtifact{}, fmt.Errorf("compile declaration revision %d: %w", revision, err)
	}
	bound, err := artifact.BindDeclaration(stored.Revision, stored.SHA256)
	if err != nil {
		return corecompiler.NativeConfigArtifact{}, fmt.Errorf("bind declaration revision %d: %w", revision, err)
	}
	return bound, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
