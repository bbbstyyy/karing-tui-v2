package backupclosure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type fixture struct {
	store               *storage.Store
	rules               *coreartifact.Store
	stateRoot           string
	parent              string
	rulePath            string
	ruleHash            string
	ruleData            []byte
	configRevision      uint64
	declarationRevision uint64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(root, "snapshot-staging")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(context.Background(), filepath.Join(root, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ruleStore, err := coreartifact.NewStore(filepath.Join(root, "core"))
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"version":4,"rules":[{"domain":["private.example"]}]}`)
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	path, _, err := ruleStore.PutRuleSet(context.Background(), bytes.NewReader(content), hash, "source")
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{store: store, rules: ruleStore, stateRoot: root, parent: parent, rulePath: path, ruleHash: hash, ruleData: content}
}

func (f *fixture) commit(t *testing.T, includeRule bool) int64 {
	t.Helper()
	ctx := context.Background()
	declaration := []byte(fmt.Sprintf(`{"version":1,"sequence":%d}`, f.declarationRevision+1))
	declared, err := f.store.CommitDeclaration(ctx, f.declarationRevision, declaration, "test:backup-closure")
	if err != nil {
		t.Fatal(err)
	}
	f.declarationRevision = declared.Revision
	rules := make([]compiler.NativeRuleSetManifest, 0)
	nativeRules := make([]map[string]any, 0)
	if includeRule {
		r := compiler.NativeRuleSetManifest{Ref: "cn-preset-private", RuntimeTag: "rs-" + shaHex([]byte("cn-preset-private")), RuntimePath: f.rulePath,
			SHA256: f.ruleHash, Format: compiler.RuleSetFormatSource}
		rules = append(rules, r)
		nativeRules = append(nativeRules, map[string]any{"type": "local", "tag": r.RuntimeTag,
			"path": r.RuntimePath, "format": r.Format})
	}
	config, err := json.Marshal(map[string]any{
		"route":        map[string]any{"rule_set": nativeRules},
		"private_note": "token-DO-NOT-EXPOSE",
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(config)
	manifest := compiler.NativeManifest{
		SchemaID: compiler.NativeSchemaID, ConfigSHA256: hex.EncodeToString(sum[:]),
		DeclarationRevision: declared.Revision, DeclarationSHA256: declared.SHA256,
		RuleSets: rules,
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := f.store.PrepareApplyWithMetadata(ctx, f.configRevision, config, encoded, []byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginActivation(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginVerification(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CommitApplied(ctx, attempt.ID, true); err != nil {
		t.Fatal(err)
	}
	f.configRevision++
	return attempt.GenerationID
}

func requireNoBackupScopes(t *testing.T, f *fixture) {
	t.Helper()
	entries, err := os.ReadDir(f.parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("private database scopes leaked: %+v err=%v", entries, err)
	}
	ruleScopes := filepath.Join(f.stateRoot, "core", "historical-check-snapshots")
	entries, err = os.ReadDir(ruleScopes)
	if err == nil && len(entries) != 0 {
		t.Fatalf("private rule-copy scopes leaked: %+v", entries)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestBuildClosurePinsAndCopiesDeduplicatedResources(t *testing.T) {
	f := newFixture(t)
	one := f.commit(t, true)
	two := f.commit(t, true)
	ctx := context.Background()
	closure, err := Build(ctx, f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	if closure.Inventory.Format != ManifestVersion || closure.Inventory.StorageSchema != supportedStorageSchema ||
		!closure.Inventory.ContainsCredentials || closure.Inventory.RestoreReady ||
		len(closure.Inventory.Generations) != 2 || len(closure.Inventory.RuleSets) != 1 ||
		closure.Inventory.Generations[0].ID != one || closure.Inventory.Generations[1].ID != two {
		t.Fatalf("unexpected bounded resource inventory: %+v", closure.Inventory)
	}
	rule := closure.Inventory.RuleSets[0]
	if rule.SHA256 != f.ruleHash || rule.Size != int64(len(f.ruleData)) ||
		rule.RelativePath != "rule-sets/sha256/"+f.ruleHash+".json" {
		t.Fatalf("unbound rule: %+v", rule)
	}
	if closure.Inventory.DatabaseSHA256 != closure.Database.SHA256 ||
		closure.Inventory.DatabaseBytes != closure.Database.Size || len(closure.InventorySHA256) != 64 {
		t.Fatal("unbound database manifest")
	}
	if bytes.Contains(closure.InventoryJSON, []byte("token-DO-NOT-EXPOSE")) ||
		bytes.Contains(closure.InventoryJSON, []byte(f.stateRoot)) {
		t.Fatal("private content or paths leaked into manifest")
	}
	path, ok := closure.copies.FileFor(f.rulePath)
	if !ok {
		t.Fatal("missing independently copied rule file")
	}
	original, err := os.Stat(f.rulePath)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.Stat(path)
	if err != nil || os.SameFile(original, copied) || copied.Mode().Perm() != 0o400 {
		t.Fatalf("unsafe rule copy: %v %v", copied, err)
	}
	if err := closure.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}
	if err := closure.Close(); err != nil {
		t.Fatal("duplicate Close was not idempotent")
	}
	requireNoBackupScopes(t, f)
}

func TestBuildClosureCapturesStableDatabaseCopyAcrossLiveWrites(t *testing.T) {
	f := newFixture(t)
	first := f.commit(t, true)
	closure, err := build(context.Background(), f.store, f.stateRoot, f.parent, func(*Closure) {
		// A live declaration revision is committed after the database copy.
		if _, err := f.store.CommitDeclaration(context.Background(), f.declarationRevision,
			[]byte(`{"version":1,"sequence":999}`), "test:concurrent-writer"); err != nil {
			t.Error(err)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(closure.Inventory.Generations) != 1 || closure.Inventory.Generations[0].ID != first {
		t.Fatal("live state leaked into copied database inventory")
	}
	if err := closure.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoBackupScopes(t, f)
}

func TestBuildClosureFailsClosedForMissingAndCorruptResource(t *testing.T) {
	for _, name := range []string{"missing", "changed_bytes", "symlink", "inode_swap_during_copy", "corrupt_isolated_copy", "corrupt_database_copy"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.commit(t, true)
			var injected func(*Closure)
			switch name {
			case "missing":
				if err := os.Remove(f.rulePath); err != nil {
					t.Fatal(err)
				}
			case "changed_bytes":
				if err := os.WriteFile(f.rulePath, []byte(`{"evil":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(f.rulePath, f.rulePath+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(f.rulePath+".old", f.rulePath); err != nil {
					t.Fatal(err)
				}
			case "inode_swap_during_copy":
				injected = func(*Closure) {
					if err := os.Rename(f.rulePath, f.rulePath+".old"); err != nil {
						t.Error(err)
						return
					}
					if err := os.WriteFile(f.rulePath, f.ruleData, 0o600); err != nil {
						t.Error(err)
					}
				}
			case "corrupt_isolated_copy":
				injected = func(c *Closure) {
					p, ok := c.copies.FileFor(f.rulePath)
					if !ok {
						t.Error("missing isolated copy")
						return
					}
					if err := os.Chmod(p, 0o600); err != nil {
						t.Error(err)
						return
					}
					if err := os.WriteFile(p, []byte("corrupted copy"), 0o600); err != nil {
						t.Error(err)
					}
				}
			case "corrupt_database_copy":
				injected = func(c *Closure) {
					fd, err := os.OpenFile(c.Database.Path, os.O_WRONLY, 0)
					if err != nil {
						t.Error(err)
						return
					}
					_, err = fd.WriteAt([]byte{0x1, 0x2, 0x3, 0x4}, 128)
					if err != nil {
						t.Error(err)
					}
					_ = fd.Close()
				}
			}
			closure, err := build(context.Background(), f.store, f.stateRoot, f.parent, injected)
			if closure != nil || !errors.Is(err, ErrUnsafeClosure) {
				t.Fatalf("unsafe closure accepted: %v err=%v", closure, err)
			}
			requireNoBackupScopes(t, f)
		})
	}
}

func TestBuildClosureRejectsIncompleteLegacyMetadata(t *testing.T) {
	f := newFixture(t)
	attempt, err := f.store.PrepareApply(context.Background(), 0, []byte(`{"route":{"rule_set":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginActivation(context.Background(), attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginVerification(context.Background(), attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CommitApplied(context.Background(), attempt.ID, true); err != nil {
		t.Fatal(err)
	}
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if closure != nil || !errors.Is(err, ErrUnsafeClosure) {
		t.Fatalf("legacy generation accepted: %v %v", closure, err)
	}
	requireNoBackupScopes(t, f)
}

func TestBuildClosureManifestTamperingAndCanceledContext(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if closure, err := Build(ctx, f.store, f.stateRoot, f.parent); closure != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled closure accepted: %v %v", closure, err)
	}
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	closure.Inventory.RuleSets[0].Size++
	if err := closure.Verify(context.Background()); !errors.Is(err, ErrUnsafeClosure) {
		t.Fatalf("tampered manifest accepted: %v", err)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoBackupScopes(t, f)
}

func TestBuildClosureSupportsEmptyRetainedHistory(t *testing.T) {
	f := newFixture(t)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(closure.Inventory.Generations) != 0 || len(closure.Inventory.RuleSets) != 0 || closure.Inventory.RestoreReady {
		t.Fatalf("empty closure incorrect: %+v", closure.Inventory)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoBackupScopes(t, f)
}

func TestBuildClosureRefusesUnsafeStateRootAndMalformedBoundNativeRules(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	aliases := []string{"", "relative", f.stateRoot + "/../" + filepath.Base(f.stateRoot)}
	for _, stateRoot := range aliases {
		if c, err := Build(context.Background(), f.store, stateRoot, f.parent); c != nil || !errors.Is(err, ErrUnsafeClosure) {
			t.Fatalf("unsafe root accepted: %q %v", stateRoot, err)
		}
	}
	f2 := newFixture(t)
	ctx := context.Background()
	declaration, err := f2.store.CommitDeclaration(ctx, 0, []byte(`{"v":1}`), "test:forged")
	if err != nil {
		t.Fatal(err)
	}
	// Config contains one native local rule, while signed compiler manifest
	// claims zero. Both stored payload hashes are correct but closure is not.
	native, err := json.Marshal(map[string]any{"route": map[string]any{"rule_set": []map[string]any{{
		"type": "local", "tag": "bad", "path": f2.rulePath, "format": "source",
	}}}})
	if err != nil {
		t.Fatal(err)
	}
	manifest := compiler.NativeManifest{SchemaID: compiler.NativeSchemaID, ConfigSHA256: shaHex(native), DeclarationRevision: declaration.Revision, DeclarationSHA256: declaration.SHA256}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := f2.store.PrepareApplyWithMetadata(ctx, 0, native, encoded, []byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	if err := f2.store.BeginActivation(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := f2.store.BeginVerification(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := f2.store.CommitApplied(ctx, attempt.ID, true); err != nil {
		t.Fatal(err)
	}
	if c, err := Build(ctx, f2.store, f2.stateRoot, f2.parent); c != nil || !errors.Is(err, ErrUnsafeClosure) {
		t.Fatalf("unlisted local rule accepted: %v %v", c, err)
	}
	requireNoBackupScopes(t, f2)
}

func TestBuildClosureDoesNotReturnSensitivePathsInErrors(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	if err := os.Remove(f.rulePath); err != nil {
		t.Fatal(err)
	}
	_, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err == nil || strings.Contains(err.Error(), f.stateRoot) || strings.Contains(err.Error(), "private_note") {
		t.Fatalf("sensitive paths leaked into build error: %v", err)
	}
}

func TestBuildClosureRejectsHardlinkedSourceArtifact(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	outside := filepath.Join(f.stateRoot, "unsafe-shared-hardlink")
	if err := os.Link(f.rulePath, outside); err != nil {
		t.Fatal(err)
	}
	if c, err := Build(context.Background(), f.store, f.stateRoot, f.parent); c != nil || !errors.Is(err, ErrUnsafeClosure) {
		t.Fatalf("hardlinked rule source was accepted: %v %v", c, err)
	}
	requireNoBackupScopes(t, f)
}

func TestBuildClosureRejectsExcessManifestRuleEntriesWithoutReadingThem(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	decl, err := f.store.CommitDeclaration(ctx, 0, []byte(`{"v":1}`), "test:too-many")
	if err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"route":{"rule_set":[]}}`)
	manifest := compiler.NativeManifest{
		SchemaID: compiler.NativeSchemaID, ConfigSHA256: shaHex(config),
		DeclarationRevision: decl.Revision, DeclarationSHA256: decl.SHA256,
	}
	for i := 0; i < MaxClosureRuleSets+1; i++ {
		manifest.RuleSets = append(manifest.RuleSets, compiler.NativeRuleSetManifest{
			Ref: fmt.Sprintf("resource-%d", i), RuntimeTag: fmt.Sprintf("tag-%d", i),
			RuntimePath: filepath.Join(f.stateRoot, "core", "rule-sets", "sha256", fmt.Sprintf("%064x.json", i)),
			SHA256:      fmt.Sprintf("%064x", i), Format: compiler.RuleSetFormatSource,
		})
	}
	metadata, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := f.store.PrepareApplyWithMetadata(ctx, 0, config, metadata, []byte(`[]`))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginActivation(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.BeginVerification(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.store.CommitApplied(ctx, attempt.ID, true); err != nil {
		t.Fatal(err)
	}
	if closure, err := Build(ctx, f.store, f.stateRoot, f.parent); closure != nil || !errors.Is(err, ErrUnsafeClosure) {
		t.Fatalf("overlimit resources accepted: %v %v", closure, err)
	}
	requireNoBackupScopes(t, f)
}
