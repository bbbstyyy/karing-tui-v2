package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func historicalRuleSetHarness(t *testing.T) (
	*storage.Store, *fakeApplyCore, *serverRuntime, int64, string, string, []byte,
) {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	resourceStore, err := coreartifact.NewStore(filepath.Join(root, "core"))
	if err != nil {
		t.Fatal(err)
	}
	create := func(name string) (string, string, []byte) {
		t.Helper()
		payload := []byte(fmt.Sprintf(`{"version":4,"rules":[{"domain":[%q]}]}`, name+".example"))
		sum := sha256.Sum256(payload)
		hash := hex.EncodeToString(sum[:])
		path, _, err := resourceStore.PutRuleSet(ctx, bytes.NewReader(payload), hash, "source")
		if err != nil {
			t.Fatal(err)
		}
		return path, hash, payload
	}
	_, firstHash, _ := create("source")
	fallbackPath, fallbackHash, fallbackBytes := create("fallback")

	store := openServerTestStore(t, ctx)
	t.Cleanup(func() { _ = store.Close() })
	firstDocument := declarationAPIWithRuleSet(firstHash)
	if _, err := store.CommitDeclaration(ctx, 0, firstDocument, "test:ruleset-source"); err != nil {
		t.Fatal(err)
	}
	engine, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       domain.DefaultInboundSet(),
		ControlAddress: netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:  declarationAPITestSecret,
		RuleSets:       resourceStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := NewDeclarationCompileCoordinator(store, engine)
	if err != nil {
		t.Fatal(err)
	}
	core := &fakeApplyCore{}
	apply, err := NewApplyCoordinator(store, core, testApplyPolicy())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &serverRuntime{apply: apply, declarations: declarations, gate: NewOperationGate()}
	handler := New(runtimepath.Paths{}).handler(store, runtime)
	first := checkedPreviewTest(t, handler)
	if resp := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", first.Receipt); resp.Code != http.StatusOK {
		t.Fatalf("first rule-set apply failed: %d %s", resp.Code, resp.Body.String())
	}
	snap, err := store.Snapshot(ctx)
	if err != nil || snap.AppliedGenerationID == nil {
		t.Fatalf("no source generation: %+v, %v", snap, err)
	}
	sourceID := *snap.AppliedGenerationID
	current, err := store.CurrentDeclaration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	secondDocument := strings.Replace(string(declarationAPIWithRuleSet(fallbackHash)),
		`"log_level":"warn"`, `"log_level":"info"`, 1)
	if _, err := store.CommitDeclaration(ctx, current.Revision, []byte(secondDocument), "test:ruleset-fallback"); err != nil {
		t.Fatal(err)
	}
	second := checkedPreviewTest(t, handler)
	if resp := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", second.Receipt); resp.Code != http.StatusOK {
		t.Fatalf("fallback rule-set apply failed: %d %s", resp.Code, resp.Body.String())
	}
	return store, core, runtime, sourceID, root, fallbackPath, fallbackBytes
}

func TestHistoricalCoreCheckPinsBothSourceAndFallbackRuleSetInodes(t *testing.T) {
	store, core, runtime, sourceID, root, fallback, fallbackBytes := historicalRuleSetHarness(t)
	ctx := context.Background()
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	core.checkFn = func(context.Context, Generation) error {
		// Replacing a fallback artifact by an identical file is invisible to
		// post-check hash-by-PATH verification, but not to held inode pins.
		oldPath := fallback + ".moved"
		if err := os.Rename(fallback, oldPath); err != nil {
			return err
		}
		return os.WriteFile(fallback, fallbackBytes, 0o600)
	}
	eventsBefore := len(core.events)
	evidence, err := runtime.CheckHistoricalGeneration(ctx, store, root, sourceID)
	if !errors.Is(err, ErrHistoricalCheckChanged) || evidence.CoreChecked ||
		evidence.Applied || evidence.RestoreReady {
		t.Fatalf("fallback same-content inode swap escaped dry run: evidence=%+v err=%v", evidence, err)
	}
	if len(core.events) != eventsBefore+1 || core.events[len(core.events)-1] != "check" {
		t.Fatalf("unexpected activation during resource check: %v", core.events)
	}
	after, err := store.Snapshot(ctx)
	if err != nil || after.ActiveAttemptID != nil || !sameRecoveryAuditSnapshot(before, after) {
		t.Fatalf("resource swap changed confirmed revision or left active journal: %+v err=%v", after, err)
	}
}

func TestHistoricalCoreCheckWithPinnedRuleSetsPassesWithoutActivation(t *testing.T) {
	store, core, runtime, sourceID, root, _, _ := historicalRuleSetHarness(t)
	before, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	eventsBefore := len(core.events)
	evidence, err := runtime.CheckHistoricalGeneration(context.Background(), store, root, sourceID)
	if err != nil || !evidence.CoreChecked || evidence.RestoreReady || evidence.Applied {
		t.Fatalf("healthy source/fallback pins rejected: %+v err=%v", evidence, err)
	}
	after, err := store.Snapshot(context.Background())
	if err != nil || after.ActiveAttemptID != nil || !sameRecoveryAuditSnapshot(before, after) ||
		len(core.events) != eventsBefore+1 || core.events[len(core.events)-1] != "check" {
		t.Fatalf("healthy pinned dry run changed live core: %+v events=%v err=%v", after, core.events, err)
	}
}

func TestHistoricalCoreCheckRejectsMidCheckFallbackSQLiteTamper(t *testing.T) {
	store, core, runtime, sourceID := historicalCoreCheckHarness(t)
	ctx := context.Background()
	before, err := store.Snapshot(ctx)
	if err != nil || before.AppliedGenerationID == nil {
		t.Fatal("missing fallback state")
	}
	core.checkFn = func(context.Context, Generation) error {
		return corruptStoredGenerationManifestHash(store.Path(), *before.AppliedGenerationID)
	}
	eventsBefore := len(core.events)
	evidence, err := runtime.CheckHistoricalGeneration(ctx, store, "", sourceID)
	if !errors.Is(err, ErrHistoricalCheckChanged) || evidence.CoreChecked || evidence.Applied ||
		len(core.events) != eventsBefore+1 || core.events[len(core.events)-1] != "check" {
		t.Fatalf("fallback DB corruption was accepted: %+v err=%v events=%v", evidence, err, core.events)
	}
	after, err := store.Snapshot(ctx)
	if err != nil || after.ActiveAttemptID != nil || !sameRecoveryAuditSnapshot(before, after) {
		t.Fatalf("fallback corruption changed confirmed pointers: %+v err=%v", after, err)
	}
}

func TestHistoricalRuleSetPinRejectsArbitraryManifestPath(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "not-our-rule.json")
	data := []byte(`{"version":4,"rules":[]}`)
	if err := os.WriteFile(external, data, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	manifest := compiler.NativeManifest{
		SchemaID:            compiler.NativeSchemaID,
		ConfigSHA256:        strings.Repeat("a", 64),
		DeclarationRevision: 1,
		DeclarationSHA256:   strings.Repeat("b", 64),
		RuleSets: []compiler.NativeRuleSetManifest{{
			Ref: "custom:one", RuntimeTag: "rs-one", RuntimePath: external,
			SHA256: hex.EncodeToString(sum[:]), Format: compiler.RuleSetFormatSource,
		}},
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := []historicalStoredArtifact{{id: 9, artifacts: storage.GenerationArtifacts{
		ConfigSHA256: strings.Repeat("a", 64), ManifestJSON: body,
	}}}
	pins, err := pinHistoricalRuleSets(context.Background(), root, artifacts)
	if err == nil || pins != nil {
		t.Fatalf("arbitrary external path was pinned: pins=%v err=%v", pins, err)
	}
}

func TestHistoricalCoreCheckStagesAndCleansIsolatedTargetFallbackCopies(t *testing.T) {
	store, core, runtime, sourceID, root, fallback, fallbackBytes := historicalRuleSetHarness(t)
	ctx := context.Background()
	snapshotsDir := filepath.Join(root, "core", "historical-check-snapshots")
	// A callback observes the scoped copies while Check is running; it
	// cannot activate the core or change the real config reference paths.
	core.checkFn = func(context.Context, Generation) error {
		entries, err := os.ReadDir(snapshotsDir)
		if err != nil || len(entries) != 1 || !entries[0].IsDir() {
			return fmt.Errorf("expected exactly one isolated recovery check: entries=%v err=%v", entries, err)
		}
		copyPath := filepath.Join(snapshotsDir, entries[0].Name(), filepath.Base(fallback))
		copyBytes, err := os.ReadFile(copyPath)
		if err != nil || !bytes.Equal(copyBytes, fallbackBytes) {
			return fmt.Errorf("fallback snapshot missing/wrong: err=%v", err)
		}
		copyInfo, err := os.Lstat(copyPath)
		if err != nil || copyInfo.Mode().Perm() != 0o400 {
			return fmt.Errorf("fallback snapshot is not private read-only: %v", err)
		}
		originInfo, err := os.Lstat(fallback)
		if err != nil || os.SameFile(originInfo, copyInfo) {
			return fmt.Errorf("snapshot is a hard link to mutable shared file")
		}
		parts, err := os.ReadDir(filepath.Dir(copyPath))
		if err != nil || len(parts) != 2 {
			return fmt.Errorf("target and fallback snapshots not both retained: %v %v", parts, err)
		}
		return nil
	}
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := runtime.CheckHistoricalGeneration(ctx, store, root, sourceID)
	if err != nil || !evidence.CoreChecked || evidence.Applied || evidence.RestoreReady {
		t.Fatalf("isolated historical core check failed: evidence=%+v err=%v", evidence, err)
	}
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("completed check leaked temporary copies: entries=%v err=%v", entries, err)
	}
	after, err := store.Snapshot(ctx)
	if err != nil || !sameRecoveryAuditSnapshot(before, after) || after.ActiveAttemptID != nil {
		t.Fatalf("isolated copy check mutated confirmed state: %+v err=%v", after, err)
	}
}

func TestHistoricalCoreCheckRejectsMutatedIsolatedCopyAndCleansIt(t *testing.T) {
	store, core, runtime, sourceID, root, fallback, _ := historicalRuleSetHarness(t)
	ctx := context.Background()
	snapshotsDir := filepath.Join(root, "core", "historical-check-snapshots")
	core.checkFn = func(context.Context, Generation) error {
		entries, err := os.ReadDir(snapshotsDir)
		if err != nil || len(entries) != 1 {
			return fmt.Errorf("snapshot directory missing: %v", err)
		}
		copyPath := filepath.Join(snapshotsDir, entries[0].Name(), filepath.Base(fallback))
		if err := os.Chmod(copyPath, 0o600); err != nil {
			return err
		}
		return os.WriteFile(copyPath, []byte("tampered"), 0o600)
	}
	initialEvents := len(core.events)
	evidence, err := runtime.CheckHistoricalGeneration(ctx, store, root, sourceID)
	if !errors.Is(err, ErrHistoricalCheckChanged) || evidence.CoreChecked ||
		len(core.events) != initialEvents+1 || core.events[len(core.events)-1] != "check" {
		t.Fatalf("tampered isolated snapshot accepted: evidence=%+v err=%v events=%v", evidence, err, core.events)
	}
	entries, err := os.ReadDir(snapshotsDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("modified but same-inode copy left behind: entries=%v err=%v", entries, err)
	}
	if state, err := store.Snapshot(ctx); err != nil || state.ActiveAttemptID != nil {
		t.Fatalf("failed isolated check retained active journal: %+v err=%v", state, err)
	}
}

func TestHistoricalCoreCheckRejectsUnsafeSnapshotDirectoryBeforeCoreIO(t *testing.T) {
	store, core, runtime, sourceID, root, _, _ := historicalRuleSetHarness(t)
	path := filepath.Join(root, "core", "historical-check-snapshots")
	if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := len(core.events)
	_, err := runtime.CheckHistoricalGeneration(context.Background(), store, root, sourceID)
	if !errors.Is(err, ErrHistoricalCheckRejected) || len(core.events) != before {
		t.Fatalf("unsafe snapshot root reached core: err=%v events=%v", err, core.events)
	}
	if state, err := store.Snapshot(context.Background()); err != nil || state.ActiveAttemptID != nil {
		t.Fatalf("unsafe path changed journal state: %+v err=%v", state, err)
	}
}
