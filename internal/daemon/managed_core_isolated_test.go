//go:build linux

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestManagedCoreIsolatedCheckDoesNotStageBindOrActivate(t *testing.T) {
	ctx := context.Background()
	coreRoot := filepath.Join(t.TempDir(), "core")
	ruleStore, err := coreartifact.NewStore(coreRoot)
	if err != nil {
		t.Fatal(err)
	}
	ruleData := []byte(`{"version":4,"rules":[]}`)
	ruleSHA := testSHA256(ruleData)
	rulePath, _, err := ruleStore.PutRuleSet(ctx, bytes.NewReader(ruleData), ruleSHA, "source")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := coreartifact.PinRuleSet(rulePath, ruleSHA)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	scope, err := coreartifact.StagePinnedRuleSetSnapshot(ctx, coreRoot, []*coreartifact.RuleSetPin{pin})
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Close()
	isolatedNative := []byte(`{"route":{"rule_set":[{"type":"local","tag":"rs-check","format":"source","path":"isolated"}]}}`)
	isolatedPath, isolatedSHA, err := scope.StageNativeCheckConfig(ctx, isolatedNative)
	if err != nil {
		t.Fatal(err)
	}
	original := []byte(`{"route":{"rule_set":[{"type":"local","tag":"rs-check","format":"source","path":"original"}]}}`)
	originalSHA := testSHA256(original)
	manifest := compiler.NativeManifest{SchemaID: compiler.NativeSchemaID,
		ConfigSHA256: originalSHA, RuleSets: []compiler.NativeRuleSetManifest{{
			Ref: "custom:test", RuntimeTag: "rs-check", RuntimePath: rulePath,
			SHA256: ruleSHA, Format: compiler.RuleSetFormatSource,
		}},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sourceMapBytes := []byte("[]")
	state := &fakeManagedArtifactState{
		fakeManagedState: &fakeManagedState{config: original, hash: originalSHA},
		artifacts: storage.GenerationArtifacts{
			ConfigJSON: original, ConfigSHA256: originalSHA,
			ManifestJSON: manifestBytes, ManifestSHA256: testSHA256(manifestBytes),
			SourceMapJSON: sourceMapBytes, SourceMapSHA256: testSHA256(sourceMapBytes),
		},
	}
	files := &fakeGenerationFiles{path: "/not-used/generation/config.json"}
	binder := &fakeBinder{}
	supervisor := &fakeSupervisor{}
	checkCalls := 0
	check := func(_ context.Context, path, sha string, _, _ io.Writer) error {
		checkCalls++
		if path != isolatedPath || sha != isolatedSHA {
			t.Fatalf("check invoked non-isolated path/hash: path=%q sha=%s", path, sha)
		}
		bytes, err := os.ReadFile(path)
		if err != nil || testSHA256(bytes) != sha {
			t.Fatalf("check did not read isolated bytes: err=%v", err)
		}
		return nil
	}
	managed := newManagedCore(state, files, binder, supervisor, &fakeProbe{}, check, nil, nil)
	generation := Generation{ID: 19, Config: original, SHA256: originalSHA}
	if err := managed.CheckIsolated(ctx, generation, isolatedPath, isolatedSHA); err != nil {
		t.Fatal(err)
	}
	if checkCalls != 1 || files.stageCount != 0 || binder.path != "" ||
		supervisor.starts != 0 || supervisor.stops != 0 {
		t.Fatalf("isolated Check touched activation/staging: calls=%d files=%+v binder=%+v supervisor=%+v",
			checkCalls, files, binder, supervisor)
	}
	// Even a valid temporary file must be rejected when the immutable
	// database candidate no longer matches the original generation bytes.
	bad := generation
	bad.Config = []byte("{}")
	if err := managed.CheckIsolated(ctx, bad, isolatedPath, isolatedSHA); err == nil {
		t.Fatal("persisted generation mismatch accepted")
	}
	if checkCalls != 1 || files.stageCount != 0 {
		t.Fatal("invalid original generation reached isolated core check")
	}
	// A modified check-only file is refused without emitting its contents.
	if err := os.Chmod(isolatedPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(isolatedPath, []byte(`{"tampered":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := managed.CheckIsolated(ctx, generation, isolatedPath, isolatedSHA); err == nil ||
		checkCalls != 1 {
		t.Fatalf("tampered private native copy reached core: %v calls=%d", err, checkCalls)
	}
}

func TestNativeCheckSnapshotSidecarHasIndependentDigestAndStaysBounded(t *testing.T) {
	ctx := context.Background()
	root := filepath.Join(t.TempDir(), "core")
	store, err := coreartifact.NewStore(root)
	if err != nil {
		t.Fatal(err)
	}
	resource := []byte("compiled")
	hash := sha256.Sum256(resource)
	sha := hex.EncodeToString(hash[:])
	path, _, err := store.PutRuleSet(ctx, bytes.NewReader(resource), sha, "binary")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := coreartifact.PinRuleSet(path, sha)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	scope, err := coreartifact.StagePinnedRuleSetSnapshot(ctx, root, []*coreartifact.RuleSetPin{pin})
	if err != nil {
		t.Fatal(err)
	}
	defer scope.Close()
	sidecar := []byte(`{"check_only":true}`)
	pathNative, digest, err := scope.StageNativeCheckConfig(ctx, sidecar)
	if err != nil || digest != testSHA256(sidecar) {
		t.Fatalf("sidecar stage: %q %v", digest, err)
	}
	if err := scope.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, err := scope.StageNativeCheckConfig(ctx, sidecar); err == nil {
		t.Fatal("second native sidecar should be refused")
	}
	if info, err := os.Stat(pathNative); err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("native config mode is not private read-only: %+v err=%v", info, err)
	}
}
