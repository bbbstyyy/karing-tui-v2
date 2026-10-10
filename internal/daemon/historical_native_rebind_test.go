package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func historicalRebindFixture(t *testing.T) ([]byte, compiler.NativeManifest, *coreartifact.RuleSetSnapshot) {
	t.Helper()
	store, _, _, id, stateRoot, _, _ := historicalRuleSetHarness(t)
	payload, err := store.GenerationArtifacts(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var manifest compiler.NativeManifest
	if err := json.Unmarshal(payload.ManifestJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	pins, err := pinHistoricalRuleSets(context.Background(), stateRoot, []historicalStoredArtifact{
		{id: id, artifacts: payload},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pins.Close() })
	scope, err := coreartifact.StagePinnedRuleSetSnapshot(context.Background(),
		filepath.Join(stateRoot, "core"), pins.files)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = scope.Close() })
	return payload.ConfigJSON, manifest, scope
}

func nativeRebindRoutes(t *testing.T, config []byte) []map[string]any {
	t.Helper()
	var full struct {
		Route struct {
			RuleSet []map[string]any `json:"rule_set"`
		} `json:"route"`
	}
	if err := json.Unmarshal(config, &full); err != nil {
		t.Fatal(err)
	}
	return full.Route.RuleSet
}

func TestHistoricalNativeRebindChangesOnlyLocalRuleSetPath(t *testing.T) {
	original, manifest, scope := historicalRebindFixture(t)
	before := append([]byte(nil), original...)
	rebound, err := rebindHistoricalCheckJSON(context.Background(), original, manifest, scope)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(rebound, original) || !bytes.Equal(before, original) {
		t.Fatal("isolated rebind mutated or reused the stored generation bytes")
	}
	rules := nativeRebindRoutes(t, rebound)
	if len(rules) != 1 || rules[0]["tag"] != manifest.RuleSets[0].RuntimeTag {
		t.Fatalf("rebound local rule set does not match historical manifest: %v", rules)
	}
	expectedCopy, ok := scope.FileFor(manifest.RuleSets[0].RuntimePath)
	if !ok || rules[0]["path"] != expectedCopy {
		t.Fatalf("native rule path was not rebound into isolated snapshot: %v expected=%q", rules[0], expectedCopy)
	}
	if _, err := os.Lstat(expectedCopy); err != nil {
		t.Fatal(err)
	}
	// Compare all JSON fields, recursively, after replacing the one approved
	// route.rule_set[].path back. DNS, outbounds, selectors and control secret
	// may not be changed by this compatibility-only operation.
	var beforeDoc, afterDoc map[string]any
	if json.Unmarshal(original, &beforeDoc) != nil || json.Unmarshal(rebound, &afterDoc) != nil {
		t.Fatal("invalid original or isolated native JSON")
	}
	afterDoc["route"].(map[string]any)["rule_set"].([]any)[0].(map[string]any)["path"] =
		manifest.RuleSets[0].RuntimePath
	if !reflect.DeepEqual(beforeDoc, afterDoc) {
		t.Fatal("native rebinding unexpectedly changed fields other than local rule paths")
	}
	sum := sha256.Sum256(original)
	if hex.EncodeToString(sum[:]) != manifest.ConfigSHA256 {
		t.Fatal("historical manifest hash changed after temporary rebinding")
	}
}

func TestHistoricalNativeRebindRejectsMismatchedManifestAndConfig(t *testing.T) {
	original, manifest, scope := historicalRebindFixture(t)
	tests := []struct {
		name string
		alter func(*compiler.NativeManifest, *[]byte)
	}{
		{"stored config SHA", func(m *compiler.NativeManifest, _ *[]byte) {
			m.ConfigSHA256 = strings.Repeat("0", 64)
		}},
		{"wrong runtime path", func(m *compiler.NativeManifest, _ *[]byte) {
			m.RuleSets[0].RuntimePath = "/tmp/not-the-original.srs"
		}},
		{"wrong runtime tag", func(m *compiler.NativeManifest, _ *[]byte) {
			m.RuleSets[0].RuntimeTag = "wrong"
		}},
		{"wrong runtime format", func(m *compiler.NativeManifest, _ *[]byte) {
			m.RuleSets[0].Format = compiler.RuleSetFormatBinary
		}},
		{"unsupported runtime format", func(m *compiler.NativeManifest, _ *[]byte) {
			m.RuleSets[0].Format = compiler.RuleSetFormat("unsupported")
		}},
		{"missing resource binding", func(m *compiler.NativeManifest, _ *[]byte) {
			m.RuleSets = nil
		}},
		{"duplicate manifest resource", func(m *compiler.NativeManifest, _ *[]byte) {
			m.RuleSets = append(m.RuleSets, m.RuleSets[0])
		}},
		{"corrupt original bytes", func(_ *compiler.NativeManifest, config *[]byte) {
			*config = []byte(`{"route":{"rule_set":[]}}`)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			candidate := append([]byte(nil), original...)
			m := manifest
			m.RuleSets = append([]compiler.NativeRuleSetManifest(nil), manifest.RuleSets...)
			tc.alter(&m, &candidate)
			if _, err := rebindHistoricalCheckJSON(context.Background(), candidate, m, scope);
				!errors.Is(err, ErrHistoricalPathRebind) {
				t.Fatalf("invalid historical native binding accepted: %v", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := rebindHistoricalCheckJSON(ctx, original, manifest, scope); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled rebind did not stop: %v", err)
	}
}

func TestHistoricalCoreCheckUsesReboundNativePathsNotSharedPaths(t *testing.T) {
	store, core, runtime, sourceID, root, _, _ := historicalRuleSetHarness(t)
	ctx := context.Background()
	source, err := store.GenerationArtifacts(ctx, sourceID)
	if err != nil {
		t.Fatal(err)
	}
	var manifest compiler.NativeManifest
	if err := json.Unmarshal(source.ManifestJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	scopeParent := filepath.Join(root, "core", "historical-check-snapshots")
	calls := 0
	core.checkFn = func(_ context.Context, candidate Generation) error {
		calls++
		if candidate.SHA256 == source.ConfigSHA256 ||
			bytes.Equal(candidate.Config, source.ConfigJSON) {
			t.Fatal("core Check received archived native JSON instead of isolated JSON")
		}
		sum := sha256.Sum256(candidate.Config)
		if candidate.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("isolated candidate digest does not bind checked bytes")
		}
		rules := nativeRebindRoutes(t, candidate.Config)
		if len(rules) != len(manifest.RuleSets) {
			t.Fatalf("wrong number of isolated rule sets: %v", rules)
		}
		for _, rule := range rules {
			path, ok := rule["path"].(string)
			if !ok || filepath.Dir(filepath.Dir(path)) != scopeParent ||
				path == manifest.RuleSets[0].RuntimePath {
				t.Fatalf("core received unsafe/shared rule-set path: %q", path)
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("isolated rule-set file not present during Check: %v", err)
			}
		}
		return nil
	}
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := runtime.CheckHistoricalGeneration(ctx, store, root, sourceID)
	if err != nil || !evidence.CoreChecked || evidence.Applied || evidence.RestoreReady || calls != 1 {
		t.Fatalf("rebound dry run did not complete safely: evidence=%+v err=%v calls=%d", evidence, err, calls)
	}
	after, err := store.Snapshot(ctx)
	if err != nil || !sameRecoveryAuditSnapshot(before, after) || after.ActiveAttemptID != nil {
		t.Fatalf("isolated Check changed applied/LKG: %+v err=%v", after, err)
	}
	unchanged, err := store.GenerationArtifacts(ctx, sourceID)
	if err != nil || !sameHistoricalPayload(source, unchanged) {
		t.Fatalf("isolated native config was persisted over original: %v", err)
	}
	entries, err := os.ReadDir(scopeParent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary native and rule files leaked: entries=%v err=%v", entries, err)
	}
}

type coreWithoutIsolatedCheck struct{ underlying *fakeApplyCore }
func (c coreWithoutIsolatedCheck) Check(ctx context.Context, g Generation) error {
	return c.underlying.Check(ctx, g)
}
func (c coreWithoutIsolatedCheck) Activate(ctx context.Context, g Generation) error {
	return c.underlying.Activate(ctx, g)
}
func (c coreWithoutIsolatedCheck) Verify(ctx context.Context, g Generation) error {
	return c.underlying.Verify(ctx, g)
}
func (c coreWithoutIsolatedCheck) Rollback(ctx context.Context, g *Generation) error {
	return c.underlying.Rollback(ctx, g)
}

func TestHistoricalCoreCheckFailsClosedWithoutIsolatedCoreAdapter(t *testing.T) {
	store, core, runtime, sourceID, root, _, _ := historicalRuleSetHarness(t)
	runtime.apply.core = coreWithoutIsolatedCheck{underlying: core}
	initial := len(core.events)
	_, err := runtime.CheckHistoricalGeneration(context.Background(), store, root, sourceID)
	if !errors.Is(err, ErrHistoricalCheckUnavailable) || len(core.events) != initial {
		t.Fatalf("missing isolated Check interface fell back to shared native Check: %v events=%v", err, core.events)
	}
	state, err := store.Snapshot(context.Background())
	if err != nil || state.ActiveAttemptID != nil {
		t.Fatalf("unsupported adapter retained prepared journal: %+v err=%v", state, err)
	}
}
