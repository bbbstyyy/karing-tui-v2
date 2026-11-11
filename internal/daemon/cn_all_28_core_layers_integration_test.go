//go:build integration && linux

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

// This is a real pinned-Core behavior test of the original 28-group source
// mapping, not a test with licensed CN production rule contents. Every
// referenced rule set is a temporary synthetic loopback source asset.
func TestManagedCoreRealCNAll28GroupsFiveLayerPrecedence(t *testing.T) {
	assertOrdinaryUserCoreEnvironment(t)
	corePath := os.Getenv("KARING_TUI_TEST_CORE")
	if corePath == "" {
		t.Skip("KARING_TUI_TEST_CORE is not set")
	}
	ctx := context.Background()
	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(ctx, filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	proxyA, _, proxyAHits, closeA := startTargetOutcomeHTTPProxy(t, "unused.invalid:1", true)
	defer closeA()
	proxyB, _, proxyBHits, closeB := startTargetOutcomeHTTPProxy(t, "unused.invalid:2", true)
	defer closeB()
	proxyC, _, proxyCHits, closeC := startTargetOutcomeHTTPProxy(t, "unused.invalid:3", true)
	defer closeC()
	target, targetHits, closeTarget := startRouteOutcomeTarget(t)
	defer closeTarget()

	snapshot, err := preset.LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil || len(snapshot.Groups) != preset.CNExpectedGroups ||
		len(plan) != preset.CNResourceExpectedLogicalRefs {
		t.Fatalf("pinned CN source inventory changed: %v", err)
	}
	ports := reserveLoopbackPorts(t, 4)
	inbounds := domain.InboundSet{
		Listen:   netip.MustParseAddr("127.0.0.1"),
		RulePort: ports[0], DirectPort: ports[1], SelectedPort: ports[2],
	}
	const controlSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	policy := core.DefaultPolicy()
	policy.ReadyTimeout = 5 * time.Second
	policy.StopTimeout = 3 * time.Second
	policy.InitialBackoff = 50 * time.Millisecond
	policy.MaxBackoff = 200 * time.Millisecond
	managed, err := NewManagedCore(store, ManagedCoreOptions{
		Executable:      corePath,
		StateRoot:       filepath.Join(stateDir, "core"),
		ControlEndpoint: fmt.Sprintf("http://127.0.0.1:%d", ports[3]),
		ControlSecret:   controlSecret,
		Inbounds:        inbounds,
		Policy:          policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	assets, err := coreartifact.NewStore(filepath.Join(stateDir, "core"))
	if err != nil {
		t.Fatal(err)
	}
	matchSource := []byte(`{"version":4,"rules":[{"ip_cidr":["127.0.0.1/32"]}]}`)
	otherSource := []byte(`{"version":4,"rules":[{"ip_cidr":["198.18.0.0/15"]}]}`)
	matchSHA := fmt.Sprintf("%x", sha256.Sum256(matchSource))
	otherSHA := fmt.Sprintf("%x", sha256.Sum256(otherSource))
	for _, item := range []struct {
		body []byte
		hash string
	}{
		{matchSource, matchSHA}, {otherSource, otherSHA},
	} {
		if _, _, err := assets.PutRuleSet(ctx, bytes.NewReader(item.body), item.hash, "source"); err != nil {
			t.Fatal(err)
		}
	}

	native, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       inbounds,
		ControlAddress: netip.AddrPortFrom(inbounds.Listen, ports[3]),
		ControlSecret:  controlSecret,
		RuleSets:       assets,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewDeclarationCompileCoordinator(store, native)
	if err != nil {
		t.Fatal(err)
	}
	runtime, done, cancel, err := startServerRuntimeWithDeclarations(context.Background(), store, managed, coordinator)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("CN 28-group supervisor shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("CN 28-group supervisor did not shut down")
		}
	}()

	revision := uint64(0)
	configRevision := uint64(0)
	var appliedGenerationID int64
	apply := func(label string, custom, geosite, geoip, acl bool) {
		t.Helper()
		document := cnAll28LayerDeclaration(t, snapshot, plan, matchSHA, otherSHA,
			proxyA.Port(), proxyB.Port(), proxyC.Port(), target.Port(),
			custom, geosite, geoip, acl, false)
		committed, err := store.CommitDeclaration(ctx, revision, document, "integration:cn-28-"+label)
		if err != nil {
			t.Fatal(err)
		}
		applyCtx, finish := context.WithTimeout(ctx, 40*time.Second)
		attempt, artifact, err := runtime.ApplyDeclarationRevision(applyCtx, committed.Revision, configRevision)
		finish()
		if err != nil {
			t.Fatalf("CN %s Core Check/Apply failed: %v; stderr=%s", label, err, managed.StderrTail())
		}
		revision = committed.Revision
		configRevision = attempt.TargetRevision
		appliedGenerationID = attempt.GenerationID
		if label == "custom-bing" {
			assertCNAll28SourceMap(t, artifact.SourceMap, snapshot)
			found := false
			for _, item := range artifact.Manifest.RuleSets {
				if item.Ref == "geoip:bing" {
					found = true
				}
			}
			if !found {
				t.Fatal("compiled Core manifest lost explicit synthetic Bing resource")
			}
		}
	}

	// Explicitly enable every Karing source group, including the default-off
	// Bing rule, without changing its order, target or predicate families.
	apply("custom-bing", true, true, true, true)
	startCtx, finishStart := context.WithTimeout(ctx, 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		finishStart()
		t.Fatalf("start CN Core generation failed: %v; stderr=%s", err, managed.StderrTail())
	}
	finishStart()
	waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	rule := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)
	assertFiveLayerProxyOutcome(t, "CN Custom L1 Bing (synthetic)", rule,
		target, targetHits, proxyAHits, proxyBHits, proxyCHits, managed)

	// If even one required CN resource is absent, a declaration may be
	// staged but MUST NOT install a partial generation or route to DIRECT.
	badDocument := cnAll28LayerDeclaration(t, snapshot, plan, matchSHA, otherSHA,
		proxyA.Port(), proxyB.Port(), proxyC.Port(), target.Port(),
		true, true, true, true, true)
	bad, err := store.CommitDeclaration(ctx, revision, badDocument,
		"integration:cn-28-missing-geoip-bing")
	if err != nil {
		t.Fatal(err)
	}
	revision = bad.Revision
	badCtx, cancelBad := context.WithTimeout(ctx, 10*time.Second)
	_, _, err = runtime.ApplyDeclarationRevision(badCtx, bad.Revision, configRevision)
	cancelBad()
	if !errors.Is(err, declaration.ErrRuleSetResourceMissing) {
		t.Fatalf("missing CN Bing resource metadata did not fail closed: %v", err)
	}
	afterBad, err := store.Snapshot(ctx)
	if err != nil || afterBad.AppliedGenerationID == nil ||
		*afterBad.AppliedGenerationID != appliedGenerationID ||
		afterBad.LastKnownGoodGenerationID == nil ||
		*afterBad.LastKnownGoodGenerationID != appliedGenerationID ||
		afterBad.RecoveryRequired {
		t.Fatalf("missing resource replaced LKG or triggered recovery: %+v %v", afterBad, err)
	}
	assertFiveLayerProxyOutcome(t, "LKG CN Bing after missing resource", rule,
		target, targetHits, proxyAHits, proxyBHits, proxyCHits, managed)

	apply("geosite", false, true, true, true)
	waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	assertFiveLayerProxyOutcome(t, "GeoSite L2 after CN Custom disabled", rule,
		target, targetHits, proxyBHits, proxyAHits, proxyCHits, managed)

	apply("geoip", false, false, true, true)
	waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	assertFiveLayerProxyOutcome(t, "GeoIP L3 after GeoSite disabled", rule,
		target, targetHits, proxyCHits, proxyAHits, proxyBHits, managed)

	apply("acl", false, false, false, true)
	waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	drainFiveLayerSignals(targetHits, proxyAHits, proxyBHits, proxyCHits)
	connectCtx, disconnect := context.WithTimeout(ctx, 4*time.Second)
	conn, err := socks5Connect(connectCtx, rule, target)
	disconnect()
	if err == nil {
		_ = conn.Close()
		t.Fatal("ACL BLOCK failed: request bypassed via CN or DIRECT")
	}
	for _, witness := range []<-chan struct{}{targetHits, proxyAHits, proxyBHits, proxyCHits} {
		assertNoRouteOutcomeSignal(t, witness, 100*time.Millisecond, "CN ACL BLOCK")
	}

	apply("final", false, false, false, false)
	waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	drainFiveLayerSignals(targetHits, proxyAHits, proxyBHits, proxyCHits)
	connectCtx, disconnect = context.WithTimeout(ctx, 4*time.Second)
	conn, err = socks5Connect(connectCtx, rule, target)
	disconnect()
	if err != nil {
		t.Fatalf("FINAL DIRECT failed after all earlier layers disabled: %v", err)
	}
	var marker [2]byte
	_, err = io.ReadFull(conn, marker[:])
	_ = conn.Close()
	if err != nil || marker != [2]byte{'o', 'k'} {
		t.Fatalf("FINAL DIRECT target marker mismatch: %q, %v", marker, err)
	}
	assertRouteOutcomeSignal(t, targetHits, 2*time.Second, "CN five-layer FINAL")
	for _, witness := range []<-chan struct{}{proxyAHits, proxyBHits, proxyCHits} {
		assertNoRouteOutcomeSignal(t, witness, 100*time.Millisecond, "FINAL must not select proxy")
	}
}

func cnAll28LayerDeclaration(t *testing.T, snapshot preset.CNSnapshot,
	plan []preset.CNResourceSpec, matchSHA, noMatchSHA string,
	aPort, bPort, cPort, destinationPort uint16,
	custom, geosite, geoip, acl, omitBing bool) []byte {
	t.Helper()
	// Reuse the previously pinned 5-layer declaration fixture for the lower
	// three layers and FINAL, replacing only L1 with the 28 original groups.
	baseline := fiveLayerDeclaration(noMatchSHA, aPort, bPort, cPort,
		destinationPort, custom, geosite, geoip, acl)
	var doc map[string]any
	if err := json.Unmarshal(baseline, &doc); err != nil {
		t.Fatal(err)
	}
	routing, ok := doc["routing"].(map[string]any)
	if !ok {
		t.Fatal("base routing fixture is missing")
	}
	overrides := make([]map[string]any, 0, len(snapshot.Groups))
	for _, group := range snapshot.Groups {
		overrides = append(overrides, map[string]any{
			"group_id": group.ID, "enabled": true,
		})
	}
	routing["cn_preset"] = map[string]any{
		"source_commit": preset.CNSourceCommit,
		"overrides":     overrides,
	}
	routing["custom"] = []any{}
	resources := make([]map[string]any, 0, len(plan))
	for _, spec := range plan {
		if spec.Ref == "geoip:bing" && omitBing {
			continue
		}
		sha := noMatchSHA
		if spec.Ref == "geoip:bing" {
			sha = matchSHA
		}
		resources = append(resources, map[string]any{
			"ref": spec.Ref, "sha256": sha, "format": "source",
		})
	}
	doc["rule_sets"] = resources
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func assertCNAll28SourceMap(t *testing.T, source []compiler.RouteSourceMapEntry,
	snapshot preset.CNSnapshot) {
	t.Helper()
	// Four trailing entries are synthetic GeoSite, GeoIP, ACL and FINAL.
	if len(source) != len(snapshot.Groups)+4 {
		t.Fatalf("real CN Core source-map has %d entries, expected all 28 + L2/L3/L4/FINAL", len(source))
	}
	for i, group := range snapshot.Groups {
		entry := source[i]
		if entry.Layer != domain.LayerCustom || entry.GroupID != group.ID ||
			entry.Target != group.Target || entry.Final {
			t.Fatalf("CN Core source-map group %d has wrong origin or target: %+v", i, entry)
		}
	}
	for i, layer := range []domain.RoutingLayer{
		domain.LayerGeoSite, domain.LayerGeoIP, domain.LayerACL,
	} {
		if source[len(snapshot.Groups)+i].Layer != layer {
			t.Fatalf("CN Core source-map reordered layer %s", layer)
		}
	}
	if !source[len(source)-1].Final {
		t.Fatal("CN Core lost FINAL after 28 groups")
	}
}
