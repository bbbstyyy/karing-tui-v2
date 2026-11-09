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
	"strings"
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

// The test uses only synthetic in-memory rule sets. It demonstrates that all
// original CN group declarations can coexist with a safe custom Group DNS
// override and independent region append inside one REAL pinned Core. It is
// NOT evidence that upstream CN rule assets are licensed or redistributable.
// Unsafe DNS overrides on CN groups that require IP/rule-set matching must
// continue to be refused rather than silently changing the original matcher.
func TestManagedCoreRealCNGroupDNSRegionJoint(t *testing.T) {
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

	bootstrap, bootstrapQueries, closeBootstrap := startDNSPathUDPServer(t)
	defer closeBootstrap()
	outbound, outboundQueries, closeOutbound := startDNSPathTCPServer(t)
	defer closeOutbound()
	directDNS, directQueries, closeDirect := startDNSPathUDPServer(t)
	defer closeDirect()
	groupDNS, groupQueries, closeGroup := startDNSPathTCPServer(t)
	defer closeGroup()
	proxy, proxyConnects, closeProxy := startDNSPathHTTPProxy(t)
	defer closeProxy()
	target, targetHits, closeTarget := startRouteOutcomeTarget(t)
	defer closeTarget()

	snapshot, err := preset.LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil || len(snapshot.Groups) != preset.CNExpectedGroups ||
		len(plan) != preset.CNResourceExpectedLogicalRefs {
		t.Fatalf("pinned CN 28-group resource inventory changed: %v", err)
	}
	ports := reserveLoopbackPorts(t, 4)
	inbounds := domain.InboundSet{
		Listen:   netip.MustParseAddr("127.0.0.1"),
		RulePort: ports[0], DirectPort: ports[1], SelectedPort: ports[2],
	}
	const secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	policy := core.DefaultPolicy()
	policy.InitialBackoff = 50 * time.Millisecond
	policy.MaxBackoff = 200 * time.Millisecond
	policy.ReadyTimeout = 5 * time.Second
	policy.StopTimeout = 3 * time.Second
	managed, err := NewManagedCore(store, ManagedCoreOptions{
		Executable:      corePath,
		StateRoot:       filepath.Join(stateDir, "core"),
		ControlEndpoint: fmt.Sprintf("http://127.0.0.1:%d", ports[3]),
		ControlSecret:   secret,
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
	// The "geoip" logical prefixes below are NOT production GeoIP data:
	// synthetic domain predicates exercise only route order and DNS behavior.
	sources := map[string][]byte{
		"unmatched": []byte(`{"version":4,"rules":[{"ip_cidr":["198.18.0.0/15"]}]}`),
		"apple":     []byte(`{"version":4,"rules":[{"domain":["cn-apple.integration.test"]}]}`),
		"site":      []byte(`{"version":4,"rules":[{"domain":["region-site.integration.test"]}]}`),
		"ip":        []byte(`{"version":4,"rules":[{"domain":["region-ip.integration.test"]}]}`),
	}
	hashes := make(map[string]string, len(sources))
	for name, body := range sources {
		hash := fmt.Sprintf("%x", sha256.Sum256(body))
		hashes[name] = hash
		if _, _, err := assets.PutRuleSet(ctx, bytes.NewReader(body), hash, "source"); err != nil {
			t.Fatalf("stage synthetic %s rule-set: %v", name, err)
		}
	}
	native, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       inbounds,
		ControlAddress: netip.AddrPortFrom(inbounds.Listen, ports[3]),
		ControlSecret:  secret,
		RuleSets:       assets,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewDeclarationCompileCoordinator(store, native)
	if err != nil {
		t.Fatal(err)
	}
	runtime, done, cancel, err := startServerRuntimeWithDeclarations(
		context.Background(), store, managed, coordinator,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("CN DNS/region supervisor shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("CN DNS/region supervisor did not shut down")
		}
	}()

	makeDocument := func(omitRegionIP, unsafeCNDNS bool) []byte {
		return cnDNSRegionJointDeclaration(t, snapshot, plan, hashes,
			proxy.Port(), bootstrap.Port(), outbound.Port(), directDNS.Port(),
			groupDNS.Port(), omitRegionIP, unsafeCNDNS)
	}
	committed, err := store.CommitDeclaration(ctx, 0, makeDocument(false, false),
		"integration:cn-group-dns-region")
	if err != nil {
		t.Fatal(err)
	}
	applyCtx, finish := context.WithTimeout(ctx, 40*time.Second)
	attempt, artifact, err := runtime.ApplyDeclarationRevision(applyCtx, committed.Revision, 0)
	finish()
	if err != nil {
		t.Fatalf("joint CN/DNS/region Core Check/Apply: %v; stderr=%s", err, managed.StderrTail())
	}
	assertCNJointSourceMap(t, artifact.SourceMap, snapshot)
	startCtx, stopStart := context.WithTimeout(ctx, 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		stopStart()
		t.Fatalf("start CN/DNS/region Core: %v; stderr=%s", err, managed.StderrTail())
	}
	stopStart()
	waitManagedCoreState(t, managed, 5*time.Second, func(s core.Snapshot) bool {
		return s.State == core.StateRunning && s.PID > 0
	})
	rule := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)
	connect := func(name string) {
		t.Helper()
		drainDNSPathQueries(directQueries)
		drainDNSPathQueries(groupQueries)
		drainDNSPathProxyConnects(proxyConnects)
		drainFiveLayerSignals(targetHits)
		connectCtx, stopConnect := context.WithTimeout(ctx, 6*time.Second)
		conn, err := socks5ConnectDomain(connectCtx, rule, name, target.Port())
		stopConnect()
		if err != nil {
			t.Fatalf("CN/DNS/region %s SOCKS5 CONNECT: %v; stderr=%s", name, err, managed.StderrTail())
		}
		var marker [2]byte
		_, err = io.ReadFull(conn, marker[:])
		_ = conn.Close()
		if err != nil || marker != [2]byte{'o', 'k'} {
			t.Fatalf("CN/DNS/region %s target response %q: %v", name, marker, err)
		}
		assertRouteOutcomeSignal(t, targetHits, 2*time.Second, name+" echo")
	}

	// The custom group must outrank all 28 CN L1 groups and use its own DNS
	// through CurrentSelected, while the actual target remains DIRECT.
	connect("group.integration.test")
	assertDNSPathQuery(t, bootstrapQueries, "outbound-dns.integration.test", 5*time.Second, "Bootstrap DNS")
	assertDNSPathQuery(t, outboundQueries, "proxy.integration.test", 5*time.Second, "Outbound node DNS")
	assertDNSPathQuery(t, groupQueries, "group.integration.test", 5*time.Second, "L1 Group DNS")
	assertDNSPathProxyConnect(t, proxyConnects, groupDNS.Port(), 5*time.Second, "Group DNS detour")
	assertNoDNSPathQuery(t, directQueries, "group.integration.test", 250*time.Millisecond, "L1 Group DNS vs Direct")
	assertNoDNSPathProxyConnectPort(t, proxyConnects, target.Port(), 250*time.Millisecond, "L1 DIRECT target")

	// Domain-driven synthetic geosite:apple matches the original CN
	// apple-services source group (DIRECT). It must resolve via Direct DNS.
	connect("cn-apple.integration.test")
	assertDNSPathQuery(t, directQueries, "cn-apple.integration.test", 5*time.Second, "CN apple DIRECT DNS")
	assertNoDNSPathQuery(t, groupQueries, "cn-apple.integration.test", 250*time.Millisecond, "CN not Group DNS")
	assertNoDNSPathProxyConnectPort(t, proxyConnects, target.Port(), 250*time.Millisecond, "CN DIRECT target")

	// Independent geosite:cn and geoip:cn region append rules follow the
	// original CN groups. FINAL is BLOCK to distinguish a region match.
	for _, name := range []string{"region-site.integration.test", "region-ip.integration.test"} {
		connect(name)
		assertDNSPathQuery(t, directQueries, name, 5*time.Second, "region append Direct DNS")
		assertNoDNSPathQuery(t, groupQueries, name, 250*time.Millisecond, "region not Group DNS")
		assertNoDNSPathProxyConnectPort(t, proxyConnects, target.Port(), 250*time.Millisecond, "region DIRECT")
	}
	drainFiveLayerSignals(targetHits)
	blockCtx, stopBlock := context.WithTimeout(ctx, 5*time.Second)
	conn, err := socks5ConnectDomain(blockCtx, rule, "unknown.integration.test", target.Port())
	stopBlock()
	if err == nil {
		_ = conn.Close()
		t.Fatal("unknown hostname bypassed CN/region FINAL BLOCK")
	}
	assertNoRouteOutcomeSignal(t, targetHits, 200*time.Millisecond, "FINAL BLOCK")

	// A missing region asset must never produce a partial new native config
	// or silently fall back to DIRECT. The existing generation and LKG stay.
	missing, err := store.CommitDeclaration(ctx, committed.Revision,
		makeDocument(true, false), "integration:cn-missing-region-ip")
	if err != nil {
		t.Fatal(err)
	}
	badCtx, endBad := context.WithTimeout(ctx, 10*time.Second)
	_, _, err = runtime.ApplyDeclarationRevision(badCtx, missing.Revision, attempt.TargetRevision)
	endBad()
	if !errors.Is(err, declaration.ErrRuleSetResourceMissing) {
		t.Fatalf("missing synthetic region asset was not rejected: %v", err)
	}
	after, err := store.Snapshot(ctx)
	if err != nil || after.AppliedGenerationID == nil ||
		*after.AppliedGenerationID != attempt.GenerationID ||
		after.LastKnownGoodGenerationID == nil ||
		*after.LastKnownGoodGenerationID != attempt.GenerationID ||
		after.RecoveryRequired {
		t.Fatalf("failed region apply replaced running LKG: %+v, err=%v", after, err)
	}
	connect("region-site.integration.test")
	assertDNSPathQuery(t, directQueries, "region-site.integration.test", 5*time.Second, "LKG region DNS")

	// CN apple-push is an OR of domain and IP predicates. Attaching group
	// DNS cannot be safely resolved before IP/rule-set matching; reject the
	// entire attempted apply, rather than dropping any original predicate.
	unsafe, err := store.CommitDeclaration(ctx, missing.Revision,
		makeDocument(false, true), "integration:cn-unsafe-group-dns")
	if err != nil {
		t.Fatal(err)
	}
	unsafeCtx, endUnsafe := context.WithTimeout(ctx, 10*time.Second)
	_, _, err = runtime.ApplyDeclarationRevision(unsafeCtx, unsafe.Revision, attempt.TargetRevision)
	endUnsafe()
	// Declaration compilation intentionally wraps lower-level compiler faults
	// as an invalid document. Confirm both the public error category and
	// the precise fail-closed DNS ambiguity, without relying on errors.Is
	// across a non-wrapping diagnostic boundary.
	if !errors.Is(err, declaration.ErrInvalidDocument) ||
		!strings.Contains(err.Error(), compiler.ErrDNSRouteResolutionAmbiguous.Error()) {
		t.Fatalf("unsafe CN Group DNS matcher did not fail closed: %v", err)
	}
	after, err = store.Snapshot(ctx)
	if err != nil || after.AppliedGenerationID == nil ||
		*after.AppliedGenerationID != attempt.GenerationID ||
		after.LastKnownGoodGenerationID == nil ||
		*after.LastKnownGoodGenerationID != attempt.GenerationID ||
		after.RecoveryRequired {
		t.Fatalf("unsafe Group DNS apply changed LKG: %+v, err=%v", after, err)
	}
	stopCtx, stopCore := context.WithTimeout(ctx, 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCore()
		t.Fatalf("stop joint CN/DNS Core: %v", err)
	}
	stopCore()
}

// The original 28-group pinned source inventory is always compiled, while
// ordinary custom routes are interleaved explicitly and the two region append
// rules stay in their respective L2/L3 layers.
func cnDNSRegionJointDeclaration(t *testing.T, snapshot preset.CNSnapshot,
	plan []preset.CNResourceSpec, hashes map[string]string,
	proxyPort, bootstrapPort, outboundPort, directPort, groupPort uint16,
	omitRegionIP, unsafeCNDNS bool) []byte {
	t.Helper()
	baseline := dnsPathDeclaration(proxyPort, bootstrapPort, outboundPort,
		directPort, groupPort, groupPort)
	var doc map[string]any
	if err := json.Unmarshal(baseline, &doc); err != nil {
		t.Fatal(err)
	}
	routing := doc["routing"].(map[string]any)
	routing["geosite"] = []any{}
	routing["geoip"] = []any{}
	routing["acl"] = []any{}
	routing["final"] = map[string]any{"kind": "block"}
	routing["region_append"] = map[string]any{
		"region_code": "cn", "geosite_enabled": true, "geoip_enabled": true,
	}
	overrides := make([]map[string]any, 0, len(snapshot.Groups))
	order := []map[string]any{{"kind": "custom", "group_id": "group-dns-route"}}
	for _, group := range snapshot.Groups {
		override := map[string]any{"group_id": group.ID, "enabled": true}
		if unsafeCNDNS && group.ID == "cn.apple-push" {
			override["dns_profile_id"] = "group-dns"
		}
		overrides = append(overrides, override)
		order = append(order, map[string]any{"kind": "cn_preset", "group_id": group.ID})
	}
	routing["cn_preset"] = map[string]any{
		"source_commit": preset.CNSourceCommit, "overrides": overrides,
	}
	routing["custom_order"] = order

	// Proxy DNS is omitted from this joint fixture: attempting to insert a
	// pre-resolve for CN rule-set/IP targets would alter source semantics.
	// Independent Proxy/Node/Bootstrap behavior is covered by DNS-path tests.
	dns := doc["dns"].(map[string]any)
	delete(dns, "proxy_profile_id")
	profiles := dns["profiles"].([]any)
	kept := make([]any, 0, len(profiles))
	for _, entry := range profiles {
		if entry.(map[string]any)["role"] != "proxy" {
			kept = append(kept, entry)
		}
	}
	dns["profiles"] = kept

	resources := make([]map[string]any, 0, len(plan))
	for _, item := range plan {
		if omitRegionIP && item.Ref == "geoip:cn" {
			continue
		}
		key := "unmatched"
		switch item.Ref {
		case "geosite:apple":
			key = "apple"
		case "geosite:cn":
			key = "site"
		case "geoip:cn":
			key = "ip"
		}
		resources = append(resources, map[string]any{
			"ref": item.Ref, "sha256": hashes[key], "format": "source",
		})
	}
	doc["rule_sets"] = resources
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertCNJointSourceMap(t *testing.T, rows []compiler.RouteSourceMapEntry,
	snapshot preset.CNSnapshot) {
	t.Helper()
	var customGroupDNSResolve, customGroupDNSRoute bool
	var cnGroups []string
	var regionSite, regionIP, final bool
	for i, entry := range rows {
		switch entry.GroupID {
		case "group-dns-route":
			if entry.DNSProfileID != "group-dns" || entry.Layer != domain.LayerCustom {
				t.Fatalf("custom group lost typed Group DNS provenance: %+v", entry)
			}
			switch entry.Action {
			case "resolve":
				customGroupDNSResolve = true
				if i+1 >= len(rows) || rows[i+1].GroupID != entry.GroupID ||
					rows[i+1].Action != "route" || rows[i+1].RuleIndex != entry.RuleIndex+1 {
					t.Fatalf("Group DNS native resolve/route not adjacent: %+v", rows)
				}
			case "route":
				customGroupDNSRoute = true
			}
		case "region:auto-geosite:cn":
			regionSite = entry.Layer == domain.LayerGeoSite && entry.Target.Kind == domain.TargetDirect
		case "region:auto-geoip:cn":
			regionIP = entry.Layer == domain.LayerGeoIP && entry.Target.Kind == domain.TargetDirect
		default:
			if entry.Final {
				final = entry.Layer == domain.LayerFinal && entry.Target.Kind == domain.TargetBlock
			} else if len(entry.GroupID) >= 3 && entry.GroupID[:3] == "cn." &&
				entry.Action != "resolve" {
				cnGroups = append(cnGroups, entry.GroupID)
			}
		}
	}
	if !customGroupDNSResolve || !customGroupDNSRoute || !regionSite ||
		!regionIP || !final || len(cnGroups) != len(snapshot.Groups) {
		t.Fatalf("joint Core omitted CN/group DNS/region/FINAL provenance: CN=%d rows=%d", len(cnGroups), len(rows))
	}
	for i, group := range snapshot.Groups {
		if cnGroups[i] != group.ID {
			t.Fatalf("original CN group %d reordered: %s vs %s", i, cnGroups[i], group.ID)
		}
	}
}
