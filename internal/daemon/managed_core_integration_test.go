//go:build integration && linux

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestManagedCoreRealIntegration(t *testing.T) {
	assertOrdinaryUserCoreEnvironment(t)
	corePath := os.Getenv("KARING_TUI_TEST_CORE")
	if corePath == "" {
		t.Skip("KARING_TUI_TEST_CORE is not set")
	}

	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ports := reserveLoopbackPorts(t, 4)
	inbounds := domain.InboundSet{
		Listen:       netip.MustParseAddr("127.0.0.1"),
		RulePort:     ports[0],
		DirectPort:   ports[1],
		SelectedPort: ports[2],
	}
	const secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	controlEndpoint := fmt.Sprintf("http://127.0.0.1:%d", ports[3])

	policy := core.DefaultPolicy()
	policy.InitialBackoff = 50 * time.Millisecond
	policy.MaxBackoff = 200 * time.Millisecond
	policy.FailureWindow = 10 * time.Second
	policy.MaxFailures = 4
	policy.ReadyTimeout = 5 * time.Second
	policy.StopTimeout = 3 * time.Second

	managed, err := NewManagedCore(store, ManagedCoreOptions{
		Executable:      corePath,
		StateRoot:       filepath.Join(stateDir, "core"),
		ControlEndpoint: controlEndpoint,
		ControlSecret:   secret,
		Inbounds:        inbounds,
		Policy:          policy,
		LogCapacity:     64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	ruleSets, err := coreartifact.NewStore(filepath.Join(stateDir, "core"))
	if err != nil {
		t.Fatal(err)
	}
	ruleSetContent := []byte(`{"version":4,"rules":[{"domain_suffix":["example.invalid"]}]}`)
	ruleSetSHA256 := fmt.Sprintf("%x", sha256.Sum256(ruleSetContent))
	ruleSetPath, _, err := ruleSets.PutRuleSet(ctx, bytes.NewReader(ruleSetContent), ruleSetSHA256, "source")
	if err != nil {
		t.Fatal(err)
	}
	regionGeoSiteContent := []byte(`{"version":4,"rules":[{"domain_suffix":["region-cn.invalid"]}]}`)
	regionGeoSiteSHA256 := fmt.Sprintf("%x", sha256.Sum256(regionGeoSiteContent))
	regionGeoSitePath, _, err := ruleSets.PutRuleSet(ctx, bytes.NewReader(regionGeoSiteContent), regionGeoSiteSHA256, "source")
	if err != nil {
		t.Fatal(err)
	}
	regionGeoIPContent := []byte(`{"version":4,"rules":[{"ip_cidr":["198.18.0.0/15"]}]}`)
	regionGeoIPSHA256 := fmt.Sprintf("%x", sha256.Sum256(regionGeoIPContent))
	regionGeoIPPath, _, err := ruleSets.PutRuleSet(ctx, bytes.NewReader(regionGeoIPContent), regionGeoIPSHA256, "source")
	if err != nil {
		t.Fatal(err)
	}

	schemaCompiler, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       inbounds,
		ControlAddress: netip.AddrPortFrom(inbounds.Listen, ports[3]),
		ControlSecret:  secret,
		RuleSets:       ruleSets,
	})
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := NewDeclarationCompileCoordinator(store, schemaCompiler)
	if err != nil {
		t.Fatal(err)
	}
	runtime, runDone, runCancel, err := startServerRuntimeWithDeclarations(context.Background(), store, managed, declarations)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		runCancel()
		select {
		case err := <-runDone:
			if err != nil {
				t.Errorf("managed core supervisor shutdown: %v; stderr=%s", err, managed.StderrTail())
			}
		case <-time.After(5 * time.Second):
			t.Errorf("managed core supervisor did not shut down")
		}
	}()
	if !runtime.ManagedApplyReady() {
		t.Fatal("managed apply runtime was not composed")
	}

	firstDeclaration, err := store.CommitDeclaration(
		ctx,
		0,
		integrationDeclarationDocument("warn", ruleSetSHA256, regionGeoSiteSHA256, regionGeoIPSHA256),
		"integration:first",
	)
	if err != nil {
		t.Fatal(err)
	}
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 40*time.Second)
	firstAttempt, firstArtifact, err := runtime.ApplyDeclarationRevision(applyCtx, firstDeclaration.Revision, 0)
	applyCancel()
	if err != nil {
		t.Fatalf("first declaration-driven real-core apply: %v; stderr=%s", err, managed.StderrTail())
	}
	if firstArtifact.Manifest.DeclarationRevision != firstDeclaration.Revision ||
		firstArtifact.Manifest.DeclarationSHA256 != firstDeclaration.SHA256 {
		t.Fatalf("first declaration provenance mismatch: artifact=%+v declaration=%+v", firstArtifact.Manifest, firstDeclaration)
	}
	if len(firstArtifact.Manifest.RuleSets) != 3 {
		t.Fatalf("first declaration rule-set closure = %+v", firstArtifact.Manifest.RuleSets)
	}
	firstRuleSet := firstArtifact.Manifest.RuleSets[0]
	if firstRuleSet.Ref != "integration:example" ||
		firstRuleSet.SHA256 != ruleSetSHA256 ||
		firstRuleSet.Format != compiler.RuleSetFormatSource ||
		firstRuleSet.RuntimePath != ruleSetPath {
		t.Fatalf("first declaration rule-set binding mismatch: %+v", firstRuleSet)
	}
	regionGeoSiteRuleSet := firstArtifact.Manifest.RuleSets[1]
	if regionGeoSiteRuleSet.Ref != "geosite:cn" ||
		regionGeoSiteRuleSet.SHA256 != regionGeoSiteSHA256 ||
		regionGeoSiteRuleSet.Format != compiler.RuleSetFormatSource ||
		regionGeoSiteRuleSet.RuntimePath != regionGeoSitePath {
		t.Fatalf("region GeoSite rule-set binding mismatch: %+v", regionGeoSiteRuleSet)
	}
	regionGeoIPRuleSet := firstArtifact.Manifest.RuleSets[2]
	if regionGeoIPRuleSet.Ref != "geoip:cn" ||
		regionGeoIPRuleSet.SHA256 != regionGeoIPSHA256 ||
		regionGeoIPRuleSet.Format != compiler.RuleSetFormatSource ||
		regionGeoIPRuleSet.RuntimePath != regionGeoIPPath {
		t.Fatalf("region GeoIP rule-set binding mismatch: %+v", regionGeoIPRuleSet)
	}
	if len(firstArtifact.SourceMap) != 4 ||
		firstArtifact.SourceMap[0].GroupID != "integration-rule-set" ||
		firstArtifact.SourceMap[1].GroupID != "region:auto-geosite:cn" ||
		firstArtifact.SourceMap[2].GroupID != "region:auto-geoip:cn" ||
		!firstArtifact.SourceMap[3].Final {
		t.Fatalf("region append source-map order mismatch: %+v", firstArtifact.SourceMap)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != firstAttempt.GenerationID {
		t.Fatalf("first apply did not commit expected state: %+v", snapshot)
	}
	if got := managed.Snapshot(); got.State != core.StateStopped || got.DesiredRunning {
		t.Fatalf("apply while stopped did not restore stopped intent: %+v", got)
	}
	firstGeneration, err := store.GenerationArtifacts(ctx, firstAttempt.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstGeneration.ManifestJSON) == 0 || firstGeneration.ManifestSHA256 == "" ||
		len(firstGeneration.SourceMapJSON) == 0 || firstGeneration.SourceMapSHA256 == "" {
		t.Fatalf("strict compiler apply did not persist metadata: %+v", firstGeneration)
	}

	if err := os.Remove(regionGeoSitePath); err != nil {
		t.Fatal(err)
	}
	missingResourceCtx, missingResourceCancel := context.WithTimeout(context.Background(), 10*time.Second)
	missingResourceErr := runtime.Start(missingResourceCtx)
	missingResourceCancel()
	if missingResourceErr == nil {
		t.Fatal("committed generation unexpectedly started without its bound rule-set resource")
	}
	if got := managed.Snapshot(); got.State != core.StateStopped || got.PID != 0 {
		t.Fatalf("missing rule-set resource disturbed stopped core state: %+v", got)
	}
	if _, _, err := ruleSets.PutRuleSet(ctx, bytes.NewReader(regionGeoSiteContent), regionGeoSiteSHA256, "source"); err != nil {
		t.Fatalf("restore missing region GeoSite resource: %v", err)
	}

	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start committed generation: %v; stderr=%s", err, managed.StderrTail())
	}
	startCancel()
	running := waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})
	firstPID := running.PID

	// T14: the pinned core returns 204 for PUT /configs without applying
	// structural changes. HTTP success must not be treated as an applied generation.
	putCtx, putCancel := context.WithTimeout(context.Background(), 5*time.Second)
	putRequest, err := http.NewRequestWithContext(
		putCtx,
		http.MethodPut,
		controlEndpoint+"/configs",
		bytes.NewBufferString(`{"mode":"Direct","mixed-port":65534}`),
	)
	if err != nil {
		putCancel()
		t.Fatal(err)
	}
	putRequest.Header.Set("Authorization", "Bearer "+secret)
	putRequest.Header.Set("Content-Type", "application/json")
	putResponse, err := http.DefaultClient.Do(putRequest)
	if err != nil {
		putCancel()
		t.Fatalf("PUT /configs no-op probe: %v", err)
	}
	putStatus := putResponse.StatusCode
	_ = putResponse.Body.Close()
	putCancel()
	if putStatus != http.StatusNoContent {
		t.Fatalf("PUT /configs status = %d, want 204", putStatus)
	}
	afterPut := managed.Snapshot()
	if afterPut.State != core.StateRunning || afterPut.PID != firstPID {
		t.Fatalf("PUT /configs disturbed running core: before=%+v after=%+v", running, afterPut)
	}
	liveMode, livePrivate, err := managed.CurrentRoutingPolicy(ctx)
	if err != nil {
		t.Fatalf("read routing policy after PUT /configs: %v", err)
	}
	if liveMode != storage.RoutingModeRule || livePrivate {
		t.Fatalf("PUT /configs changed live routing policy to %q/%t", liveMode, livePrivate)
	}
	snapshot, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil ||
		*snapshot.AppliedGenerationID != firstAttempt.GenerationID {
		t.Fatalf("PUT /configs changed applied generation state: %+v", snapshot)
	}

	if err := syscall.Kill(-firstPID, syscall.SIGKILL); err != nil {
		t.Fatalf("crash owned core process group: %v", err)
	}
	restarted := waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0 && snapshot.PID != firstPID
	})
	if restarted.ConsecutiveFails == 0 {
		t.Fatalf("unexpected restart snapshot without recorded failure: %+v", restarted)
	}

	badConfig := []byte(`{"inbounds":[{"type":"definitely-invalid"}]}`)
	badCtx, badCancel := context.WithTimeout(context.Background(), 20*time.Second)
	_, badErr := runtime.ApplyCompiled(badCtx, 1, badConfig)
	badCancel()
	if badErr == nil {
		t.Fatal("invalid candidate unexpectedly applied")
	}
	snapshot, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != firstAttempt.GenerationID {
		t.Fatalf("failed check changed confirmed generation: %+v", snapshot)
	}
	afterBad := managed.Snapshot()
	if afterBad.State != core.StateRunning || afterBad.PID != restarted.PID {
		t.Fatalf("failed pre-activation check disturbed running core: before=%+v after=%+v", restarted, afterBad)
	}

	secondDeclaration, err := store.CommitDeclaration(
		ctx,
		firstDeclaration.Revision,
		integrationDeclarationDocument("error", ruleSetSHA256, regionGeoSiteSHA256, regionGeoIPSHA256),
		"integration:second",
	)
	if err != nil {
		t.Fatal(err)
	}
	secondCtx, secondCancel := context.WithTimeout(context.Background(), 40*time.Second)
	secondAttempt, secondArtifact, err := runtime.ApplyDeclarationRevision(secondCtx, secondDeclaration.Revision, 1)
	secondCancel()
	if err != nil {
		t.Fatalf("second declaration-driven real-core apply: %v; stderr=%s", err, managed.StderrTail())
	}
	if secondArtifact.Manifest.DeclarationRevision != secondDeclaration.Revision ||
		secondArtifact.Manifest.DeclarationSHA256 != secondDeclaration.SHA256 {
		t.Fatalf("second declaration provenance mismatch: artifact=%+v declaration=%+v", secondArtifact.Manifest, secondDeclaration)
	}
	if !bytes.Contains(secondArtifact.JSON, []byte(`"server_port":10`)) {
		t.Fatalf("second controlled apply did not compile the structural node-port change: %s", secondArtifact.JSON)
	}
	snapshot, err = store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 2 || snapshot.AppliedGenerationID == nil || *snapshot.AppliedGenerationID != secondAttempt.GenerationID {
		t.Fatalf("second apply did not advance confirmed generation: %+v", snapshot)
	}
	afterSecond := managed.Snapshot()
	if afterSecond.State != core.StateRunning || afterSecond.PID <= 0 || afterSecond.PID == restarted.PID {
		t.Fatalf("second apply did not replace running generation: before=%+v after=%+v", restarted, afterSecond)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatalf("explicit stop: %v", err)
	}
	stopCancel()
	waitManagedCoreState(t, managed, 3*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateStopped && !snapshot.DesiredRunning && snapshot.PID == 0
	})
	time.Sleep(2 * policy.MaxBackoff)
	if got := managed.Snapshot(); got.State != core.StateStopped || got.DesiredRunning || got.PID != 0 {
		t.Fatalf("core restarted after explicit stop: %+v", got)
	}

	persisted, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.CoreDesiredState != storage.CoreDesiredStopped {
		t.Fatalf("explicit stop intent was not durable: %+v", persisted)
	}
	if persisted.RecoveryRequired {
		t.Fatalf("successful integration flow unexpectedly requires recovery: %+v", persisted)
	}
}

func integrationDeclarationDocument(logLevel, ruleSetSHA256, regionGeoSiteSHA256, regionGeoIPSHA256 string) []byte {
	nodePort := uint16(9)
	if logLevel == "error" {
		nodePort = 10
	}
	return []byte(fmt.Sprintf(`{
  "schema_version":1,
  "log_level":%q,
  "rule_sets":[{
    "ref":"integration:example",
    "sha256":%q,
    "format":"source"
  },{
    "ref":"geosite:cn",
    "sha256":%q,
    "format":"source"
  },{
    "ref":"geoip:cn",
    "sha256":%q,
    "format":"source"
  }],
  "nodes":[{
    "profile_id":"integration-profile",
    "node_id":"integration-node",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  },{
    "profile_id":"integration-profile",
    "node_id":"integration-vless",
    "type":"vless",
    "server":"vless.example.invalid",
    "port":443,
    "vless":{
      "uuid":"11111111-2222-3333-4444-555555555555",
      "encryption":"none",
      "network":"udp",
      "packet_encoding":""
    },
    "tls":{
      "enabled":true,
      "server_name":"edge.example.invalid",
      "insecure":true
    }
  },{
    "profile_id":"integration-profile",
    "node_id":"integration-trojan",
    "type":"trojan",
    "server":"trojan.example.invalid",
    "port":443,
    "trojan":{
      "password":"secret",
      "network":"tcp"
    }
  }],
  "selection":{
    "current":{
      "members":[
        {"kind":"specific_node","profile_id":"integration-profile","node_id":"integration-node"},
        {"kind":"specific_node","profile_id":"integration-profile","node_id":"integration-vless"},
        {"kind":"specific_node","profile_id":"integration-profile","node_id":"integration-trojan"}
      ],
      "default":{"kind":"specific_node","profile_id":"integration-profile","node_id":"integration-node"}
    },
    "custom":[]
  },
  "routing":{
    "region_append":{"region_code":"cn","geosite_enabled":true,"geoip_enabled":true},
    "custom":[{
      "id":"integration-rule-set",
      "order":1,
      "enabled":true,
      "target":{"kind":"block"},
      "match":{"op":"atom","predicate":{"kind":"rule_set","value":"integration:example"}}
    }],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":{"kind":"direct"}
  },
  "dns":{
    "profiles":[{
      "id":"integration-outbound-dns",
      "role":"outbound",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":9
    }],
    "outbound_profile_id":"integration-outbound-dns"
  }
}`, logLevel, ruleSetSHA256, regionGeoSiteSHA256, regionGeoIPSHA256, nodePort))
}

func assertOrdinaryUserCoreEnvironment(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Fatal("T01 fixed-core integration must run as an ordinary non-root user")
	}
	if os.Getenv("DISPLAY") != "" {
		t.Fatalf("T01 fixed-core integration unexpectedly has DISPLAY=%q", os.Getenv("DISPLAY"))
	}

	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("read Linux capability status: %v", err)
	}
	var capEff uint64
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "CapEff:" {
			continue
		}
		capEff, err = strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			t.Fatalf("parse CapEff %q: %v", fields[1], err)
		}
		found = true
		break
	}
	if !found {
		t.Fatal("Linux /proc/self/status did not expose CapEff")
	}
	const capNetAdmin = uint64(1) << 12
	if capEff&capNetAdmin != 0 {
		t.Fatalf("T01 fixed-core integration unexpectedly has CAP_NET_ADMIN: CapEff=%x", capEff)
	}
}

func TestManagedCoreRealPortConflictFailsClosed(t *testing.T) {
	corePath := os.Getenv("KARING_TUI_TEST_CORE")
	if corePath == "" {
		t.Skip("KARING_TUI_TEST_CORE is not set")
	}

	stateDir := t.TempDir()
	if err := os.Chmod(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	store, err := storage.Open(ctx, filepath.Join(stateDir, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ports := reserveLoopbackPorts(t, 4)
	inbounds := domain.InboundSet{
		Listen:       netip.MustParseAddr("127.0.0.1"),
		RulePort:     ports[0],
		DirectPort:   ports[1],
		SelectedPort: ports[2],
	}
	const secret = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	controlEndpoint := fmt.Sprintf("http://127.0.0.1:%d", ports[3])

	artifact := integrationCoreArtifact(t, inbounds, ports[3], secret, "warn")
	manifestJSON, sourceMapJSON, err := artifact.MetadataJSON()
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := store.PrepareApplyWithMetadata(
		ctx,
		0,
		artifact.JSON,
		manifestJSON,
		sourceMapJSON,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginVerification(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitApplied(ctx, attempt.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := store.SetCoreDesiredState(ctx, storage.CoreDesiredRunning); err != nil {
		t.Fatal(err)
	}

	owner, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", inbounds.RulePort))
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()

	policy := core.DefaultPolicy()
	policy.InitialBackoff = 20 * time.Millisecond
	policy.MaxBackoff = 40 * time.Millisecond
	policy.FailureWindow = 5 * time.Second
	policy.MaxFailures = 2
	policy.ReadyTimeout = 500 * time.Millisecond
	policy.StopTimeout = time.Second
	managed, err := NewManagedCore(store, ManagedCoreOptions{
		Executable:      corePath,
		StateRoot:       filepath.Join(stateDir, "core"),
		ControlEndpoint: controlEndpoint,
		ControlSecret:   secret,
		Inbounds:        inbounds,
		Policy:          policy,
		LogCapacity:     64 << 10,
	})
	if err != nil {
		t.Fatal(err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- managed.Run(runCtx)
	}()
	defer func() {
		runCancel()
		select {
		case err := <-runDone:
			if err != nil {
				t.Errorf("port-conflict supervisor shutdown: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Errorf("port-conflict supervisor did not shut down")
		}
	}()
	readyCtx, readyCancel := context.WithTimeout(context.Background(), time.Second)
	if err := managed.WaitReady(readyCtx); err != nil {
		readyCancel()
		t.Fatal(err)
	}
	readyCancel()

	startCtx, startCancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = managed.Start(startCtx)
	startCancel()
	if err == nil {
		t.Fatal("core unexpectedly started by avoiding the occupied declared RulePort")
	}
	failed := managed.Snapshot()
	if failed.State != core.StateFailed || !failed.CircuitOpen || failed.PID != 0 {
		t.Fatalf("port conflict did not fail closed: %+v; stderr=%s", failed, managed.StderrTail())
	}

	probe, err := net.DialTimeout("tcp4", owner.Addr().String(), 250*time.Millisecond)
	if err != nil {
		t.Fatalf("declared port owner disappeared after core start attempts: %v", err)
	}
	_ = probe.Close()
	if replacement, err := net.Listen("tcp4", owner.Addr().String()); err == nil {
		_ = replacement.Close()
		t.Fatal("declared RulePort became free; core must never kill the existing owner")
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 || snapshot.AppliedGenerationID == nil ||
		*snapshot.AppliedGenerationID != attempt.GenerationID {
		t.Fatalf("port conflict changed confirmed generation state: %+v", snapshot)
	}
}

func reserveLoopbackPorts(t *testing.T, count int) []uint16 {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	ports := make([]uint16, 0, count)
	for i := 0; i < count; i++ {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		port := listener.Addr().(*net.TCPAddr).Port
		ports = append(ports, uint16(port))
	}
	for _, listener := range listeners {
		if err := listener.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return ports
}

func integrationCoreArtifact(t *testing.T, inbounds domain.InboundSet, controlPort uint16, secret, logLevel string) compiler.NativeConfigArtifact {
	t.Helper()

	nodePort := uint16(9)
	if logLevel == "error" {
		nodePort = 10
	}
	node := domain.Node{
		ProfileID: "integration-profile",
		NodeID:    "integration-node",
		Kind:      domain.NodeHTTP,
		Server:    "integration-proxy.invalid",
		Port:      nodePort,
		HTTP:      &domain.HTTPNodeOptions{},
	}
	nodeKey := compiler.NodeTargetKey{ProfileID: node.ProfileID, NodeID: node.NodeID}
	targets, err := compiler.NewTargetCatalog(nil, []compiler.NodeTargetKey{nodeKey})
	if err != nil {
		t.Fatal(err)
	}
	nodeRef := domain.TargetRef{
		Kind:      domain.TargetSpecificNode,
		ProfileID: node.ProfileID,
		NodeID:    node.NodeID,
	}

	routing, err := compiler.CompileRouting(domain.RoutingPlan{
		Final: domain.TargetRef{Kind: domain.TargetDirect},
	}, targets)
	if err != nil {
		t.Fatal(err)
	}
	ruleSetCatalog, err := compiler.NewRuleSetCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := compiler.BindRuleSetArtifacts(routing, ruleSetCatalog)
	if err != nil {
		t.Fatal(err)
	}
	bound, err = compiler.BindStagedRuleSetPaths(bound, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}

	selection, err := compiler.CompileSelectionGroups(domain.SelectionPlan{
		Current: domain.CurrentSelection{
			Members: []domain.TargetRef{nodeRef},
			Default: nodeRef,
		},
	}, targets, routing.OutboundTags)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := compiler.CompileBasicNodeOutbounds([]domain.Node{node}, targets, selection.NodeTargets)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := compiler.CompileRuntimeDNS(domain.DNSPlan{
		Profiles: []domain.DNSProfile{
			{
				ID:        "integration-outbound-dns",
				Role:      domain.DNSRoleOutbound,
				Transport: domain.DNSTransportUDP,
				Server:    "127.0.0.1",
				Port:      9,
			},
			{
				ID:        "integration-direct-dns",
				Role:      domain.DNSRoleDirect,
				Transport: domain.DNSTransportUDP,
				Server:    "127.0.0.1",
				Port:      9,
			},
			{
				ID:        "integration-proxy-dns",
				Role:      domain.DNSRoleProxy,
				Transport: domain.DNSTransportUDP,
				Server:    "127.0.0.1",
				Port:      9,
			},
		},
		OutboundProfileID: "integration-outbound-dns",
		DirectProfileID:   "integration-direct-dns",
		ProxyProfileID:    "integration-proxy-dns",
	}, targets)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err = compiler.BindNodeDomainResolver(nodes, dns)
	if err != nil {
		t.Fatal(err)
	}
	bound, err = compiler.BindProxyTargetDNSRouting(bound, dns)
	if err != nil {
		t.Fatal(err)
	}

	artifact, err := compiler.CompileNativeConfig(compiler.NativeConfigInput{
		Inbounds:       inbounds,
		ControlAddress: netip.AddrPortFrom(inbounds.Listen, controlPort),
		ControlSecret:  secret,
		LogLevel:       logLevel,
		Targets:        targets,
		Routing:        bound,
		Selection:      selection,
		Nodes:          nodes,
		DNS:            dns,
	})
	if err != nil {
		t.Fatal(err)
	}
	declarationRevision := uint64(1)
	declarationSHA256 := "1111111111111111111111111111111111111111111111111111111111111111"
	if logLevel == "error" {
		declarationRevision = 2
		declarationSHA256 = "2222222222222222222222222222222222222222222222222222222222222222"
	}
	artifact, err = artifact.BindDeclaration(declarationRevision, declarationSHA256)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func waitManagedCoreState(t *testing.T, managed *ManagedCore, timeout time.Duration, accept func(core.Snapshot) bool) core.Snapshot {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		snapshot := managed.Snapshot()
		if accept(snapshot) {
			return snapshot
		}
		if snapshot.State == core.StateFailed {
			t.Fatalf("managed core entered failed state: %+v; stderr=%s", snapshot, managed.StderrTail())
		}
		time.Sleep(20 * time.Millisecond)
	}
	snapshot := managed.Snapshot()
	t.Fatalf("managed core state timeout: %+v; stderr=%s", snapshot, managed.StderrTail())
	return core.Snapshot{}
}
