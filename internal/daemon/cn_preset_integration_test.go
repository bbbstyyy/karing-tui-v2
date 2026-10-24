//go:build integration && linux

package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
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

func TestManagedCoreRealCNPresetRouting(t *testing.T) {
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

	proxyAddress, proxyHits, closeProxy := startRejectingHTTPProxy(t)
	defer closeProxy()

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
	matchContent := []byte(`{"version":4,"rules":[{"ip_cidr":["127.0.0.1/32"]}]}`)
	matchSHA256 := fmt.Sprintf("%x", sha256.Sum256(matchContent))
	if _, _, err := ruleSets.PutRuleSet(ctx, bytes.NewReader(matchContent), matchSHA256, "source"); err != nil {
		t.Fatal(err)
	}
	noMatchContent := []byte(`{"version":4,"rules":[{"ip_cidr":["198.18.0.0/15"]}]}`)
	noMatchSHA256 := fmt.Sprintf("%x", sha256.Sum256(noMatchContent))
	if _, _, err := ruleSets.PutRuleSet(ctx, bytes.NewReader(noMatchContent), noMatchSHA256, "source"); err != nil {
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

	firstDocument := cnPresetIntegrationDeclaration(
		t,
		proxyAddress.Port(),
		"acl:ChinaIp",
		matchSHA256,
		noMatchSHA256,
		nil,
	)
	firstDeclaration, err := store.CommitDeclaration(ctx, 0, firstDocument, "integration:cn-default")
	if err != nil {
		t.Fatal(err)
	}
	applyCtx, applyCancel := context.WithTimeout(context.Background(), 40*time.Second)
	firstAttempt, firstArtifact, err := runtime.ApplyDeclarationRevision(applyCtx, firstDeclaration.Revision, 0)
	applyCancel()
	if err != nil {
		t.Fatalf("apply default CN declaration: %v; stderr=%s", err, managed.StderrTail())
	}
	if firstAttempt.GenerationID == 0 {
		t.Fatal("default CN apply did not create a generation")
	}
	wantDefaultSourceMap := []string{
		"cn.apple-services",
		"cn.google-play",
		"cn.google",
		"cn.bilibili",
		"cn.domestic-direct",
		"cn.foreign-proxy",
	}
	assertCNPresetSourceMap(t, firstArtifact.SourceMap, wantDefaultSourceMap)

	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	if err := runtime.Start(startCtx); err != nil {
		startCancel()
		t.Fatalf("start default CN generation: %v; stderr=%s", err, managed.StderrTail())
	}
	startCancel()
	waitManagedCoreState(t, managed, 5*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateRunning && snapshot.PID > 0
	})

	ruleAddress := netip.AddrPortFrom(inbounds.Listen, inbounds.RulePort)
	firstTarget, firstTargetHits, closeFirstTarget := startRouteOutcomeTarget(t)
	connectCtx, connectCancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := socks5Connect(connectCtx, ruleAddress, firstTarget)
	connectCancel()
	if err != nil {
		closeFirstTarget()
		t.Fatalf("default CN domestic DIRECT route failed: %v; stderr=%s", err, managed.StderrTail())
	}
	var marker [2]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		_ = conn.Close()
		closeFirstTarget()
		t.Fatalf("read default CN direct marker: %v", err)
	}
	_ = conn.Close()
	closeFirstTarget()
	if marker != [2]byte{'o', 'k'} {
		t.Fatalf("default CN direct marker = %q", marker)
	}
	assertRouteOutcomeSignal(t, firstTargetHits, 2*time.Second, "default CN domestic target")
	assertNoRouteOutcomeSignal(t, proxyHits, 100*time.Millisecond, "default CN selected proxy")

	secondDocument := cnPresetIntegrationDeclaration(
		t,
		proxyAddress.Port(),
		"geosite:geolocation-!cn",
		matchSHA256,
		noMatchSHA256,
		[]string{"cn.domestic-direct"},
	)
	secondDeclaration, err := store.CommitDeclaration(
		ctx,
		firstDeclaration.Revision,
		secondDocument,
		"integration:cn-foreign",
	)
	if err != nil {
		t.Fatal(err)
	}
	secondCtx, secondCancel := context.WithTimeout(context.Background(), 40*time.Second)
	_, secondArtifact, err := runtime.ApplyDeclarationRevision(secondCtx, secondDeclaration.Revision, 1)
	secondCancel()
	if err != nil {
		t.Fatalf("apply CN foreign-proxy declaration: %v; stderr=%s", err, managed.StderrTail())
	}
	wantForeignSourceMap := []string{
		"cn.apple-services",
		"cn.google-play",
		"cn.google",
		"cn.bilibili",
		"cn.foreign-proxy",
	}
	assertCNPresetSourceMap(t, secondArtifact.SourceMap, wantForeignSourceMap)

	secondTarget, secondTargetHits, closeSecondTarget := startRouteOutcomeTarget(t)
	defer closeSecondTarget()
	connectCtx, connectCancel = context.WithTimeout(context.Background(), 3*time.Second)
	conn, err = socks5Connect(connectCtx, ruleAddress, secondTarget)
	connectCancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("CN foreign-proxy route unexpectedly bypassed CurrentSelected")
	}
	assertRouteOutcomeSignal(t, proxyHits, 2*time.Second, "CN foreign-proxy CurrentSelected")
	assertNoRouteOutcomeSignal(t, secondTargetHits, 100*time.Millisecond, "CN foreign-proxy direct target")

	thirdDocument := cnPresetProcessIntegrationDeclaration(t, proxyAddress.Port(), noMatchSHA256)
	thirdDeclaration, err := store.CommitDeclaration(
		ctx,
		secondDeclaration.Revision,
		thirdDocument,
		"integration:cn-process-name",
	)
	if err != nil {
		t.Fatal(err)
	}
	thirdCtx, thirdCancel := context.WithTimeout(context.Background(), 40*time.Second)
	_, thirdArtifact, err := runtime.ApplyDeclarationRevision(thirdCtx, thirdDeclaration.Revision, 2)
	thirdCancel()
	if err != nil {
		t.Fatalf("apply CN process-name declaration: %v; stderr=%s", err, managed.StderrTail())
	}
	wantProcessSourceMap := []string{
		"cn.apple-services",
		"cn.google-play",
		"cn.google",
		"cn.whatsapp",
		"cn.bilibili",
		"cn.domestic-direct",
		"cn.foreign-proxy",
	}
	assertCNPresetSourceMap(t, thirdArtifact.SourceMap, wantProcessSourceMap)
	nativeJSON := string(thirdArtifact.JSON)
	for _, want := range []string{
		`"find_process":true`,
		`"process_name":["WhatsApp.exe"]`,
		`"process_name":["WhatsApp"]`,
	} {
		if !strings.Contains(nativeJSON, want) {
			t.Fatalf("CN process-name native config missing %s: %s", want, nativeJSON)
		}
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := runtime.Stop(stopCtx); err != nil {
		stopCancel()
		t.Fatalf("stop CN preset core: %v", err)
	}
	stopCancel()
	waitManagedCoreState(t, managed, 3*time.Second, func(snapshot core.Snapshot) bool {
		return snapshot.State == core.StateStopped && snapshot.PID == 0
	})
}

func cnPresetIntegrationDeclaration(
	t *testing.T,
	proxyPort uint16,
	matchRef string,
	matchSHA256 string,
	noMatchSHA256 string,
	disabledGroups []string,
) []byte {
	t.Helper()
	snapshot, err := preset.LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	disabled := make(map[string]struct{}, len(disabledGroups))
	for _, id := range disabledGroups {
		disabled[id] = struct{}{}
	}

	type ruleSetResource struct {
		Ref    string `json:"ref"`
		SHA256 string `json:"sha256"`
		Format string `json:"format"`
	}
	resources := make([]ruleSetResource, 0)
	seenRefs := make(map[string]struct{})
	matchFound := false
	for _, group := range snapshot.Groups {
		if !group.Enabled {
			continue
		}
		if _, isDisabled := disabled[group.ID]; isDisabled {
			continue
		}
		for _, ref := range group.Source.RuleSetBuildIn {
			if _, exists := seenRefs[ref]; exists {
				continue
			}
			seenRefs[ref] = struct{}{}
			sha := noMatchSHA256
			if ref == matchRef {
				sha = matchSHA256
				matchFound = true
			}
			resources = append(resources, ruleSetResource{
				Ref:    ref,
				SHA256: sha,
				Format: "source",
			})
		}
	}
	if !matchFound {
		t.Fatalf("match ref %q is not active in CN fixture", matchRef)
	}
	resourceJSON, err := json.Marshal(resources)
	if err != nil {
		t.Fatal(err)
	}

	type override struct {
		GroupID string `json:"group_id"`
		Enabled bool   `json:"enabled"`
	}
	overrides := make([]override, 0, len(disabledGroups))
	for _, id := range disabledGroups {
		overrides = append(overrides, override{GroupID: id, Enabled: false})
	}
	overrideJSON, err := json.Marshal(overrides)
	if err != nil {
		t.Fatal(err)
	}

	return []byte(fmt.Sprintf(`{
  "schema_version":1,
  "log_level":"warn",
  "rule_sets":%s,
  "nodes":[{
    "profile_id":"cn-profile",
    "node_id":"cn-selected",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{"kind":"specific_node","profile_id":"cn-profile","node_id":"cn-selected"}],
      "default":{"kind":"specific_node","profile_id":"cn-profile","node_id":"cn-selected"}
    },
    "custom":[]
  },
  "routing":{
    "cn_preset":{
      "source_commit":%q,
      "overrides":%s
    },
    "custom":[],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":{"kind":"direct"}
  },
  "dns":{
    "profiles":[{
      "id":"cn-outbound-dns",
      "role":"outbound",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":9
    }],
    "outbound_profile_id":"cn-outbound-dns"
  }
}`, resourceJSON, proxyPort, preset.CNSourceCommit, overrideJSON))
}

func cnPresetProcessIntegrationDeclaration(t *testing.T, proxyPort uint16, noMatchSHA256 string) []byte {
	t.Helper()
	snapshot, err := preset.LoadCN()
	if err != nil {
		t.Fatal(err)
	}

	type ruleSetResource struct {
		Ref    string `json:"ref"`
		SHA256 string `json:"sha256"`
		Format string `json:"format"`
	}
	resources := make([]ruleSetResource, 0)
	seenRefs := make(map[string]struct{})
	for _, group := range snapshot.Groups {
		if !group.Enabled && group.ID != "cn.whatsapp" {
			continue
		}
		for _, ref := range group.Source.RuleSetBuildIn {
			if _, exists := seenRefs[ref]; exists {
				continue
			}
			seenRefs[ref] = struct{}{}
			resources = append(resources, ruleSetResource{
				Ref:    ref,
				SHA256: noMatchSHA256,
				Format: "source",
			})
		}
	}
	resourceJSON, err := json.Marshal(resources)
	if err != nil {
		t.Fatal(err)
	}

	return []byte(fmt.Sprintf(`{
  "schema_version":1,
  "log_level":"warn",
  "rule_sets":%s,
  "nodes":[{
    "profile_id":"cn-profile",
    "node_id":"cn-selected",
    "type":"http",
    "server":"127.0.0.1",
    "port":%d,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{"kind":"specific_node","profile_id":"cn-profile","node_id":"cn-selected"}],
      "default":{"kind":"specific_node","profile_id":"cn-profile","node_id":"cn-selected"}
    },
    "custom":[]
  },
  "routing":{
    "cn_preset":{
      "source_commit":%q,
      "overrides":[{"group_id":"cn.whatsapp","enabled":true}]
    },
    "custom":[],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":{"kind":"direct"}
  },
  "dns":{
    "profiles":[{
      "id":"cn-outbound-dns",
      "role":"outbound",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":9
    }],
    "outbound_profile_id":"cn-outbound-dns"
  }
}`, resourceJSON, proxyPort, preset.CNSourceCommit))
}

func assertCNPresetSourceMap(t *testing.T, sourceMap []compiler.RouteSourceMapEntry, wantGroupIDs []string) {
	t.Helper()
	if len(sourceMap) != len(wantGroupIDs)+1 {
		t.Fatalf("CN source-map entries = %d, want %d groups + FINAL: %+v", len(sourceMap), len(wantGroupIDs), sourceMap)
	}
	for i, groupID := range wantGroupIDs {
		if sourceMap[i].Layer != domain.LayerCustom ||
			sourceMap[i].GroupID != groupID ||
			sourceMap[i].Final {
			t.Fatalf("CN source-map entry %d = %+v, want custom group %q", i, sourceMap[i], groupID)
		}
	}
	if !sourceMap[len(sourceMap)-1].Final {
		t.Fatalf("CN source-map final entry = %+v", sourceMap[len(sourceMap)-1])
	}
}
