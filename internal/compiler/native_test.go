package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const nativeTestSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestCompileNativeConfigBuildsDeterministicRunnableEnvelope(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	first, err := CompileNativeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileNativeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.JSON) != string(second.JSON) || first.SHA256 != second.SHA256 || !reflect.DeepEqual(first.Manifest, second.Manifest) {
		t.Fatal("native config output is not deterministic")
	}

	sum := sha256.Sum256(first.JSON)
	if got, want := first.SHA256, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("config SHA-256 = %q, want %q", got, want)
	}
	if first.Manifest.SchemaID != NativeSchemaID || first.Manifest.ConfigSHA256 != first.SHA256 {
		t.Fatalf("unexpected manifest identity: %+v", first.Manifest)
	}
	if got, want := first.Manifest.InboundTags, []string{
		domain.InboundTagRule,
		domain.InboundTagDirect,
		domain.InboundTagSelected,
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("inbound tags = %#v, want %#v", got, want)
	}
	if strings.Contains(string(first.JSON), `"set_system_proxy":true`) {
		t.Fatal("native config enables system proxy mutation")
	}

	var decoded struct {
		Inbounds []struct {
			Type           string `json:"type"`
			Tag            string `json:"tag"`
			Listen         string `json:"listen"`
			ListenPort     uint16 `json:"listen_port"`
			SetSystemProxy bool   `json:"set_system_proxy"`
		} `json:"inbounds"`
		Outbounds []map[string]any `json:"outbounds"`
		Route struct {
			Rules []RouteRule `json:"rules"`
		} `json:"route"`
		Experimental struct {
			ClashAPI struct {
				ExternalController string `json:"external_controller"`
				Secret             string `json:"secret"`
				DefaultMode        string `json:"default_mode"`
			} `json:"clash_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(first.JSON, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Inbounds) != 3 {
		t.Fatalf("inbounds = %d, want 3", len(decoded.Inbounds))
	}
	for _, inbound := range decoded.Inbounds {
		if inbound.Type != "mixed" || inbound.Listen != "127.0.0.1" || inbound.SetSystemProxy {
			t.Fatalf("unsafe inbound: %+v", inbound)
		}
	}
	if got := []string{
		decoded.Outbounds[0]["type"].(string),
		decoded.Outbounds[1]["type"].(string),
		decoded.Outbounds[2]["type"].(string),
	}; !reflect.DeepEqual(got, []string{"direct", "http", "selector"}) {
		t.Fatalf("outbound type order = %#v", got)
	}
	if len(decoded.Route.Rules) != 3 {
		t.Fatalf("route rules = %d, want Direct + Selected + Rule FINAL", len(decoded.Route.Rules))
	}
	if decoded.Experimental.ClashAPI.ExternalController != "127.0.0.1:3057" ||
		decoded.Experimental.ClashAPI.Secret != nativeTestSecret ||
		decoded.Experimental.ClashAPI.DefaultMode != "Rule" {
		t.Fatalf("unexpected Clash API config: %+v", decoded.Experimental.ClashAPI)
	}
}

func TestCompileNativeConfigRejectsDomainNodeUntilDNSCompilerExists(t *testing.T) {
	input := nativeTestInput(t, "proxy.example.com")
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrDNSRequired) {
		t.Fatalf("domain node error = %v", err)
	}
}

func TestCompileNativeConfigRejectsIncompleteOutboundClosure(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	input.Routing.OutboundTags = append(input.Routing.OutboundTags, "out-missing")
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrNativeConfigClosure) {
		t.Fatalf("missing outbound error = %v", err)
	}
}

func TestCompileNativeConfigRequiresStagedRuleSets(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateRuleSet, Value: "acl:test"})
	compiled, err := CompileRouting(domain.RoutingPlan{
		ACL: []domain.RouteGroup{{
			ID:    "acl-test",
			Layer: domain.LayerACL,
			Order: 1,
			Match: &match,
			Binding: domain.RouteBinding{
				Enabled: true,
				Target:  domain.TargetRef{Kind: domain.TargetDirect},
			},
		}},
		Final: domain.TargetRef{Kind: domain.TargetDirect},
	}, input.Targets)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewRuleSetCatalog([]RuleSetSource{{
		Ref:    "acl:test",
		Path:   "/package/acl-test.srs",
		SHA256: strings.Repeat("a", 64),
		Format: RuleSetFormatBinary,
	}})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindRuleSetArtifacts(compiled, catalog)
	if err != nil {
		t.Fatal(err)
	}
	input.Routing = bound

	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrRuleSetNotStaged) {
		t.Fatalf("unstaged rule-set error = %v", err)
	}

	runtimePath := "/state/core/rule-sets/sha256/" + strings.Repeat("a", 64) + ".srs"
	staged, err := BindStagedRuleSetPaths(bound, map[string]string{"acl:test": runtimePath})
	if err != nil {
		t.Fatal(err)
	}
	input.Routing = staged
	artifact, err := CompileNativeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Manifest.RuleSets) != 1 || artifact.Manifest.RuleSets[0].RuntimePath != runtimePath {
		t.Fatalf("unexpected rule-set manifest: %+v", artifact.Manifest.RuleSets)
	}
	if !strings.Contains(string(artifact.JSON), runtimePath) {
		t.Fatalf("native config does not reference staged path: %s", artifact.JSON)
	}
}

func TestCompileNativeConfigRejectsUnsafeControlPlane(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")

	input.ControlAddress = netip.MustParseAddrPort("0.0.0.0:3057")
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrInvalidControlPlane) {
		t.Fatalf("non-loopback control error = %v", err)
	}

	input = nativeTestInput(t, "127.0.0.1")
	input.ControlAddress = netip.AddrPortFrom(input.Inbounds.Listen, input.Inbounds.RulePort)
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrInvalidControlPlane) {
		t.Fatalf("control port conflict error = %v", err)
	}

	input = nativeTestInput(t, "127.0.0.1")
	input.ControlSecret = "bad"
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrInvalidControlPlane) {
		t.Fatalf("control secret error = %v", err)
	}
}

func TestCompileNativeConfigRejectsUnsupportedLogLevel(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	input.LogLevel = "verbose"
	if _, err := CompileNativeConfig(input); err == nil {
		t.Fatal("unsupported log level unexpectedly accepted")
	}
}

func nativeTestInput(t *testing.T, server string) NativeConfigInput {
	t.Helper()
	node := domain.Node{
		ProfileID: "profile-a",
		NodeID:    "node-a",
		Kind:      domain.NodeHTTP,
		Server:    server,
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}
	key := NodeTargetKey{ProfileID: node.ProfileID, NodeID: node.NodeID}
	targets, err := NewTargetCatalog(nil, []NodeTargetKey{key})
	if err != nil {
		t.Fatal(err)
	}
	nodeRef := domain.TargetRef{
		Kind:      domain.TargetSpecificNode,
		ProfileID: node.ProfileID,
		NodeID:    node.NodeID,
	}

	routing, err := CompileRouting(domain.RoutingPlan{
		Final: domain.TargetRef{Kind: domain.TargetDirect},
	}, targets)
	if err != nil {
		t.Fatal(err)
	}
	ruleSets, err := NewRuleSetCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindRuleSetArtifacts(routing, ruleSets)
	if err != nil {
		t.Fatal(err)
	}
	bound, err = BindStagedRuleSetPaths(bound, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}

	selection, err := CompileSelectionGroups(domain.SelectionPlan{
		Current: domain.CurrentSelection{
			Members: []domain.TargetRef{nodeRef},
			Default: nodeRef,
		},
	}, targets, routing.OutboundTags)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := CompileBasicNodeOutbounds([]domain.Node{node}, targets, selection.NodeTargets)
	if err != nil {
		t.Fatal(err)
	}

	return NativeConfigInput{
		Inbounds:       domain.DefaultInboundSet(),
		ControlAddress: netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:  nativeTestSecret,
		LogLevel:       "warn",
		Targets:        targets,
		Routing:        bound,
		Selection:      selection,
		Nodes:          nodes,
	}
}
