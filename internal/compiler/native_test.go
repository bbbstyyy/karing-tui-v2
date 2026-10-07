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
		Route     struct {
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
	if len(decoded.Route.Rules) != 8 {
		t.Fatalf("route rules = %d, want entry/mode/private rules plus Rule FINAL", len(decoded.Route.Rules))
	}
	if decoded.Experimental.ClashAPI.ExternalController != "127.0.0.1:3057" ||
		decoded.Experimental.ClashAPI.Secret != nativeTestSecret ||
		decoded.Experimental.ClashAPI.DefaultMode != "Rule" {
		t.Fatalf("unexpected Clash API config: %+v", decoded.Experimental.ClashAPI)
	}
}

func TestCompileNativeConfigRejectsDomainNodeWithoutBoundResolver(t *testing.T) {
	input := nativeTestInput(t, "proxy.example.com")
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrDNSRequired) {
		t.Fatalf("domain node error = %v", err)
	}
}

func TestCompileNativeConfigAllowsDomainNodeWithExplicitOutboundDNS(t *testing.T) {
	input := nativeTestInput(t, "proxy.example.com")
	dns, err := CompileOutboundDNS(domain.DNSPlan{
		Profiles: []domain.DNSProfile{{
			ID:        "outbound",
			Role:      domain.DNSRoleOutbound,
			Transport: domain.DNSTransportUDP,
			Server:    "192.0.2.53",
			Port:      53,
		}},
		OutboundProfileID: "outbound",
	}, input.Targets)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := BindNodeDomainResolver(input.Nodes, dns)
	if err != nil {
		t.Fatal(err)
	}
	input.DNS = dns
	input.Nodes = nodes

	artifact, err := CompileNativeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := artifact.Manifest.DNSServerTags, []string{dns.OutboundResolverTag, nativeDNSFailClosedTag}; !reflect.DeepEqual(got, want) {
		t.Fatalf("DNS manifest tags = %#v, want %#v", got, want)
	}

	var decoded struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Final   string           `json:"final"`
		} `json:"dns"`
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(artifact.JSON, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.DNS.Servers) != 2 {
		t.Fatalf("DNS servers = %d, want outbound + fail-closed", len(decoded.DNS.Servers))
	}
	if decoded.DNS.Servers[0]["type"] != "udp" ||
		decoded.DNS.Servers[0]["tag"] != dns.OutboundResolverTag {
		t.Fatalf("unexpected outbound DNS server: %+v", decoded.DNS.Servers[0])
	}
	if _, exists := decoded.DNS.Servers[0]["detour"]; exists {
		t.Fatalf("approved core direct-dial DNS server must omit detour: %+v", decoded.DNS.Servers[0])
	}
	if decoded.DNS.Servers[1]["type"] != "predefined" ||
		decoded.DNS.Servers[1]["tag"] != nativeDNSFailClosedTag ||
		decoded.DNS.Servers[1]["rcode"] != "REFUSED" {
		t.Fatalf("unexpected fail-closed DNS server: %+v", decoded.DNS.Servers[1])
	}
	if decoded.DNS.Final != nativeDNSFailClosedTag || decoded.DNS.Final == dns.OutboundResolverTag {
		t.Fatalf("DNS final = %q, want fail-closed tag", decoded.DNS.Final)
	}
	if got := decoded.Outbounds[1]["domain_resolver"]; got != dns.OutboundResolverTag {
		t.Fatalf("domain node resolver = %#v, want %q", got, dns.OutboundResolverTag)
	}
}

func TestCompileNativeConfigRejectsDNSClosureOutOfDependencyOrder(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	input.DNS = CompiledDNS{
		Servers: []DNSServerConfig{
			{
				Type:           "tcp",
				Tag:            "dns-outbound",
				Server:         "resolver.example.com",
				ServerPort:     53,
				DomainResolver: "dns-bootstrap",
			},
			{
				Type:       "udp",
				Tag:        "dns-bootstrap",
				Server:     "192.0.2.53",
				ServerPort: 53,
			},
		},
		OutboundResolverTag: "dns-outbound",
	}
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrNativeConfigClosure) {
		t.Fatalf("out-of-order DNS dependency error = %v", err)
	}
}

func TestCompileNativeConfigRejectsResolverOnIPLiteralNode(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	input.Nodes.Outbounds[0].DomainResolver = "dns-unexpected"
	if _, err := CompileNativeConfig(input); !errors.Is(err, ErrNativeConfigClosure) {
		t.Fatalf("IP node resolver error = %v", err)
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

func TestNativeConfigArtifactMetadataJSONIsDeterministic(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateDomainSuffix, Value: "example.com"})
	routing, err := CompileRouting(domain.RoutingPlan{
		Custom: []domain.RouteGroup{{
			ID:    "custom-a",
			Layer: domain.LayerCustom,
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
	catalog, err := NewRuleSetCatalog(nil)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindRuleSetArtifacts(routing, catalog)
	if err != nil {
		t.Fatal(err)
	}
	bound, err = BindStagedRuleSetPaths(bound, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	input.Routing = bound

	artifact, err := CompileNativeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	manifestA, sourceMapA, err := artifact.MetadataJSON()
	if err != nil {
		t.Fatal(err)
	}
	manifestB, sourceMapB, err := artifact.MetadataJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(manifestA) != string(manifestB) || string(sourceMapA) != string(sourceMapB) {
		t.Fatal("metadata JSON is not deterministic")
	}
	if !strings.Contains(string(manifestA), `"schema_id":"`+NativeSchemaID+`"`) ||
		!strings.Contains(string(manifestA), `"config_sha256":"`+artifact.SHA256+`"`) ||
		!strings.Contains(string(manifestA), `"inbound_tags"`) ||
		!strings.Contains(string(manifestA), `"outbound_tags"`) {
		t.Fatalf("unexpected manifest JSON: %s", manifestA)
	}
	if strings.Contains(string(manifestA), "SchemaID") || strings.Contains(string(sourceMapA), "RuleIndex") {
		t.Fatalf("metadata leaked Go field names: manifest=%s source-map=%s", manifestA, sourceMapA)
	}
	if !strings.Contains(string(sourceMapA), `"rule_index":6`) ||
		!strings.Contains(string(sourceMapA), `"layer":"custom"`) ||
		!strings.Contains(string(sourceMapA), `"group_id":"custom-a"`) ||
		!strings.Contains(string(sourceMapA), `"target":{"kind":"direct"}`) {
		t.Fatalf("unexpected source-map JSON: %s", sourceMapA)
	}
}

func TestNativeConfigArtifactMetadataJSONCopiesSourceMap(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	artifact, err := CompileNativeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.SourceMap) == 0 {
		t.Fatal("compiled artifact has no source map")
	}
	originalGroup := artifact.SourceMap[0].GroupID
	input.Routing.SourceMap[0].GroupID = "mutated-after-compile"
	if artifact.SourceMap[0].GroupID != originalGroup {
		t.Fatal("compiled artifact source map aliases compiler input")
	}
}
