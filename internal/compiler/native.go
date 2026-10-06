package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const (
	NativeSchemaID         = "karing-sing-box-1.13.19@beddeababcc71dfb0c78124598b13341c06c69fb"
	nativeDNSFailClosedTag = "dns-fail-closed"
)

var (
	ErrNativeConfigClosure = errors.New("native config dependency closure is incomplete")
	ErrDNSRequired         = errors.New("node server requires outbound DNS compilation")
	ErrInvalidControlPlane = errors.New("invalid core control plane")
)

type NativeConfigInput struct {
	Inbounds       domain.InboundSet
	ControlAddress netip.AddrPort
	ControlSecret  string
	LogLevel       string
	Targets        TargetCatalog
	Routing        BoundRouting
	Selection      CompiledSelection
	Nodes          CompiledNodes
	DNS            CompiledDNS
}

type NativeConfigArtifact struct {
	JSON      []byte
	SHA256    string
	Manifest  NativeManifest
	SourceMap []RouteSourceMapEntry
}

type NativeManifest struct {
	SchemaID            string                  `json:"schema_id"`
	ConfigSHA256        string                  `json:"config_sha256"`
	DeclarationRevision uint64                  `json:"declaration_revision,omitempty"`
	DeclarationSHA256   string                  `json:"declaration_sha256,omitempty"`
	InboundTags         []string                `json:"inbound_tags"`
	OutboundTags        []string                `json:"outbound_tags"`
	DNSServerTags       []string                `json:"dns_server_tags,omitempty"`
	RuleSets            []NativeRuleSetManifest `json:"rule_sets,omitempty"`
}

type NativeRuleSetManifest struct {
	Ref         string        `json:"ref"`
	RuntimeTag  string        `json:"runtime_tag"`
	RuntimePath string        `json:"runtime_path"`
	SHA256      string        `json:"sha256"`
	Format      RuleSetFormat `json:"format"`
}

type nativeLogConfig struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
}

type nativeInboundConfig struct {
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	Listen         string `json:"listen"`
	ListenPort     uint16 `json:"listen_port"`
	SetSystemProxy bool   `json:"set_system_proxy"`
}

type nativeDirectOutbound struct {
	Type           string `json:"type"`
	Tag            string `json:"tag"`
	DomainResolver string `json:"domain_resolver,omitempty"`
}

type nativePredefinedDNSServer struct {
	Type  string `json:"type"`
	Tag   string `json:"tag"`
	Rcode string `json:"rcode"`
}

type nativeDNSConfig struct {
	Servers []any  `json:"servers"`
	Final   string `json:"final"`
}

type nativeRouteConfig struct {
	Rules       []RouteRule          `json:"rules"`
	RuleSet     []LocalRuleSetConfig `json:"rule_set,omitempty"`
	FindProcess bool                 `json:"find_process,omitempty"`
}

type nativeClashAPIConfig struct {
	ExternalController string `json:"external_controller"`
	Secret             string `json:"secret"`
	DefaultMode        string `json:"default_mode"`
}

type nativeExperimentalConfig struct {
	ClashAPI nativeClashAPIConfig `json:"clash_api"`
}

type nativeConfig struct {
	Log          nativeLogConfig          `json:"log"`
	DNS          *nativeDNSConfig         `json:"dns,omitempty"`
	Inbounds     []nativeInboundConfig    `json:"inbounds"`
	Outbounds    []any                    `json:"outbounds"`
	Route        nativeRouteConfig        `json:"route"`
	Experimental nativeExperimentalConfig `json:"experimental"`
}

func CompileNativeConfig(input NativeConfigInput) (NativeConfigArtifact, error) {
	inbounds, inboundTags, err := compileNativeInbounds(input.Inbounds)
	if err != nil {
		return NativeConfigArtifact{}, err
	}
	if err := validateControlPlane(input.ControlAddress, input.ControlSecret, input.Inbounds); err != nil {
		return NativeConfigArtifact{}, err
	}
	if err := validateNativeLogLevel(input.LogLevel); err != nil {
		return NativeConfigArtifact{}, err
	}
	if err := input.Targets.Validate(); err != nil {
		return NativeConfigArtifact{}, err
	}
	if input.Targets.DirectTag == "" {
		return NativeConfigArtifact{}, fmt.Errorf("%w: DIRECT tag is empty", ErrNativeConfigClosure)
	}

	ruleSets := make([]LocalRuleSetConfig, 0, len(input.Routing.RuleSets))
	ruleSetTags := make(map[string]struct{}, len(input.Routing.RuleSets))
	manifestRuleSets := make([]NativeRuleSetManifest, 0, len(input.Routing.RuleSets))
	for _, artifact := range input.Routing.RuleSets {
		config, err := artifact.LocalConfig()
		if err != nil {
			return NativeConfigArtifact{}, err
		}
		if _, exists := ruleSetTags[artifact.RuntimeTag]; exists {
			return NativeConfigArtifact{}, fmt.Errorf("%w: duplicate rule-set runtime tag %q", ErrNativeConfigClosure, artifact.RuntimeTag)
		}
		ruleSetTags[artifact.RuntimeTag] = struct{}{}
		ruleSets = append(ruleSets, config)
		manifestRuleSets = append(manifestRuleSets, NativeRuleSetManifest{
			Ref:         artifact.Ref,
			RuntimeTag:  artifact.RuntimeTag,
			RuntimePath: artifact.RuntimePath,
			SHA256:      artifact.SHA256,
			Format:      artifact.Format,
		})
	}
	if err := validateRouteRuleSetTags(input.Routing.Rules, ruleSetTags); err != nil {
		return NativeConfigArtifact{}, err
	}

	nativeDNS, dnsTags, err := compileNativeDNS(input.DNS, input.Targets)
	if err != nil {
		return NativeConfigArtifact{}, err
	}
	dnsTagSet := make(map[string]struct{}, len(dnsTags))
	for _, tag := range dnsTags {
		dnsTagSet[tag] = struct{}{}
	}

	outbounds := make([]any, 0, 1+len(input.Nodes.Outbounds)+len(input.Selection.Groups))
	outboundTags := make([]string, 0, cap(outbounds))
	outboundSeen := make(map[string]struct{}, cap(outbounds))
	addOutbound := func(tag string, value any) error {
		if err := validateGeneratedTag(tag); err != nil {
			return err
		}
		if _, exists := outboundSeen[tag]; exists {
			return fmt.Errorf("%w: duplicate outbound tag %q", ErrNativeConfigClosure, tag)
		}
		outboundSeen[tag] = struct{}{}
		outboundTags = append(outboundTags, tag)
		outbounds = append(outbounds, value)
		return nil
	}

	directOutbound := nativeDirectOutbound{Type: "direct", Tag: input.Targets.DirectTag}
	if input.DNS.DirectResolverTag != "" {
		if _, exists := dnsTagSet[input.DNS.DirectResolverTag]; !exists {
			return NativeConfigArtifact{}, fmt.Errorf("%w: direct resolver %q is unavailable", ErrNativeConfigClosure, input.DNS.DirectResolverTag)
		}
		directOutbound.DomainResolver = input.DNS.DirectResolverTag
	}
	if err := addOutbound(input.Targets.DirectTag, directOutbound); err != nil {
		return NativeConfigArtifact{}, err
	}

	if len(input.Nodes.Outbounds) != len(input.Nodes.Tags) || len(input.Nodes.Outbounds) != len(input.Nodes.Targets) {
		return NativeConfigArtifact{}, fmt.Errorf("%w: node compiler metadata lengths do not match", ErrNativeConfigClosure)
	}
	for i, outbound := range input.Nodes.Outbounds {
		if outbound.Tag != input.Nodes.Tags[i] {
			return NativeConfigArtifact{}, fmt.Errorf("%w: node outbound tag %q does not match metadata tag %q", ErrNativeConfigClosure, outbound.Tag, input.Nodes.Tags[i])
		}
		if _, err := netip.ParseAddr(outbound.Server); err != nil {
			if outbound.DomainResolver == "" {
				return NativeConfigArtifact{}, fmt.Errorf("%w: node %q server %q has no explicit resolver", ErrDNSRequired, outbound.Tag, outbound.Server)
			}
			if outbound.DomainResolver != input.DNS.OutboundResolverTag {
				return NativeConfigArtifact{}, fmt.Errorf("%w: node %q resolver %q is not the compiled outbound resolver %q", ErrNativeConfigClosure, outbound.Tag, outbound.DomainResolver, input.DNS.OutboundResolverTag)
			}
			if _, exists := dnsTagSet[outbound.DomainResolver]; !exists {
				return NativeConfigArtifact{}, fmt.Errorf("%w: node %q resolver %q is unavailable", ErrNativeConfigClosure, outbound.Tag, outbound.DomainResolver)
			}
		} else if outbound.DomainResolver != "" {
			return NativeConfigArtifact{}, fmt.Errorf("%w: IP-literal node %q unexpectedly carries resolver %q", ErrNativeConfigClosure, outbound.Tag, outbound.DomainResolver)
		}
		if err := addOutbound(outbound.Tag, outbound); err != nil {
			return NativeConfigArtifact{}, err
		}
	}

	for _, group := range input.Selection.Groups {
		for _, dependency := range group.Outbounds {
			if _, exists := outboundSeen[dependency]; !exists {
				return NativeConfigArtifact{}, fmt.Errorf("%w: group %q references unavailable outbound %q", ErrNativeConfigClosure, group.Tag, dependency)
			}
		}
		if group.Default != "" {
			if _, exists := outboundSeen[group.Default]; !exists {
				return NativeConfigArtifact{}, fmt.Errorf("%w: group %q default %q is unavailable", ErrNativeConfigClosure, group.Tag, group.Default)
			}
		}
		if err := addOutbound(group.Tag, group); err != nil {
			return NativeConfigArtifact{}, err
		}
	}

	for _, required := range input.Routing.OutboundTags {
		if _, exists := outboundSeen[required]; !exists {
			return NativeConfigArtifact{}, fmt.Errorf("%w: route requires unavailable outbound %q", ErrNativeConfigClosure, required)
		}
	}
	for _, server := range input.DNS.Servers {
		if server.Detour == "" {
			continue
		}
		if _, exists := outboundSeen[server.Detour]; !exists {
			return NativeConfigArtifact{}, fmt.Errorf("%w: DNS server %q detour %q is unavailable", ErrNativeConfigClosure, server.Tag, server.Detour)
		}
	}
	if err := validateRouteDNSResolverTags(input.Routing.Rules, dnsTagSet); err != nil {
		return NativeConfigArtifact{}, err
	}
	if err := validateGroupDNSRouteBindings(input.Routing, input.DNS); err != nil {
		return NativeConfigArtifact{}, err
	}
	if input.DNS.ProxyResolverTag != "" && !routeRulesUseResolver(input.Routing.Rules, input.DNS.ProxyResolverTag) {
		return NativeConfigArtifact{}, fmt.Errorf("%w: proxy resolver %q is not bound to route resolution", ErrNativeConfigClosure, input.DNS.ProxyResolverTag)
	}

	config := nativeConfig{
		Log: nativeLogConfig{
			Level:     input.LogLevel,
			Timestamp: true,
		},
		DNS:       nativeDNS,
		Inbounds:  inbounds,
		Outbounds: outbounds,
		Route: nativeRouteConfig{
			Rules:       cloneRouteRules(input.Routing.Rules),
			RuleSet:     ruleSets,
			FindProcess: input.Routing.NeedsProcessLookup,
		},
		Experimental: nativeExperimentalConfig{
			ClashAPI: nativeClashAPIConfig{
				ExternalController: input.ControlAddress.String(),
				Secret:             input.ControlSecret,
				DefaultMode:        "Rule",
			},
		},
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return NativeConfigArtifact{}, fmt.Errorf("marshal native config: %w", err)
	}
	sum := sha256.Sum256(payload)
	configSHA := hex.EncodeToString(sum[:])

	return NativeConfigArtifact{
		JSON:   payload,
		SHA256: configSHA,
		Manifest: NativeManifest{
			SchemaID:      NativeSchemaID,
			ConfigSHA256:  configSHA,
			InboundTags:   append([]string(nil), inboundTags...),
			OutboundTags:  append([]string(nil), outboundTags...),
			DNSServerTags: append([]string(nil), dnsTags...),
			RuleSets:      append([]NativeRuleSetManifest(nil), manifestRuleSets...),
		},
		SourceMap: append([]RouteSourceMapEntry(nil), input.Routing.SourceMap...),
	}, nil
}

func (a NativeConfigArtifact) MetadataJSON() (manifestJSON []byte, sourceMapJSON []byte, err error) {
	manifestJSON, err = json.Marshal(a.Manifest)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal native manifest: %w", err)
	}
	sourceMapJSON, err = json.Marshal(a.SourceMap)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal native source map: %w", err)
	}
	return manifestJSON, sourceMapJSON, nil
}

func compileNativeDNS(compiled CompiledDNS, targets TargetCatalog) (*nativeDNSConfig, []string, error) {
	if len(compiled.Servers) == 0 {
		if compiled.OutboundResolverTag != "" || len(compiled.ProfileBindings) != 0 {
			return nil, nil, fmt.Errorf("%w: empty DNS server closure carries metadata", ErrNativeConfigClosure)
		}
		return nil, nil, nil
	}

	servers := make([]any, 0, len(compiled.Servers)+1)
	tags := make([]string, 0, len(compiled.Servers)+1)
	seen := make(map[string]struct{}, len(compiled.Servers)+1)
	detourPolicy, err := compiledDNSDetourPolicy(compiled, targets)
	if err != nil {
		return nil, nil, err
	}
	for _, server := range compiled.Servers {
		if err := validateGeneratedTag(server.Tag); err != nil {
			return nil, nil, err
		}
		if _, exists := seen[server.Tag]; exists {
			return nil, nil, fmt.Errorf("%w: duplicate DNS server tag %q", ErrNativeConfigClosure, server.Tag)
		}
		expectedDetour, hasPolicy := detourPolicy[server.Tag]
		if hasPolicy {
			if server.Detour != expectedDetour {
				return nil, nil, fmt.Errorf("%w: DNS server %q detour %q does not match compiled policy %q", ErrNativeConfigClosure, server.Tag, server.Detour, expectedDetour)
			}
		} else if server.Detour != "" {
			return nil, nil, fmt.Errorf("%w: DNS server %q carries unexpected detour %q", ErrNativeConfigClosure, server.Tag, server.Detour)
		}
		if server.ServerPort == 0 {
			return nil, nil, fmt.Errorf("%w: DNS server %q has zero port", ErrNativeConfigClosure, server.Tag)
		}
		if _, err := netip.ParseAddr(server.Server); err != nil {
			if server.DomainResolver == "" {
				return nil, nil, fmt.Errorf("%w: DNS server %q host %q has no bootstrap resolver", ErrDNSRequired, server.Tag, server.Server)
			}
			if _, exists := seen[server.DomainResolver]; !exists {
				return nil, nil, fmt.Errorf("%w: DNS server %q bootstrap resolver %q is unavailable before use", ErrNativeConfigClosure, server.Tag, server.DomainResolver)
			}
		} else if server.DomainResolver != "" {
			return nil, nil, fmt.Errorf("%w: IP-literal DNS server %q unexpectedly carries resolver %q", ErrNativeConfigClosure, server.Tag, server.DomainResolver)
		}
		switch server.Type {
		case "udp", "tcp":
		default:
			return nil, nil, fmt.Errorf("%w: unsupported native DNS server type %q", ErrNativeConfigClosure, server.Type)
		}
		seen[server.Tag] = struct{}{}
		tags = append(tags, server.Tag)
		servers = append(servers, server)
	}
	if compiled.OutboundResolverTag == "" {
		return nil, nil, fmt.Errorf("%w: DNS closure has servers but no outbound resolver", ErrNativeConfigClosure)
	}
	if _, exists := seen[compiled.OutboundResolverTag]; !exists {
		return nil, nil, fmt.Errorf("%w: outbound DNS resolver %q is unavailable", ErrNativeConfigClosure, compiled.OutboundResolverTag)
	}
	for _, role := range []struct {
		name string
		tag  string
	}{
		{name: "direct", tag: compiled.DirectResolverTag},
		{name: "proxy", tag: compiled.ProxyResolverTag},
	} {
		if role.tag == "" {
			continue
		}
		if _, exists := seen[role.tag]; !exists {
			return nil, nil, fmt.Errorf("%w: %s DNS resolver %q is unavailable", ErrNativeConfigClosure, role.name, role.tag)
		}
	}
	for _, binding := range compiled.GroupBindings {
		if _, exists := seen[binding.RuntimeTag]; !exists {
			return nil, nil, fmt.Errorf("%w: group %q DNS resolver %q is unavailable", ErrNativeConfigClosure, binding.GroupID, binding.RuntimeTag)
		}
	}
	if _, exists := seen[nativeDNSFailClosedTag]; exists {
		return nil, nil, fmt.Errorf("%w: fail-closed DNS tag collides with compiled DNS", ErrNativeConfigClosure)
	}

	servers = append(servers, nativePredefinedDNSServer{
		Type:  "predefined",
		Tag:   nativeDNSFailClosedTag,
		Rcode: "REFUSED",
	})
	tags = append(tags, nativeDNSFailClosedTag)
	return &nativeDNSConfig{
		Servers: servers,
		Final:   nativeDNSFailClosedTag,
	}, tags, nil
}

func compileNativeInbounds(inbounds domain.InboundSet) ([]nativeInboundConfig, []string, error) {
	ordered, err := inbounds.Ordered()
	if err != nil {
		return nil, nil, err
	}
	configs := make([]nativeInboundConfig, 0, len(ordered))
	tags := make([]string, 0, len(ordered))
	for _, inbound := range ordered {
		tag, err := inbound.Role.RuntimeTag()
		if err != nil {
			return nil, nil, err
		}
		tags = append(tags, tag)
		configs = append(configs, nativeInboundConfig{
			Type:           "mixed",
			Tag:            tag,
			Listen:         inbound.Address.Addr().String(),
			ListenPort:     inbound.Address.Port(),
			SetSystemProxy: false,
		})
	}
	return configs, tags, nil
}

func validateControlPlane(address netip.AddrPort, secret string, inbounds domain.InboundSet) error {
	if !address.IsValid() || !address.Addr().IsLoopback() || address.Port() == 0 {
		return fmt.Errorf("%w: controller must use a non-zero loopback address", ErrInvalidControlPlane)
	}
	if address.Port() == inbounds.RulePort || address.Port() == inbounds.DirectPort || address.Port() == inbounds.SelectedPort {
		return fmt.Errorf("%w: controller port conflicts with a proxy inbound", ErrInvalidControlPlane)
	}
	if len(secret) != 64 {
		return fmt.Errorf("%w: secret must contain exactly 64 hexadecimal characters", ErrInvalidControlPlane)
	}
	if _, err := hex.DecodeString(secret); err != nil {
		return fmt.Errorf("%w: secret must be hexadecimal", ErrInvalidControlPlane)
	}
	return nil
}

func validateNativeLogLevel(level string) error {
	switch level {
	case "trace", "debug", "info", "warn", "error", "fatal", "panic":
		return nil
	default:
		return fmt.Errorf("unsupported core log level %q", level)
	}
}

func validateRouteDNSResolverTags(rules []RouteRule, available map[string]struct{}) error {
	for _, rule := range rules {
		if rule.Server != "" {
			if rule.Action != "resolve" {
				return fmt.Errorf("%w: route action %q unexpectedly carries DNS server %q", ErrNativeConfigClosure, rule.Action, rule.Server)
			}
			if _, exists := available[rule.Server]; !exists {
				return fmt.Errorf("%w: route resolve references unavailable DNS server %q", ErrNativeConfigClosure, rule.Server)
			}
		}
		if err := validateRouteDNSResolverTags(rule.Rules, available); err != nil {
			return err
		}
	}
	return nil
}

func routeRulesUseResolver(rules []RouteRule, resolver string) bool {
	for _, rule := range rules {
		if rule.Action == "resolve" && rule.Server == resolver {
			return true
		}
		if routeRulesUseResolver(rule.Rules, resolver) {
			return true
		}
	}
	return false
}

func validateRouteRuleSetTags(rules []RouteRule, available map[string]struct{}) error {
	for _, rule := range rules {
		for _, tag := range rule.RuleSet {
			if _, exists := available[tag]; !exists {
				return fmt.Errorf("%w: route references unavailable rule-set tag %q", ErrNativeConfigClosure, tag)
			}
		}
		if err := validateRouteRuleSetTags(rule.Rules, available); err != nil {
			return err
		}
	}
	return nil
}
