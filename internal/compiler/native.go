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

const NativeSchemaID = "karing-sing-box-1.13.19@beddeababcc71dfb0c78124598b13341c06c69fb"

var (
	ErrNativeConfigClosure = errors.New("native config dependency closure is incomplete")
	ErrDNSRequired         = errors.New("node server requires outbound DNS compilation")
	ErrInvalidControlPlane = errors.New("invalid core control plane")
)

type NativeConfigInput struct {
	Inbounds        domain.InboundSet
	ControlAddress  netip.AddrPort
	ControlSecret   string
	LogLevel        string
	Targets         TargetCatalog
	Routing         BoundRouting
	Selection       CompiledSelection
	Nodes           CompiledNodes
}

type NativeConfigArtifact struct {
	JSON     []byte
	SHA256   string
	Manifest NativeManifest
}

type NativeManifest struct {
	SchemaID      string
	ConfigSHA256  string
	InboundTags   []string
	OutboundTags  []string
	RuleSets      []NativeRuleSetManifest
}

type NativeRuleSetManifest struct {
	Ref        string
	RuntimeTag string
	RuntimePath string
	SHA256     string
	Format     RuleSetFormat
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
	Type string `json:"type"`
	Tag  string `json:"tag"`
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

	if err := addOutbound(input.Targets.DirectTag, nativeDirectOutbound{Type: "direct", Tag: input.Targets.DirectTag}); err != nil {
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
			return NativeConfigArtifact{}, fmt.Errorf("%w: node %q server %q", ErrDNSRequired, outbound.Tag, outbound.Server)
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

	config := nativeConfig{
		Log: nativeLogConfig{
			Level:     input.LogLevel,
			Timestamp: true,
		},
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
			SchemaID:     NativeSchemaID,
			ConfigSHA256: configSHA,
			InboundTags:  inboundTags,
			OutboundTags: outboundTags,
			RuleSets:     manifestRuleSets,
		},
	}, nil
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

