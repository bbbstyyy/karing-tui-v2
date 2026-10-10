package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

type RuleSetFormat string

const (
	RuleSetFormatSource RuleSetFormat = "source"
	RuleSetFormatBinary RuleSetFormat = "binary"
)

var (
	ErrDuplicateRuleSetRef = errors.New("duplicate rule-set reference")
	ErrInvalidRuleSet      = errors.New("invalid rule-set artifact")
	ErrUnresolvedRuleSet   = errors.New("unresolved rule-set reference")
	ErrRuleSetNotStaged    = errors.New("rule-set artifact is not staged")
)

type RuleSetSource struct {
	Ref    string
	Path   string
	SHA256 string
	Format RuleSetFormat
}

type RuleSetArtifact struct {
	Ref         string
	RuntimeTag  string
	SourcePath  string
	RuntimePath string
	SHA256      string
	Format      RuleSetFormat
}

type LocalRuleSetConfig struct {
	Type   string        `json:"type"`
	Tag    string        `json:"tag"`
	Format RuleSetFormat `json:"format"`
	Path   string        `json:"path"`
}

type RuleSetCatalog struct {
	byRef map[string]RuleSetArtifact
}

type BoundRouting struct {
	CompiledRouting
	RuleSets []RuleSetArtifact
}

func NewRuleSetCatalog(sources []RuleSetSource) (RuleSetCatalog, error) {
	catalog := RuleSetCatalog{byRef: make(map[string]RuleSetArtifact, len(sources))}
	for _, source := range sources {
		artifact, err := buildRuleSetArtifact(source)
		if err != nil {
			return RuleSetCatalog{}, err
		}
		if _, exists := catalog.byRef[source.Ref]; exists {
			return RuleSetCatalog{}, fmt.Errorf("%w: %q", ErrDuplicateRuleSetRef, source.Ref)
		}
		catalog.byRef[source.Ref] = artifact
	}
	return catalog, nil
}

func (c RuleSetCatalog) Resolve(ref string) (RuleSetArtifact, error) {
	artifact, exists := c.byRef[ref]
	if !exists {
		return RuleSetArtifact{}, fmt.Errorf("%w: %q", ErrUnresolvedRuleSet, ref)
	}
	return artifact, nil
}

func (c RuleSetCatalog) Closure(refs []string) ([]RuleSetArtifact, error) {
	seen := make(map[string]struct{}, len(refs))
	closure := make([]RuleSetArtifact, 0, len(refs))
	for _, ref := range refs {
		if _, exists := seen[ref]; exists {
			continue
		}
		artifact, err := c.Resolve(ref)
		if err != nil {
			return nil, err
		}
		seen[ref] = struct{}{}
		closure = append(closure, artifact)
	}
	return closure, nil
}

func BindRuleSetArtifacts(compiled CompiledRouting, catalog RuleSetCatalog) (BoundRouting, error) {
	closure, err := catalog.Closure(compiled.RuleSetRefs)
	if err != nil {
		return BoundRouting{}, err
	}
	tagByRef := make(map[string]string, len(closure))
	for _, artifact := range closure {
		tagByRef[artifact.Ref] = artifact.RuntimeTag
	}

	bound := compiled
	bound.Rules = cloneRouteRules(compiled.Rules)
	for i := range bound.Rules {
		if err := bindRuleSetTags(&bound.Rules[i], tagByRef); err != nil {
			return BoundRouting{}, err
		}
	}
	bound.RuleSetRefs = append([]string(nil), compiled.RuleSetRefs...)
	bound.OutboundTags = append([]string(nil), compiled.OutboundTags...)
	bound.SourceMap = append([]RouteSourceMapEntry(nil), compiled.SourceMap...)

	return BoundRouting{
		CompiledRouting: bound,
		RuleSets:        closure,
	}, nil
}

func BindStagedRuleSetPaths(bound BoundRouting, staged map[string]string) (BoundRouting, error) {
	rebound := bound
	rebound.Rules = cloneRouteRules(bound.Rules)
	rebound.RuleSetRefs = append([]string(nil), bound.RuleSetRefs...)
	rebound.OutboundTags = append([]string(nil), bound.OutboundTags...)
	rebound.SourceMap = append([]RouteSourceMapEntry(nil), bound.SourceMap...)
	rebound.RuleSets = append([]RuleSetArtifact(nil), bound.RuleSets...)

	for i := range rebound.RuleSets {
		artifact := &rebound.RuleSets[i]
		path, exists := staged[artifact.Ref]
		if !exists {
			return BoundRouting{}, fmt.Errorf("%w: %q", ErrRuleSetNotStaged, artifact.Ref)
		}
		if err := validateRuntimeRuleSetPath(*artifact, path); err != nil {
			return BoundRouting{}, err
		}
		artifact.RuntimePath = path
	}
	return rebound, nil
}

func (a RuleSetArtifact) LocalConfig() (LocalRuleSetConfig, error) {
	if a.RuntimePath == "" {
		return LocalRuleSetConfig{}, fmt.Errorf("%w: %q", ErrRuleSetNotStaged, a.Ref)
	}
	if err := validateRuntimeRuleSetPath(a, a.RuntimePath); err != nil {
		return LocalRuleSetConfig{}, err
	}
	return LocalRuleSetConfig{
		Type:   "local",
		Tag:    a.RuntimeTag,
		Format: a.Format,
		Path:   a.RuntimePath,
	}, nil
}

func buildRuleSetArtifact(source RuleSetSource) (RuleSetArtifact, error) {
	if err := validateRuleSetRef(source.Ref); err != nil {
		return RuleSetArtifact{}, fmt.Errorf("%w: ref %q: %v", ErrInvalidRuleSet, source.Ref, err)
	}
	if source.Path == "" || !filepath.IsAbs(source.Path) || filepath.Clean(source.Path) != source.Path {
		return RuleSetArtifact{}, fmt.Errorf("%w: rule-set path must be a clean absolute path", ErrInvalidRuleSet)
	}
	switch source.Format {
	case RuleSetFormatSource:
		if filepath.Ext(source.Path) != ".json" {
			return RuleSetArtifact{}, fmt.Errorf("%w: source rule-set path must end in .json", ErrInvalidRuleSet)
		}
	case RuleSetFormatBinary:
		if filepath.Ext(source.Path) != ".srs" {
			return RuleSetArtifact{}, fmt.Errorf("%w: binary rule-set path must end in .srs", ErrInvalidRuleSet)
		}
	default:
		return RuleSetArtifact{}, fmt.Errorf("%w: unsupported rule-set format %q", ErrInvalidRuleSet, source.Format)
	}
	sha, err := normalizeArtifactSHA256(source.SHA256)
	if err != nil {
		return RuleSetArtifact{}, fmt.Errorf("%w: %v", ErrInvalidRuleSet, err)
	}
	return RuleSetArtifact{
		Ref:        source.Ref,
		RuntimeTag: stableRuleSetTag(source.Ref),
		SourcePath: source.Path,
		SHA256:     sha,
		Format:     source.Format,
	}, nil
}

func validateRuntimeRuleSetPath(artifact RuleSetArtifact, path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: runtime path for %q must be a clean absolute path", ErrInvalidRuleSet, artifact.Ref)
	}
	var extension string
	switch artifact.Format {
	case RuleSetFormatSource:
		extension = ".json"
	case RuleSetFormatBinary:
		extension = ".srs"
	default:
		return fmt.Errorf("%w: unsupported rule-set format %q", ErrInvalidRuleSet, artifact.Format)
	}
	if filepath.Base(path) != artifact.SHA256+extension {
		return fmt.Errorf("%w: runtime path for %q is not content-addressed by its SHA-256", ErrInvalidRuleSet, artifact.Ref)
	}
	return nil
}

func stableRuleSetTag(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return "rs-" + hex.EncodeToString(sum[:])
}

func validateRuleSetRef(ref string) error {
	if ref == "" {
		return errors.New("reference must not be empty")
	}
	if len(ref) > 1024 {
		return errors.New("reference exceeds 1024 bytes")
	}
	if strings.TrimSpace(ref) != ref {
		return errors.New("reference must not have leading or trailing whitespace")
	}
	for _, r := range ref {
		if r < 0x20 || r == 0x7f {
			return errors.New("reference contains a control character")
		}
	}
	return nil
}

func normalizeArtifactSHA256(value string) (string, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("SHA-256 must be 64 hexadecimal characters")
	}
	return hex.EncodeToString(decoded), nil
}

func cloneRouteRules(rules []RouteRule) []RouteRule {
	if len(rules) == 0 {
		return nil
	}
	cloned := make([]RouteRule, len(rules))
	for i := range rules {
		cloned[i] = rules[i]
		cloned[i].Rules = cloneRouteRules(rules[i].Rules)
		cloned[i].Inbound = append([]string(nil), rules[i].Inbound...)
		cloned[i].Domain = append([]string(nil), rules[i].Domain...)
		cloned[i].DomainSuffix = append([]string(nil), rules[i].DomainSuffix...)
		cloned[i].DomainKeyword = append([]string(nil), rules[i].DomainKeyword...)
		cloned[i].DomainRegex = append([]string(nil), rules[i].DomainRegex...)
		cloned[i].IPCIDR = append([]string(nil), rules[i].IPCIDR...)
		cloned[i].RuleSet = append([]string(nil), rules[i].RuleSet...)
		cloned[i].Port = append([]uint16(nil), rules[i].Port...)
		cloned[i].PortRange = append([]string(nil), rules[i].PortRange...)
		cloned[i].Network = append([]string(nil), rules[i].Network...)
		cloned[i].ProcessName = append([]string(nil), rules[i].ProcessName...)
	}
	return cloned
}

func bindRuleSetTags(rule *RouteRule, tagByRef map[string]string) error {
	for i, ref := range rule.RuleSet {
		tag, exists := tagByRef[ref]
		if !exists {
			return fmt.Errorf("%w in compiled rule: %q", ErrUnresolvedRuleSet, ref)
		}
		rule.RuleSet[i] = tag
	}
	for i := range rule.Rules {
		if err := bindRuleSetTags(&rule.Rules[i], tagByRef); err != nil {
			return err
		}
	}
	return nil
}
