package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var (
	ErrRouteExplainUnavailable = errors.New("route explanation is unavailable")
	ErrRouteExplainInput       = errors.New("invalid route explanation input")
	ErrRouteExplainIntegrity   = errors.New("route explanation generation integrity check failed")
)

type routeExplainStore interface {
	Snapshot(context.Context) (storage.Snapshot, error)
	GenerationArtifacts(context.Context, int64) (storage.GenerationArtifacts, error)
}

type RouteExplainCoordinator struct {
	store routeExplainStore
}

type routeExplainInput struct {
	entry       domain.InboundRole
	inboundTag  string
	domain      string
	ip          netip.Addr
	hasIP       bool
	port        uint16
	network     domain.NetworkType
	processName string
}

type routeEvalState uint8

const (
	routeEvalFalse routeEvalState = iota
	routeEvalTrue
	routeEvalUnknown
)

type routeEvalResult struct {
	state   routeEvalState
	unknown []string
}

func NewRouteExplainCoordinator(store routeExplainStore) (*RouteExplainCoordinator, error) {
	if store == nil {
		return nil, errors.New("route explanation store is nil")
	}
	return &RouteExplainCoordinator{store: store}, nil
}

func (c *RouteExplainCoordinator) Explain(
	ctx context.Context,
	request apiv1.RouteExplainRequest,
) (apiv1.RouteExplainResponse, error) {
	input, err := parseRouteExplainInput(request)
	if err != nil {
		return apiv1.RouteExplainResponse{}, err
	}
	snapshot, err := c.store.Snapshot(ctx)
	if err != nil {
		return apiv1.RouteExplainResponse{}, fmt.Errorf("read applied generation for route explanation: %w", err)
	}
	if snapshot.AppliedGenerationID == nil {
		return apiv1.RouteExplainResponse{}, ErrRouteExplainUnavailable
	}
	generationID := *snapshot.AppliedGenerationID
	artifacts, err := c.store.GenerationArtifacts(ctx, generationID)
	if err != nil {
		return apiv1.RouteExplainResponse{}, fmt.Errorf("load applied generation %d: %w", generationID, err)
	}
	manifest, rules, sourceMap, err := decodeRouteExplainGeneration(generationID, artifacts)
	if err != nil {
		return apiv1.RouteExplainResponse{}, err
	}

	sourceByRule := make(map[int]compiler.RouteSourceMapEntry, len(sourceMap))
	for _, entry := range sourceMap {
		sourceByRule[entry.RuleIndex] = entry
	}

	response := apiv1.RouteExplainResponse{
		APIVersion:          apiv1.Version,
		Evidence:            "simulated",
		Decision:            "unknown",
		ConfigRevision:      snapshot.Revision,
		GenerationID:        generationID,
		DeclarationRevision: manifest.DeclarationRevision,
		Entry:               string(input.entry),
		Input:               request,
		Trace:               make([]apiv1.RouteExplainStep, 0, len(rules)),
	}

	for index, rule := range rules {
		evaluation := evaluateRouteRule(rule, input)
		step := routeExplainStep(index, rule, sourceByRule, evaluation)
		response.Trace = append(response.Trace, step)

		switch evaluation.state {
		case routeEvalFalse:
			continue
		case routeEvalUnknown:
			response.Evidence = "unknown"
			response.Decision = "unknown"
			response.RuleIndex = intPtr(index)
			response.UnknownConditions = append([]string(nil), evaluation.unknown...)
			copyRouteExplainSource(&response, step)
			return response, nil
		case routeEvalTrue:
			switch rule.Action {
			case "resolve":
				continue
			case "route", "reject":
				response.Evidence = "simulated"
				response.Decision = rule.Action
				response.RuleIndex = intPtr(index)
				copyRouteExplainSource(&response, step)
				return response, nil
			default:
				response.Evidence = "unknown"
				response.Decision = "unknown"
				response.RuleIndex = intPtr(index)
				response.UnknownConditions = []string{"unsupported_action:" + rule.Action}
				copyRouteExplainSource(&response, step)
				return response, nil
			}
		}
	}

	return apiv1.RouteExplainResponse{}, fmt.Errorf(
		"%w: generation %d has no terminal route for %s entry",
		ErrRouteExplainIntegrity,
		generationID,
		input.entry,
	)
}

func decodeRouteExplainGeneration(
	generationID int64,
	artifacts storage.GenerationArtifacts,
) (compiler.NativeManifest, []compiler.RouteRule, []compiler.RouteSourceMapEntry, error) {
	if len(artifacts.ConfigJSON) == 0 || len(artifacts.ManifestJSON) == 0 || len(artifacts.SourceMapJSON) == 0 {
		return compiler.NativeManifest{}, nil, nil, fmt.Errorf(
			"%w: generation %d metadata is incomplete",
			ErrRouteExplainIntegrity,
			generationID,
		)
	}
	if err := verifyRouteExplainHash("config", artifacts.ConfigJSON, artifacts.ConfigSHA256); err != nil {
		return compiler.NativeManifest{}, nil, nil, fmt.Errorf("%w: generation %d: %v", ErrRouteExplainIntegrity, generationID, err)
	}
	if err := verifyRouteExplainHash("manifest", artifacts.ManifestJSON, artifacts.ManifestSHA256); err != nil {
		return compiler.NativeManifest{}, nil, nil, fmt.Errorf("%w: generation %d: %v", ErrRouteExplainIntegrity, generationID, err)
	}
	if err := verifyRouteExplainHash("source map", artifacts.SourceMapJSON, artifacts.SourceMapSHA256); err != nil {
		return compiler.NativeManifest{}, nil, nil, fmt.Errorf("%w: generation %d: %v", ErrRouteExplainIntegrity, generationID, err)
	}

	var manifest compiler.NativeManifest
	if err := json.Unmarshal(artifacts.ManifestJSON, &manifest); err != nil {
		return compiler.NativeManifest{}, nil, nil, fmt.Errorf("%w: decode generation %d manifest: %v", ErrRouteExplainIntegrity, generationID, err)
	}
	if manifest.SchemaID != compiler.NativeSchemaID || manifest.ConfigSHA256 != artifacts.ConfigSHA256 {
		return compiler.NativeManifest{}, nil, nil, fmt.Errorf(
			"%w: generation %d manifest/config identity mismatch",
			ErrRouteExplainIntegrity,
			generationID,
		)
	}
	if err := manifest.ValidateDeclarationBinding(true); err != nil {
		return compiler.NativeManifest{}, nil, nil, fmt.Errorf(
			"%w: generation %d declaration provenance: %v",
			ErrRouteExplainIntegrity,
			generationID,
			err,
		)
	}

	var native struct {
		Route struct {
			Rules []compiler.RouteRule `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(artifacts.ConfigJSON, &native); err != nil {
		return compiler.NativeManifest{}, nil, nil, fmt.Errorf("%w: decode generation %d config: %v", ErrRouteExplainIntegrity, generationID, err)
	}
	if len(native.Route.Rules) == 0 {
		return compiler.NativeManifest{}, nil, nil, fmt.Errorf("%w: generation %d has no route rules", ErrRouteExplainIntegrity, generationID)
	}

	var sourceMap []compiler.RouteSourceMapEntry
	if err := json.Unmarshal(artifacts.SourceMapJSON, &sourceMap); err != nil {
		return compiler.NativeManifest{}, nil, nil, fmt.Errorf("%w: decode generation %d source map: %v", ErrRouteExplainIntegrity, generationID, err)
	}
	seen := make(map[int]struct{}, len(sourceMap))
	for _, entry := range sourceMap {
		if entry.RuleIndex < 0 || entry.RuleIndex >= len(native.Route.Rules) {
			return compiler.NativeManifest{}, nil, nil, fmt.Errorf(
				"%w: generation %d source-map rule index %d is out of range",
				ErrRouteExplainIntegrity,
				generationID,
				entry.RuleIndex,
			)
		}
		if _, exists := seen[entry.RuleIndex]; exists {
			return compiler.NativeManifest{}, nil, nil, fmt.Errorf(
				"%w: generation %d source-map rule index %d is duplicated",
				ErrRouteExplainIntegrity,
				generationID,
				entry.RuleIndex,
			)
		}
		seen[entry.RuleIndex] = struct{}{}
		if err := entry.Target.Validate(); err != nil {
			return compiler.NativeManifest{}, nil, nil, fmt.Errorf(
				"%w: generation %d source-map rule index %d target: %v",
				ErrRouteExplainIntegrity,
				generationID,
				entry.RuleIndex,
				err,
			)
		}
		rule := native.Route.Rules[entry.RuleIndex]
		if rule.Action != entry.Action || rule.Outbound != entry.Outbound || rule.Server != entry.Server {
			return compiler.NativeManifest{}, nil, nil, fmt.Errorf(
				"%w: generation %d source-map rule index %d does not match native action",
				ErrRouteExplainIntegrity,
				generationID,
				entry.RuleIndex,
			)
		}
	}
	return manifest, native.Route.Rules, sourceMap, nil
}

func parseRouteExplainInput(request apiv1.RouteExplainRequest) (routeExplainInput, error) {
	entry := domain.InboundRole(request.Entry)
	if entry == "" {
		entry = domain.InboundRule
	}
	inboundTag, err := entry.RuntimeTag()
	if err != nil {
		return routeExplainInput{}, fmt.Errorf("%w: entry: %v", ErrRouteExplainInput, err)
	}

	domainName := request.Domain
	if domainName != "" {
		if strings.TrimSpace(domainName) != domainName {
			return routeExplainInput{}, fmt.Errorf("%w: domain has leading or trailing whitespace", ErrRouteExplainInput)
		}
		for _, r := range domainName {
			if r < 0x20 || r == 0x7f {
				return routeExplainInput{}, fmt.Errorf("%w: domain contains a control character", ErrRouteExplainInput)
			}
		}
		domainName = strings.ToLower(strings.TrimSuffix(domainName, "."))
		if domainName == "" {
			return routeExplainInput{}, fmt.Errorf("%w: domain is empty after normalization", ErrRouteExplainInput)
		}
	}

	var (
		ip    netip.Addr
		hasIP bool
	)
	if request.IP != "" {
		ip, err = netip.ParseAddr(request.IP)
		if err != nil {
			return routeExplainInput{}, fmt.Errorf("%w: invalid IP %q", ErrRouteExplainInput, request.IP)
		}
		ip = ip.Unmap()
		hasIP = true
	}

	network := domain.NetworkType(request.Network)
	if network != "" && network != domain.NetworkTCP && network != domain.NetworkUDP {
		return routeExplainInput{}, fmt.Errorf("%w: unsupported network %q", ErrRouteExplainInput, request.Network)
	}
	if request.ProcessName != "" {
		if strings.TrimSpace(request.ProcessName) != request.ProcessName {
			return routeExplainInput{}, fmt.Errorf("%w: process_name has leading or trailing whitespace", ErrRouteExplainInput)
		}
		for _, r := range request.ProcessName {
			if r < 0x20 || r == 0x7f {
				return routeExplainInput{}, fmt.Errorf("%w: process_name contains a control character", ErrRouteExplainInput)
			}
		}
	}

	return routeExplainInput{
		entry:       entry,
		inboundTag:  inboundTag,
		domain:      domainName,
		ip:          ip,
		hasIP:       hasIP,
		port:        request.Port,
		network:     network,
		processName: request.ProcessName,
	}, nil
}

func evaluateRouteRule(rule compiler.RouteRule, input routeExplainInput) routeEvalResult {
	var result routeEvalResult
	switch rule.Type {
	case "":
		result = evaluateRouteRuleFields(rule, input)
	case "logical":
		result = evaluateLogicalRouteRule(rule, input)
	default:
		result = routeUnknown("unsupported_rule_type:" + rule.Type)
	}
	if rule.Invert {
		result = invertRouteEval(result)
	}
	return result
}

func evaluateLogicalRouteRule(rule compiler.RouteRule, input routeExplainInput) routeEvalResult {
	if len(rule.Rules) == 0 {
		return routeUnknown("logical_rule_without_children")
	}
	children := make([]routeEvalResult, 0, len(rule.Rules))
	for _, child := range rule.Rules {
		children = append(children, evaluateRouteRule(child, input))
	}
	switch rule.Mode {
	case "and":
		return routeAnd(children...)
	case "or":
		return routeOr(children...)
	default:
		return routeUnknown("unsupported_logical_mode:" + rule.Mode)
	}
}

func evaluateRouteRuleFields(rule compiler.RouteRule, input routeExplainInput) routeEvalResult {
	parts := make([]routeEvalResult, 0, 10)
	if len(rule.Inbound) != 0 {
		parts = append(parts, routeBool(stringSliceContains(rule.Inbound, input.inboundTag)))
	}
	if len(rule.Domain) != 0 {
		if input.domain == "" {
			parts = append(parts, routeUnknown("domain"))
		} else {
			matched := false
			for _, candidate := range rule.Domain {
				if input.domain == strings.ToLower(strings.TrimSuffix(candidate, ".")) {
					matched = true
					break
				}
			}
			parts = append(parts, routeBool(matched))
		}
	}
	if len(rule.DomainSuffix) != 0 {
		if input.domain == "" {
			parts = append(parts, routeUnknown("domain"))
		} else {
			matched := false
			for _, candidate := range rule.DomainSuffix {
				suffix := strings.ToLower(strings.TrimSuffix(candidate, "."))
				if input.domain == suffix || strings.HasSuffix(input.domain, "."+strings.TrimPrefix(suffix, ".")) ||
					strings.HasSuffix(input.domain, suffix) {
					matched = true
					break
				}
			}
			parts = append(parts, routeBool(matched))
		}
	}
	if len(rule.DomainKeyword) != 0 {
		if input.domain == "" {
			parts = append(parts, routeUnknown("domain"))
		} else {
			matched := false
			for _, keyword := range rule.DomainKeyword {
				if strings.Contains(input.domain, strings.ToLower(keyword)) {
					matched = true
					break
				}
			}
			parts = append(parts, routeBool(matched))
		}
	}
	if len(rule.DomainRegex) != 0 {
		if input.domain == "" {
			parts = append(parts, routeUnknown("domain"))
		} else {
			matched := false
			for _, pattern := range rule.DomainRegex {
				re, err := regexp.Compile(pattern)
				if err != nil {
					parts = append(parts, routeUnknown("invalid_domain_regex:"+pattern))
					continue
				}
				if re.MatchString(input.domain) {
					matched = true
					break
				}
			}
			parts = append(parts, routeBool(matched))
		}
	}
	if len(rule.IPCIDR) != 0 {
		if !input.hasIP {
			parts = append(parts, routeUnknown("ip"))
		} else {
			matched := false
			for _, cidr := range rule.IPCIDR {
				prefix, err := netip.ParsePrefix(cidr)
				if err != nil {
					parts = append(parts, routeUnknown("invalid_ip_cidr:"+cidr))
					continue
				}
				if prefix.Contains(input.ip) {
					matched = true
					break
				}
			}
			parts = append(parts, routeBool(matched))
		}
	}
	if len(rule.RuleSet) != 0 {
		unknown := make([]string, 0, len(rule.RuleSet))
		for _, tag := range rule.RuleSet {
			unknown = append(unknown, "rule_set:"+tag)
		}
		parts = append(parts, routeEvalResult{state: routeEvalUnknown, unknown: unknown})
	}
	if len(rule.Port) != 0 {
		if input.port == 0 {
			parts = append(parts, routeUnknown("port"))
		} else {
			matched := false
			for _, port := range rule.Port {
				if input.port == port {
					matched = true
					break
				}
			}
			parts = append(parts, routeBool(matched))
		}
	}
	if len(rule.PortRange) != 0 {
		if input.port == 0 {
			parts = append(parts, routeUnknown("port"))
		} else {
			matched := false
			for _, encoded := range rule.PortRange {
				start, end, ok := parseRoutePortRange(encoded)
				if !ok {
					parts = append(parts, routeUnknown("invalid_port_range:"+encoded))
					continue
				}
				if input.port >= start && input.port <= end {
					matched = true
					break
				}
			}
			parts = append(parts, routeBool(matched))
		}
	}
	if len(rule.Network) != 0 {
		if input.network == "" {
			parts = append(parts, routeUnknown("network"))
		} else {
			parts = append(parts, routeBool(stringSliceContains(rule.Network, string(input.network))))
		}
	}
	if len(rule.ProcessName) != 0 {
		if input.processName == "" {
			parts = append(parts, routeUnknown("process_name"))
		} else {
			parts = append(parts, routeBool(stringSliceContains(rule.ProcessName, input.processName)))
		}
	}
	if len(parts) == 0 {
		return routeEvalResult{state: routeEvalTrue}
	}
	return routeAnd(parts...)
}

func routeExplainStep(
	index int,
	rule compiler.RouteRule,
	sourceByRule map[int]compiler.RouteSourceMapEntry,
	evaluation routeEvalResult,
) apiv1.RouteExplainStep {
	step := apiv1.RouteExplainStep{
		RuleIndex:         index,
		Result:            routeEvalString(evaluation.state),
		Source:            "synthetic",
		Action:            rule.Action,
		Outbound:          rule.Outbound,
		Server:            rule.Server,
		UnknownConditions: append([]string(nil), evaluation.unknown...),
	}
	if source, exists := sourceByRule[index]; exists {
		target := source.Target
		step.Source = "source_map"
		step.Layer = source.Layer
		step.GroupID = source.GroupID
		step.Final = source.Final
		step.Target = &target
		step.DNSProfileID = source.DNSProfileID
		return step
	}
	if rule.Outbound == compiler.DirectOutboundTag {
		target := domain.TargetRef{Kind: domain.TargetDirect}
		step.Target = &target
	}
	if rule.Outbound == compiler.CurrentSelectedOutboundTag {
		target := domain.TargetRef{Kind: domain.TargetCurrentSelected}
		step.Target = &target
	}
	return step
}

func copyRouteExplainSource(response *apiv1.RouteExplainResponse, step apiv1.RouteExplainStep) {
	response.Source = step.Source
	response.Layer = step.Layer
	response.GroupID = step.GroupID
	response.Final = step.Final
	response.Target = step.Target
	response.Action = step.Action
	response.Outbound = step.Outbound
	response.Server = step.Server
	response.DNSProfileID = step.DNSProfileID
}

func routeAnd(values ...routeEvalResult) routeEvalResult {
	unknown := make([]string, 0)
	for _, value := range values {
		if value.state == routeEvalFalse {
			return routeEvalResult{state: routeEvalFalse}
		}
		if value.state == routeEvalUnknown {
			unknown = appendUniqueStrings(unknown, value.unknown...)
		}
	}
	if len(unknown) != 0 {
		return routeEvalResult{state: routeEvalUnknown, unknown: unknown}
	}
	return routeEvalResult{state: routeEvalTrue}
}

func routeOr(values ...routeEvalResult) routeEvalResult {
	unknown := make([]string, 0)
	for _, value := range values {
		if value.state == routeEvalTrue {
			return routeEvalResult{state: routeEvalTrue}
		}
		if value.state == routeEvalUnknown {
			unknown = appendUniqueStrings(unknown, value.unknown...)
		}
	}
	if len(unknown) != 0 {
		return routeEvalResult{state: routeEvalUnknown, unknown: unknown}
	}
	return routeEvalResult{state: routeEvalFalse}
}

func invertRouteEval(value routeEvalResult) routeEvalResult {
	switch value.state {
	case routeEvalTrue:
		return routeEvalResult{state: routeEvalFalse}
	case routeEvalFalse:
		return routeEvalResult{state: routeEvalTrue}
	default:
		return value
	}
}

func routeBool(value bool) routeEvalResult {
	if value {
		return routeEvalResult{state: routeEvalTrue}
	}
	return routeEvalResult{state: routeEvalFalse}
}

func routeUnknown(condition string) routeEvalResult {
	return routeEvalResult{state: routeEvalUnknown, unknown: []string{condition}}
}

func routeEvalString(value routeEvalState) string {
	switch value {
	case routeEvalFalse:
		return "false"
	case routeEvalTrue:
		return "true"
	default:
		return "unknown"
	}
}

func parseRoutePortRange(value string) (uint16, uint16, bool) {
	left, right, ok := strings.Cut(value, ":")
	if !ok {
		return 0, 0, false
	}
	start, err := strconv.ParseUint(left, 10, 16)
	if err != nil || start == 0 {
		return 0, 0, false
	}
	end, err := strconv.ParseUint(right, 10, 16)
	if err != nil || end == 0 || start > end {
		return 0, 0, false
	}
	return uint16(start), uint16(end), true
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func appendUniqueStrings(target []string, values ...string) []string {
	seen := make(map[string]struct{}, len(target)+len(values))
	for _, value := range target {
		seen[value] = struct{}{}
	}
	for _, value := range values {
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		target = append(target, value)
	}
	return target
}

func verifyRouteExplainHash(name string, content []byte, expected string) error {
	if expected == "" {
		return fmt.Errorf("%s SHA-256 is missing", name)
	}
	sum := sha256.Sum256(content)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("%s SHA-256 mismatch: got %s want %s", name, actual, expected)
	}
	return nil
}

func intPtr(value int) *int {
	return &value
}
