package declaration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

const SchemaVersionV1 = 1

var (
	ErrInvalidDocument            = errors.New("invalid declaration document")
	ErrUnsupportedSchema          = errors.New("unsupported declaration schema")
	ErrRuleSetResourceMissing     = errors.New("declaration rule-set resource metadata is missing")
	ErrRuleSetResourceUnavailable = errors.New("declaration rule-set resource is unavailable")
)

type RuleSetResource struct {
	Ref    string
	SHA256 string
	Format compiler.RuleSetFormat
}

type CNPresetPlan struct {
	SourceCommit string
	Overrides    []preset.CNOverride
	CustomOrder  []preset.CNCustomOrderEntry
}

type Model struct {
	LogLevel     string
	RuleSets     []RuleSetResource
	Nodes        []domain.Node
	Selection    domain.SelectionPlan
	Routing      domain.RoutingPlan
	CNPreset     *CNPresetPlan
	RegionAppend *domain.RegionAppendPlan
	DNS          domain.DNSPlan
}

type RuleSetResolver interface {
	ResolveRuleSet(context.Context, string, string) (string, error)
}

type NativeCompilerOptions struct {
	Inbounds       domain.InboundSet
	ControlAddress netip.AddrPort
	ControlSecret  string
	RuleSets       RuleSetResolver
}

type NativeCompiler struct {
	options NativeCompilerOptions
}

func NewNativeCompiler(options NativeCompilerOptions) (*NativeCompiler, error) {
	if err := options.Inbounds.Validate(); err != nil {
		return nil, fmt.Errorf("validate declaration compiler inbounds: %w", err)
	}
	if !options.ControlAddress.IsValid() || !options.ControlAddress.Addr().IsLoopback() || options.ControlAddress.Port() == 0 {
		return nil, errors.New("declaration compiler control address must be a non-zero loopback address")
	}
	if len(options.ControlSecret) != 64 {
		return nil, errors.New("declaration compiler control secret must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(options.ControlSecret); err != nil {
		return nil, errors.New("declaration compiler control secret must be hexadecimal")
	}
	return &NativeCompiler{options: options}, nil
}

func (c *NativeCompiler) CompileDeclaration(ctx context.Context, document []byte) (compiler.NativeConfigArtifact, error) {
	if c == nil {
		return compiler.NativeConfigArtifact{}, errors.New("declaration compiler is nil")
	}
	model, err := ParseV1(document)
	if err != nil {
		return compiler.NativeConfigArtifact{}, err
	}
	return c.compileModel(ctx, model)
}

func (c *NativeCompiler) CompileDeclarationWithCurrentSelection(
	ctx context.Context,
	document []byte,
	target domain.TargetRef,
) (compiler.NativeConfigArtifact, error) {
	if c == nil {
		return compiler.NativeConfigArtifact{}, errors.New("declaration compiler is nil")
	}
	model, err := ParseV1(document)
	if err != nil {
		return compiler.NativeConfigArtifact{}, err
	}
	if err := applyCurrentSelectionIntent(&model.Selection, target); err != nil {
		return compiler.NativeConfigArtifact{}, err
	}
	return c.compileModel(ctx, model)
}

func CurrentSelectionRuntimeTag(document []byte, target domain.TargetRef) (string, error) {
	model, err := ParseV1(document)
	if err != nil {
		return "", err
	}
	if err := applyCurrentSelectionIntent(&model.Selection, target); err != nil {
		return "", err
	}
	customIDs := make([]string, 0, len(model.Selection.Custom))
	for _, group := range model.Selection.Custom {
		customIDs = append(customIDs, group.GroupID)
	}
	nodeKeys := make([]compiler.NodeTargetKey, 0, len(model.Nodes))
	for _, node := range model.Nodes {
		nodeKeys = append(nodeKeys, compiler.NodeTargetKey{ProfileID: node.ProfileID, NodeID: node.NodeID})
	}
	targets, err := compiler.NewTargetCatalog(customIDs, nodeKeys)
	if err != nil {
		return "", fmt.Errorf("%w: target catalog: %v", ErrInvalidDocument, err)
	}
	tag, err := targets.ResolveTarget(target)
	if err != nil {
		return "", fmt.Errorf("%w: current selection target: %v", ErrInvalidDocument, err)
	}
	return tag, nil
}

func applyCurrentSelectionIntent(selection *domain.SelectionPlan, target domain.TargetRef) error {
	if selection == nil {
		return fmt.Errorf("%w: current selection plan is nil", ErrInvalidDocument)
	}
	if err := target.Validate(); err != nil {
		return fmt.Errorf("%w: current selection target: %v", ErrInvalidDocument, err)
	}
	found := false
	for _, member := range selection.Current.Members {
		if member == target {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("%w: current selection target %+v is not a member", ErrInvalidDocument, target)
	}
	selection.Current.Default = target
	if err := selection.Validate(); err != nil {
		return fmt.Errorf("%w: current selection override: %v", ErrInvalidDocument, err)
	}
	return nil
}

func (c *NativeCompiler) compileModel(ctx context.Context, model Model) (compiler.NativeConfigArtifact, error) {
	if err := ctx.Err(); err != nil {
		return compiler.NativeConfigArtifact{}, err
	}
	compiled, err := compileSemantic(ctx, model, c.options.RuleSets, true)
	if err != nil {
		return compiler.NativeConfigArtifact{}, err
	}
	if err := ctx.Err(); err != nil {
		return compiler.NativeConfigArtifact{}, err
	}
	return compiler.CompileNativeConfig(compiler.NativeConfigInput{
		Inbounds:       c.options.Inbounds,
		ControlAddress: c.options.ControlAddress,
		ControlSecret:  c.options.ControlSecret,
		LogLevel:       model.LogLevel,
		Targets:        compiled.targets,
		Routing:        compiled.routing,
		Selection:      compiled.selection,
		Nodes:          compiled.nodes,
		DNS:            compiled.dns,
	})
}

func ValidateV1(document []byte) error {
	model, err := ParseV1(document)
	if err != nil {
		return err
	}
	_, err = compileSemantic(context.Background(), model, nil, false)
	return err
}

func ValidateV1WithResolver(ctx context.Context, document []byte, resolver RuleSetResolver) error {
	model, err := ParseV1(document)
	if err != nil {
		return err
	}
	_, err = compileSemantic(ctx, model, resolver, true)
	return err
}

func ParseV1(document []byte) (Model, error) {
	if len(document) == 0 {
		return Model{}, fmt.Errorf("%w: document is empty", ErrInvalidDocument)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var wire documentV1
	if err := decoder.Decode(&wire); err != nil {
		return Model{}, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	if err := requireEOF(decoder); err != nil {
		return Model{}, err
	}
	if wire.SchemaVersion != SchemaVersionV1 {
		return Model{}, fmt.Errorf("%w: got %d, want %d", ErrUnsupportedSchema, wire.SchemaVersion, SchemaVersionV1)
	}
	if err := validateLogLevel(wire.LogLevel); err != nil {
		return Model{}, err
	}
	ruleSets, err := parseRuleSetResources(wire.RuleSets)
	if err != nil {
		return Model{}, err
	}

	nodes := make([]domain.Node, 0, len(wire.Nodes))
	seenNodes := make(map[compiler.NodeTargetKey]struct{}, len(wire.Nodes))
	for i, item := range wire.Nodes {
		node, err := item.toDomain()
		if err != nil {
			return Model{}, fmt.Errorf("%w: node %d: %v", ErrInvalidDocument, i, err)
		}
		if err := node.Validate(); err != nil {
			return Model{}, fmt.Errorf("%w: node %d: %v", ErrInvalidDocument, i, err)
		}
		key := compiler.NodeTargetKey{ProfileID: node.ProfileID, NodeID: node.NodeID}
		if _, exists := seenNodes[key]; exists {
			return Model{}, fmt.Errorf("%w: duplicate node %q/%q", ErrInvalidDocument, node.ProfileID, node.NodeID)
		}
		seenNodes[key] = struct{}{}
		nodes = append(nodes, node)
	}

	selection, err := wire.Selection.toDomain()
	if err != nil {
		return Model{}, err
	}
	if err := selection.Validate(); err != nil {
		return Model{}, fmt.Errorf("%w: selection: %v", ErrInvalidDocument, err)
	}
	routing, err := wire.Routing.toDomain()
	if err != nil {
		return Model{}, err
	}
	if err := routing.Validate(); err != nil {
		return Model{}, fmt.Errorf("%w: routing: %v", ErrInvalidDocument, err)
	}
	cnPreset, err := wire.Routing.cnPresetPlan()
	if err != nil {
		return Model{}, err
	}
	regionAppend, err := wire.Routing.regionAppendPlan()
	if err != nil {
		return Model{}, err
	}
	effectiveRouting, err := applyDeclarationRoutingPolicies(routing, cnPreset, regionAppend)
	if err != nil {
		return Model{}, err
	}
	dns, err := wire.DNS.toDomain()
	if err != nil {
		return Model{}, err
	}
	if err := dns.ValidateActiveRouteBindings(effectiveRouting); err != nil {
		return Model{}, fmt.Errorf("%w: DNS: %v", ErrInvalidDocument, err)
	}

	return Model{
		LogLevel:     wire.LogLevel,
		RuleSets:     ruleSets,
		Nodes:        nodes,
		Selection:    selection,
		Routing:      routing,
		CNPreset:     cnPreset,
		RegionAppend: regionAppend,
		DNS:          dns,
	}, nil
}

func applyDeclarationRoutingPolicies(
	routing domain.RoutingPlan,
	cnPreset *CNPresetPlan,
	regionAppend *domain.RegionAppendPlan,
) (domain.RoutingPlan, error) {
	result := routing
	if cnPreset != nil {
		if cnPreset.SourceCommit != preset.CNSourceCommit {
			return domain.RoutingPlan{}, fmt.Errorf(
				"%w: routing.cn_preset source commit %q is unsupported",
				ErrInvalidDocument,
				cnPreset.SourceCommit,
			)
		}
		snapshot, err := preset.LoadCN()
		if err != nil {
			return domain.RoutingPlan{}, fmt.Errorf("%w: load CN preset snapshot: %v", ErrInvalidDocument, err)
		}
		cnGroups, err := preset.LowerCNCustomRouting(snapshot, cnPreset.Overrides)
		if err != nil {
			return domain.RoutingPlan{}, fmt.Errorf("%w: routing.cn_preset: %v", ErrInvalidDocument, err)
		}
		result.Custom, err = preset.MergeCNCustomRouting(result.Custom, cnGroups, cnPreset.CustomOrder)
		if err != nil {
			return domain.RoutingPlan{}, fmt.Errorf("%w: routing.custom_order: %v", ErrInvalidDocument, err)
		}
	}
	if regionAppend != nil {
		var err error
		result, err = domain.ApplyRegionAppend(result, *regionAppend)
		if err != nil {
			return domain.RoutingPlan{}, fmt.Errorf("%w: routing.region_append: %v", ErrInvalidDocument, err)
		}
	}
	if err := result.Validate(); err != nil {
		return domain.RoutingPlan{}, fmt.Errorf("%w: effective routing: %v", ErrInvalidDocument, err)
	}
	return result, nil
}

type semanticCompilation struct {
	targets   compiler.TargetCatalog
	routing   compiler.BoundRouting
	selection compiler.CompiledSelection
	nodes     compiler.CompiledNodes
	dns       compiler.CompiledDNS
}

func compileSemantic(
	ctx context.Context,
	model Model,
	resolver RuleSetResolver,
	requireResources bool,
) (semanticCompilation, error) {
	if err := ctx.Err(); err != nil {
		return semanticCompilation{}, err
	}
	customIDs := make([]string, 0, len(model.Selection.Custom))
	for _, group := range model.Selection.Custom {
		customIDs = append(customIDs, group.GroupID)
	}
	nodeKeys := make([]compiler.NodeTargetKey, 0, len(model.Nodes))
	for _, node := range model.Nodes {
		nodeKeys = append(nodeKeys, compiler.NodeTargetKey{ProfileID: node.ProfileID, NodeID: node.NodeID})
	}
	targets, err := compiler.NewTargetCatalog(customIDs, nodeKeys)
	if err != nil {
		return semanticCompilation{}, fmt.Errorf("%w: target catalog: %v", ErrInvalidDocument, err)
	}
	routingPlan, err := applyDeclarationRoutingPolicies(model.Routing, model.CNPreset, model.RegionAppend)
	if err != nil {
		return semanticCompilation{}, err
	}
	routing, err := compiler.CompileRouting(routingPlan, targets)
	if err != nil {
		return semanticCompilation{}, fmt.Errorf("%w: routing compile: %v", ErrInvalidDocument, err)
	}
	bound, err := bindRuleSetResources(ctx, routing, model.RuleSets, resolver, requireResources)
	if err != nil {
		return semanticCompilation{}, err
	}

	dns, err := compiler.CompileRuntimeDNSForRouting(model.DNS, routingPlan, targets)
	if err != nil {
		return semanticCompilation{}, fmt.Errorf("%w: DNS compile: %v", ErrInvalidDocument, err)
	}
	required := compiler.RuntimeOutboundRequirements(routing, dns)
	selection, err := compiler.CompileSelectionGroups(model.Selection, targets, required)
	if err != nil {
		return semanticCompilation{}, fmt.Errorf("%w: selection compile: %v", ErrInvalidDocument, err)
	}
	nodes, err := compiler.CompileBasicNodeOutbounds(model.Nodes, targets, selection.NodeTargets)
	if err != nil {
		return semanticCompilation{}, fmt.Errorf("%w: node compile: %v", ErrInvalidDocument, err)
	}
	nodes, err = compiler.BindNodeDomainResolver(nodes, dns)
	if err != nil {
		return semanticCompilation{}, fmt.Errorf("%w: node DNS binding: %v", ErrInvalidDocument, err)
	}
	bound, err = compiler.BindGroupDNSRouting(bound, dns)
	if err != nil {
		return semanticCompilation{}, fmt.Errorf("%w: group DNS routing: %v", ErrInvalidDocument, err)
	}
	bound, err = compiler.BindProxyTargetDNSRouting(bound, dns)
	if err != nil {
		return semanticCompilation{}, fmt.Errorf("%w: proxy DNS routing: %v", ErrInvalidDocument, err)
	}
	return semanticCompilation{
		targets:   targets,
		routing:   bound,
		selection: selection,
		nodes:     nodes,
		dns:       dns,
	}, nil
}

func bindRuleSetResources(
	ctx context.Context,
	routing compiler.CompiledRouting,
	resources []RuleSetResource,
	resolver RuleSetResolver,
	requireResources bool,
) (compiler.BoundRouting, error) {
	declared := make(map[string]RuleSetResource, len(resources))
	for _, resource := range resources {
		declared[resource.Ref] = resource
	}

	sources := make([]compiler.RuleSetSource, 0, len(routing.RuleSetRefs))
	staged := make(map[string]string, len(routing.RuleSetRefs))
	for _, ref := range routing.RuleSetRefs {
		resource, exists := declared[ref]
		if !exists {
			return compiler.BoundRouting{}, fmt.Errorf("%w: %q", ErrRuleSetResourceMissing, ref)
		}
		var path string
		if requireResources {
			if resolver == nil {
				return compiler.BoundRouting{}, fmt.Errorf("%w: resolver is not configured for %q", ErrRuleSetResourceUnavailable, ref)
			}
			resolved, err := resolver.ResolveRuleSet(ctx, resource.SHA256, string(resource.Format))
			if err != nil {
				return compiler.BoundRouting{}, fmt.Errorf("%w: %q: %w", ErrRuleSetResourceUnavailable, ref, err)
			}
			path = resolved
		} else {
			extension, err := declarationRuleSetExtension(resource.Format)
			if err != nil {
				return compiler.BoundRouting{}, err
			}
			path = filepath.Join("/declaration/rule-sets/sha256", resource.SHA256+extension)
		}
		sources = append(sources, compiler.RuleSetSource{
			Ref:    ref,
			Path:   path,
			SHA256: resource.SHA256,
			Format: resource.Format,
		})
		staged[ref] = path
	}

	catalog, err := compiler.NewRuleSetCatalog(sources)
	if err != nil {
		return compiler.BoundRouting{}, fmt.Errorf("%w: rule-set catalog: %v", ErrInvalidDocument, err)
	}
	bound, err := compiler.BindRuleSetArtifacts(routing, catalog)
	if err != nil {
		return compiler.BoundRouting{}, fmt.Errorf("%w: rule-set binding: %v", ErrInvalidDocument, err)
	}
	bound, err = compiler.BindStagedRuleSetPaths(bound, staged)
	if err != nil {
		return compiler.BoundRouting{}, fmt.Errorf("%w: staged rule-set binding: %v", ErrInvalidDocument, err)
	}
	return bound, nil
}

func declarationRuleSetExtension(format compiler.RuleSetFormat) (string, error) {
	switch format {
	case compiler.RuleSetFormatSource:
		return ".json", nil
	case compiler.RuleSetFormatBinary:
		return ".srs", nil
	default:
		return "", fmt.Errorf("%w: unsupported rule-set format %q", ErrInvalidDocument, format)
	}
}
