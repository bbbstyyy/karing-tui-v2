package declaration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const SchemaVersionV1 = 1

var (
	ErrInvalidDocument         = errors.New("invalid declaration document")
	ErrUnsupportedSchema       = errors.New("unsupported declaration schema")
	ErrRuleSetsUnsupportedInV1 = errors.New("declaration schema v1 does not support rule-set resources yet")
)

type Model struct {
	LogLevel  string
	Nodes     []domain.Node
	Selection domain.SelectionPlan
	Routing   domain.RoutingPlan
	DNS       domain.DNSPlan
}

type NativeCompilerOptions struct {
	Inbounds       domain.InboundSet
	ControlAddress netip.AddrPort
	ControlSecret  string
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
	if err := ctx.Err(); err != nil {
		return compiler.NativeConfigArtifact{}, err
	}
	model, err := ParseV1(document)
	if err != nil {
		return compiler.NativeConfigArtifact{}, err
	}
	compiled, err := compileSemantic(model)
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
	_, err = compileSemantic(model)
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
	dns, err := wire.DNS.toDomain()
	if err != nil {
		return Model{}, err
	}
	if err := dns.ValidateActiveRouteBindings(routing); err != nil {
		return Model{}, fmt.Errorf("%w: DNS: %v", ErrInvalidDocument, err)
	}

	return Model{
		LogLevel:  wire.LogLevel,
		Nodes:     nodes,
		Selection: selection,
		Routing:   routing,
		DNS:       dns,
	}, nil
}

type semanticCompilation struct {
	targets   compiler.TargetCatalog
	routing   compiler.BoundRouting
	selection compiler.CompiledSelection
	nodes     compiler.CompiledNodes
	dns       compiler.CompiledDNS
}

func compileSemantic(model Model) (semanticCompilation, error) {
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
	routing, err := compiler.CompileRouting(model.Routing, targets)
	if err != nil {
		return semanticCompilation{}, fmt.Errorf("%w: routing compile: %v", ErrInvalidDocument, err)
	}
	if len(routing.RuleSetRefs) != 0 {
		return semanticCompilation{}, fmt.Errorf("%w: referenced %v", ErrRuleSetsUnsupportedInV1, routing.RuleSetRefs)
	}
	ruleSets, err := compiler.NewRuleSetCatalog(nil)
	if err != nil {
		return semanticCompilation{}, err
	}
	bound, err := compiler.BindRuleSetArtifacts(routing, ruleSets)
	if err != nil {
		return semanticCompilation{}, err
	}
	bound, err = compiler.BindStagedRuleSetPaths(bound, map[string]string{})
	if err != nil {
		return semanticCompilation{}, err
	}

	dns, err := compiler.CompileRuntimeDNSForRouting(model.DNS, model.Routing, targets)
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
