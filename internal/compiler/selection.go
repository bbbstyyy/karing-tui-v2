package compiler

import (
	"errors"
	"fmt"
	"sort"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

var ErrSelectionClosure = errors.New("selection outbound closure is incomplete")

type GroupOutboundConfig struct {
	Type                      string   `json:"type"`
	Tag                       string   `json:"tag"`
	Outbounds                 []string `json:"outbounds"`
	Default                   string   `json:"default,omitempty"`
	URL                       string   `json:"url,omitempty"`
	Interval                  string   `json:"interval,omitempty"`
	Tolerance                 uint16   `json:"tolerance,omitempty"`
	IdleTimeout               string   `json:"idle_timeout,omitempty"`
	InterruptExistConnections bool     `json:"interrupt_exist_connections,omitempty"`
}

type CompiledSelection struct {
	Groups      []GroupOutboundConfig
	NodeTargets []domain.TargetRef
	NodeTags    []string
}

func CompileSelectionGroups(plan domain.SelectionPlan, catalog TargetCatalog, requiredOutboundTags []string) (CompiledSelection, error) {
	if err := plan.Validate(); err != nil {
		return CompiledSelection{}, err
	}
	if err := catalog.Validate(); err != nil {
		return CompiledSelection{}, err
	}

	for _, group := range plan.Custom {
		if _, exists := catalog.CustomURLTestTags[group.GroupID]; !exists {
			return CompiledSelection{}, fmt.Errorf("%w: custom URLTest group %q has no target tag", ErrSelectionClosure, group.GroupID)
		}
	}

	nodeByTag := make(map[string]domain.TargetRef, len(catalog.NodeTags))
	for key, tag := range catalog.NodeTags {
		nodeByTag[tag] = domain.TargetRef{
			Kind:      domain.TargetSpecificNode,
			ProfileID: key.ProfileID,
			NodeID:    key.NodeID,
		}
	}
	customIDByTag := make(map[string]string, len(catalog.CustomURLTestTags))
	for groupID, tag := range catalog.CustomURLTestTags {
		customIDByTag[tag] = groupID
	}

	var result CompiledSelection
	nodeSeen := make(map[string]struct{})
	recordNode := func(target domain.TargetRef) error {
		tag, err := catalog.ResolveTarget(target)
		if err != nil {
			return err
		}
		if _, exists := nodeSeen[tag]; exists {
			return nil
		}
		nodeSeen[tag] = struct{}{}
		result.NodeTargets = append(result.NodeTargets, target)
		result.NodeTags = append(result.NodeTags, tag)
		return nil
	}

	needCurrent := false
	needGlobal := false
	requiredCustom := make(map[string]struct{})

	for _, tag := range requiredOutboundTags {
		switch {
		case tag == catalog.DirectTag:
			continue
		case tag == catalog.CurrentSelectedTag:
			needCurrent = true
		case tag == catalog.GlobalURLTestTag:
			needGlobal = true
		case customIDByTag[tag] != "":
			requiredCustom[customIDByTag[tag]] = struct{}{}
		case nodeByTag[tag].Kind == domain.TargetSpecificNode:
			if err := recordNode(nodeByTag[tag]); err != nil {
				return CompiledSelection{}, fmt.Errorf("%w: required node tag %q: %v", ErrSelectionClosure, tag, err)
			}
		default:
			return CompiledSelection{}, fmt.Errorf("%w: unknown required outbound tag %q", ErrSelectionClosure, tag)
		}
	}

	var currentOutbounds []string
	var currentDefault string
	if needCurrent {
		currentOutbounds = make([]string, 0, len(plan.Current.Members))
		for _, member := range plan.Current.Members {
			tag, err := catalog.ResolveTarget(member)
			if err != nil {
				return CompiledSelection{}, fmt.Errorf("%w: CurrentSelected member %+v: %v", ErrSelectionClosure, member, err)
			}
			currentOutbounds = append(currentOutbounds, tag)
			switch member.Kind {
			case domain.TargetSpecificNode:
				if err := recordNode(member); err != nil {
					return CompiledSelection{}, err
				}
			case domain.TargetGlobalURLTest:
				needGlobal = true
			case domain.TargetCustomURLTest:
				requiredCustom[member.GroupID] = struct{}{}
			}
		}
		var err error
		currentDefault, err = catalog.ResolveTarget(plan.Current.Default)
		if err != nil {
			return CompiledSelection{}, fmt.Errorf("%w: CurrentSelected default: %v", ErrSelectionClosure, err)
		}
	}

	if needGlobal {
		if plan.Global == nil {
			return CompiledSelection{}, fmt.Errorf("%w: Global URLTest is required but not configured", ErrSelectionClosure)
		}
		group, err := compileURLTestGroup(*plan.Global, catalog.GlobalURLTestTag, catalog, recordNode)
		if err != nil {
			return CompiledSelection{}, err
		}
		result.Groups = append(result.Groups, group)
	}

	for _, groupPlan := range plan.Custom {
		if _, required := requiredCustom[groupPlan.GroupID]; !required {
			continue
		}
		tag := catalog.CustomURLTestTags[groupPlan.GroupID]
		group, err := compileURLTestGroup(groupPlan, tag, catalog, recordNode)
		if err != nil {
			return CompiledSelection{}, err
		}
		result.Groups = append(result.Groups, group)
		delete(requiredCustom, groupPlan.GroupID)
	}
	if len(requiredCustom) != 0 {
		missing := make([]string, 0, len(requiredCustom))
		for groupID := range requiredCustom {
			missing = append(missing, groupID)
		}
		sort.Strings(missing)
		return CompiledSelection{}, fmt.Errorf("%w: custom URLTest groups are required but not configured: %v", ErrSelectionClosure, missing)
	}

	if needCurrent {
		result.Groups = append(result.Groups, GroupOutboundConfig{
			Type:                      "selector",
			Tag:                       catalog.CurrentSelectedTag,
			Outbounds:                 currentOutbounds,
			Default:                   currentDefault,
			InterruptExistConnections: plan.Current.InterruptExistConnections,
		})
	}

	return result, nil
}

func compileURLTestGroup(
	group domain.URLTestGroup,
	tag string,
	catalog TargetCatalog,
	recordNode func(domain.TargetRef) error,
) (GroupOutboundConfig, error) {
	outbounds := make([]string, 0, len(group.Members))
	for _, member := range group.Members {
		nodeTag, err := catalog.ResolveTarget(member)
		if err != nil {
			return GroupOutboundConfig{}, fmt.Errorf("%w: URLTest group %q member %+v: %v", ErrSelectionClosure, group.GroupID, member, err)
		}
		outbounds = append(outbounds, nodeTag)
		if err := recordNode(member); err != nil {
			return GroupOutboundConfig{}, err
		}
	}
	return GroupOutboundConfig{
		Type:                      "urltest",
		Tag:                       tag,
		Outbounds:                 outbounds,
		URL:                       group.Policy.URL,
		Interval:                  group.Policy.Interval.String(),
		Tolerance:                 group.Policy.Tolerance,
		IdleTimeout:               group.Policy.IdleTimeout.String(),
		InterruptExistConnections: group.Policy.InterruptExistConnections,
	}, nil
}
