package domain

import (
	"errors"
	"fmt"
	"net/url"
	"time"
)

var (
	ErrInvalidSelectionPlan   = errors.New("invalid selection plan")
	ErrDuplicateSelectionItem = errors.New("duplicate selection item")
)

type URLTestPolicy struct {
	URL                       string
	Interval                  time.Duration
	Tolerance                 uint16
	IdleTimeout               time.Duration
	InterruptExistConnections bool
}

func (p URLTestPolicy) Validate() error {
	parsed, err := url.Parse(p.URL)
	if err != nil {
		return fmt.Errorf("%w: invalid URLTest URL: %v", ErrInvalidSelectionPlan, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%w: URLTest URL must use http or https", ErrInvalidSelectionPlan)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%w: URLTest URL must have a host", ErrInvalidSelectionPlan)
	}
	if parsed.User != nil {
		return fmt.Errorf("%w: URLTest URL must not contain userinfo", ErrInvalidSelectionPlan)
	}
	if p.Interval <= 0 {
		return fmt.Errorf("%w: URLTest interval must be positive", ErrInvalidSelectionPlan)
	}
	if p.Tolerance == 0 {
		return fmt.Errorf("%w: URLTest tolerance must be positive", ErrInvalidSelectionPlan)
	}
	if p.IdleTimeout <= 0 {
		return fmt.Errorf("%w: URLTest idle timeout must be positive", ErrInvalidSelectionPlan)
	}
	return nil
}

type URLTestGroup struct {
	GroupID string
	Members []TargetRef
	Policy  URLTestPolicy
}

func (g URLTestGroup) Validate(requireGroupID bool) error {
	if requireGroupID && g.GroupID == "" {
		return fmt.Errorf("%w: custom URLTest group ID must not be empty", ErrInvalidSelectionPlan)
	}
	if !requireGroupID && g.GroupID != "" {
		return fmt.Errorf("%w: global URLTest group must not carry a custom group ID", ErrInvalidSelectionPlan)
	}
	if len(g.Members) == 0 {
		return fmt.Errorf("%w: URLTest group %q has no node candidates", ErrInvalidSelectionPlan, g.GroupID)
	}
	if err := g.Policy.Validate(); err != nil {
		return err
	}
	seen := make(map[TargetRef]struct{}, len(g.Members))
	for i, member := range g.Members {
		if err := member.Validate(); err != nil {
			return fmt.Errorf("%w: URLTest group %q member %d: %v", ErrInvalidSelectionPlan, g.GroupID, i, err)
		}
		if member.Kind != TargetSpecificNode {
			return fmt.Errorf("%w: URLTest group %q member %d must be a specific node", ErrInvalidSelectionPlan, g.GroupID, i)
		}
		if _, exists := seen[member]; exists {
			return fmt.Errorf("%w: URLTest group %q repeats node %q/%q", ErrDuplicateSelectionItem, g.GroupID, member.ProfileID, member.NodeID)
		}
		seen[member] = struct{}{}
	}
	return nil
}

type CurrentSelection struct {
	Members                   []TargetRef
	Default                   TargetRef
	InterruptExistConnections bool
}

func (s CurrentSelection) Validate() error {
	if len(s.Members) == 0 {
		return fmt.Errorf("%w: CurrentSelected has no candidates", ErrInvalidSelectionPlan)
	}
	if err := s.Default.Validate(); err != nil {
		return fmt.Errorf("%w: invalid CurrentSelected default: %v", ErrInvalidSelectionPlan, err)
	}
	if !isCurrentSelectionMember(s.Default) {
		return fmt.Errorf("%w: unsupported CurrentSelected default target %q", ErrInvalidSelectionPlan, s.Default.Kind)
	}

	seen := make(map[TargetRef]struct{}, len(s.Members))
	defaultFound := false
	for i, member := range s.Members {
		if err := member.Validate(); err != nil {
			return fmt.Errorf("%w: CurrentSelected member %d: %v", ErrInvalidSelectionPlan, i, err)
		}
		if !isCurrentSelectionMember(member) {
			return fmt.Errorf("%w: CurrentSelected member %d has unsupported target %q", ErrInvalidSelectionPlan, i, member.Kind)
		}
		if _, exists := seen[member]; exists {
			return fmt.Errorf("%w: CurrentSelected repeats member %+v", ErrDuplicateSelectionItem, member)
		}
		seen[member] = struct{}{}
		if member == s.Default {
			defaultFound = true
		}
	}
	if !defaultFound {
		return fmt.Errorf("%w: CurrentSelected default is not in its candidate list", ErrInvalidSelectionPlan)
	}
	return nil
}

type SelectionPlan struct {
	Current CurrentSelection
	Global  *URLTestGroup
	Custom  []URLTestGroup
}

func (p SelectionPlan) Validate() error {
	if err := p.Current.Validate(); err != nil {
		return err
	}
	if p.Global != nil {
		if err := p.Global.Validate(false); err != nil {
			return err
		}
	}
	seenGroups := make(map[string]struct{}, len(p.Custom))
	for i, group := range p.Custom {
		if err := group.Validate(true); err != nil {
			return fmt.Errorf("custom URLTest group %d: %w", i, err)
		}
		if _, exists := seenGroups[group.GroupID]; exists {
			return fmt.Errorf("%w: custom URLTest group %q", ErrDuplicateSelectionItem, group.GroupID)
		}
		seenGroups[group.GroupID] = struct{}{}
	}
	return nil
}

func isCurrentSelectionMember(target TargetRef) bool {
	switch target.Kind {
	case TargetSpecificNode, TargetGlobalURLTest, TargetCustomURLTest:
		return true
	default:
		return false
	}
}
