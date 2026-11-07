package preset

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

var ErrInvalidCNOverride = errors.New("invalid CN preset override")

type CNOverride struct {
	GroupID      string
	Enabled      *bool
	Target       *domain.TargetRef
	DNSProfileID *string
}

type EffectiveCNGroup struct {
	ID           string
	Order        uint32
	DisplayName  string
	Enabled      bool
	Target       domain.TargetRef
	DNSProfileID string
	Source       CNRule
}

func ApplyCNOverrides(snapshot CNSnapshot, overrides []CNOverride) ([]EffectiveCNGroup, error) {
	index := make(map[string]int, len(snapshot.Groups))
	groups := make([]EffectiveCNGroup, len(snapshot.Groups))
	for i, group := range snapshot.Groups {
		if group.ID == "" {
			return nil, fmt.Errorf("%w: snapshot group %d has empty ID", ErrInvalidCNOverride, i+1)
		}
		if _, exists := index[group.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate snapshot group ID %q", ErrInvalidCNOverride, group.ID)
		}
		index[group.ID] = i
		groups[i] = EffectiveCNGroup{
			ID:          group.ID,
			Order:       group.Order,
			DisplayName: group.DisplayName,
			Enabled:     group.Enabled,
			Target:      group.Target,
			Source:      cloneCNRule(group.Source),
		}
	}

	seen := make(map[string]struct{}, len(overrides))
	for _, override := range overrides {
		if override.GroupID == "" {
			return nil, fmt.Errorf("%w: override group ID must not be empty", ErrInvalidCNOverride)
		}
		if _, exists := seen[override.GroupID]; exists {
			return nil, fmt.Errorf("%w: duplicate override for group %q", ErrInvalidCNOverride, override.GroupID)
		}
		seen[override.GroupID] = struct{}{}

		position, exists := index[override.GroupID]
		if !exists {
			return nil, fmt.Errorf("%w: unknown group %q", ErrInvalidCNOverride, override.GroupID)
		}
		group := &groups[position]

		if override.Enabled != nil {
			group.Enabled = *override.Enabled
		}
		if override.Target != nil {
			if err := override.Target.Validate(); err != nil {
				return nil, fmt.Errorf("%w: group %q target: %v", ErrInvalidCNOverride, override.GroupID, err)
			}
			group.Target = *override.Target
		}
		if override.DNSProfileID != nil {
			if err := validateOptionalStableID(*override.DNSProfileID); err != nil {
				return nil, fmt.Errorf("%w: group %q DNS profile: %v", ErrInvalidCNOverride, override.GroupID, err)
			}
			group.DNSProfileID = *override.DNSProfileID
		}
	}
	return groups, nil
}

func validateOptionalStableID(value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 256 {
		return errors.New("identifier exceeds 256 bytes")
	}
	if strings.TrimSpace(value) != value {
		return errors.New("identifier must not have leading or trailing whitespace")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '-', '_', '.', ':', '/':
			continue
		default:
			return fmt.Errorf("identifier contains unsupported character %q", r)
		}
	}
	return nil
}
