package preset

import (
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

type CNCustomOrderKind string

const (
	CNCustomOrderUser   CNCustomOrderKind = "custom"
	CNCustomOrderPreset CNCustomOrderKind = "cn_preset"
)

var ErrInvalidCNCustomOrder = errors.New("invalid CN custom routing order")

type CNCustomOrderEntry struct {
	Kind    CNCustomOrderKind
	GroupID string
}

// MergeCNCustomRouting interleaves ordinary L1 custom groups with all CN preset
// groups. The order list is authoritative for the merged L1 list, while the
// projection of ordinary custom IDs must preserve their already-validated
// relative order.
func MergeCNCustomRouting(
	custom []domain.RouteGroup,
	cn []domain.RouteGroup,
	order []CNCustomOrderEntry,
) ([]domain.RouteGroup, error) {
	customByID := make(map[string]domain.RouteGroup, len(custom))
	customIDs := make([]string, 0, len(custom))
	for _, group := range custom {
		if group.Layer != domain.LayerCustom {
			return nil, fmt.Errorf("%w: ordinary group %q is not in the custom layer", ErrInvalidCNCustomOrder, group.ID)
		}
		if _, exists := customByID[group.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate ordinary custom group %q", ErrInvalidCNCustomOrder, group.ID)
		}
		customByID[group.ID] = group
		customIDs = append(customIDs, group.ID)
	}

	cnByID := make(map[string]domain.RouteGroup, len(cn))
	for _, group := range cn {
		if group.Layer != domain.LayerCustom {
			return nil, fmt.Errorf("%w: CN group %q is not in the custom layer", ErrInvalidCNCustomOrder, group.ID)
		}
		if _, exists := cnByID[group.ID]; exists {
			return nil, fmt.Errorf("%w: duplicate CN preset group %q", ErrInvalidCNCustomOrder, group.ID)
		}
		if _, exists := customByID[group.ID]; exists {
			return nil, fmt.Errorf("%w: group ID %q is used by both ordinary custom and CN preset groups", ErrInvalidCNCustomOrder, group.ID)
		}
		cnByID[group.ID] = group
	}

	if len(order) == 0 {
		if len(custom) != 0 {
			return nil, fmt.Errorf("%w: custom_order is required when CN preset and ordinary custom groups coexist", ErrInvalidCNCustomOrder)
		}
		result := cloneCNCustomRouteGroups(cn)
		for i := range result {
			result[i].Order = uint32(i + 1)
		}
		return result, nil
	}
	if len(order) != len(custom)+len(cn) {
		return nil, fmt.Errorf(
			"%w: custom_order has %d entries, want %d",
			ErrInvalidCNCustomOrder,
			len(order),
			len(custom)+len(cn),
		)
	}

	result := make([]domain.RouteGroup, 0, len(order))
	seen := make(map[string]CNCustomOrderKind, len(order))
	customProjection := make([]string, 0, len(custom))
	for i, entry := range order {
		if entry.GroupID == "" {
			return nil, fmt.Errorf("%w: custom_order[%d] has empty group ID", ErrInvalidCNCustomOrder, i)
		}
		if previous, exists := seen[entry.GroupID]; exists {
			return nil, fmt.Errorf(
				"%w: custom_order repeats group %q as %s after %s",
				ErrInvalidCNCustomOrder,
				entry.GroupID,
				entry.Kind,
				previous,
			)
		}
		seen[entry.GroupID] = entry.Kind

		var group domain.RouteGroup
		switch entry.Kind {
		case CNCustomOrderUser:
			var exists bool
			group, exists = customByID[entry.GroupID]
			if !exists {
				return nil, fmt.Errorf("%w: custom_order references unknown ordinary custom group %q", ErrInvalidCNCustomOrder, entry.GroupID)
			}
			customProjection = append(customProjection, entry.GroupID)
		case CNCustomOrderPreset:
			var exists bool
			group, exists = cnByID[entry.GroupID]
			if !exists {
				return nil, fmt.Errorf("%w: custom_order references unknown CN preset group %q", ErrInvalidCNCustomOrder, entry.GroupID)
			}
		default:
			return nil, fmt.Errorf("%w: custom_order[%d] has unsupported kind %q", ErrInvalidCNCustomOrder, i, entry.Kind)
		}

		group = cloneCNCustomRouteGroup(group)
		group.Order = uint32(i + 1)
		result = append(result, group)
	}

	for id := range customByID {
		if _, exists := seen[id]; !exists {
			return nil, fmt.Errorf("%w: ordinary custom group %q is missing from custom_order", ErrInvalidCNCustomOrder, id)
		}
	}
	for id := range cnByID {
		if _, exists := seen[id]; !exists {
			return nil, fmt.Errorf("%w: CN preset group %q is missing from custom_order", ErrInvalidCNCustomOrder, id)
		}
	}
	if len(customProjection) != len(customIDs) {
		return nil, fmt.Errorf("%w: ordinary custom projection is incomplete", ErrInvalidCNCustomOrder)
	}
	for i := range customIDs {
		if customProjection[i] != customIDs[i] {
			return nil, fmt.Errorf(
				"%w: ordinary custom projection changed relative order at position %d: got %q, want %q",
				ErrInvalidCNCustomOrder,
				i,
				customProjection[i],
				customIDs[i],
			)
		}
	}
	return result, nil
}

func cloneCNCustomRouteGroups(source []domain.RouteGroup) []domain.RouteGroup {
	if source == nil {
		return nil
	}
	result := make([]domain.RouteGroup, len(source))
	for i := range source {
		result[i] = cloneCNCustomRouteGroup(source[i])
	}
	return result
}

func cloneCNCustomRouteGroup(source domain.RouteGroup) domain.RouteGroup {
	result := source
	if source.Match != nil {
		match := source.Match.Clone()
		result.Match = &match
	}
	return result
}
