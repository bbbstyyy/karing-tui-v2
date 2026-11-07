package profileupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrInvalidRuntimeNodeOverlay = errors.New("invalid runtime profile node overlay set")

type runtimeOverlayDigestItem struct {
	NodeID   string `json:"node_id"`
	Disabled bool   `json:"disabled,omitempty"`
	SortRank *int64 `json:"sort_rank,omitempty"`
}

func ApplyRuntimeNodeOverlays(
	nodes []domain.Node,
	overlays []storage.ProfileNodeOverlayState,
) ([]domain.Node, string, error) {
	if len(nodes) == 0 {
		hash, err := runtimeOverlayDigest(nil)
		return nil, hash, err
	}
	profileID := nodes[0].ProfileID
	nodeIndex := make(map[string]int, len(nodes))
	for index, node := range nodes {
		if err := node.Validate(); err != nil {
			return nil, "", err
		}
		if node.ProfileID != profileID {
			return nil, "", fmt.Errorf(
				"%w: nodes contain profiles %q and %q",
				ErrInvalidRuntimeNodeOverlay,
				profileID,
				node.ProfileID,
			)
		}
		if _, duplicate := nodeIndex[node.NodeID]; duplicate {
			return nil, "", fmt.Errorf(
				"%w: duplicate node ID %q",
				ErrInvalidRuntimeNodeOverlay,
				node.NodeID,
			)
		}
		nodeIndex[node.NodeID] = index
	}

	byNodeID := make(map[string]storage.ProfileNodeOverlayState, len(overlays))
	var digestItems []runtimeOverlayDigestItem
	for _, state := range overlays {
		if err := state.Overlay.Validate(); err != nil {
			return nil, "", err
		}
		if state.Overlay.ProfileID != profileID {
			return nil, "", fmt.Errorf(
				"%w: overlay for profile %q supplied while applying profile %q",
				ErrInvalidRuntimeNodeOverlay,
				state.Overlay.ProfileID,
				profileID,
			)
		}
		if _, duplicate := byNodeID[state.Overlay.NodeID]; duplicate {
			return nil, "", fmt.Errorf(
				"%w: duplicate overlay for node %q",
				ErrInvalidRuntimeNodeOverlay,
				state.Overlay.NodeID,
			)
		}
		byNodeID[state.Overlay.NodeID] = state
		if _, relevant := nodeIndex[state.Overlay.NodeID]; relevant &&
			(state.Overlay.Disabled || state.Overlay.SortRank != nil) {
			digestItems = append(digestItems, runtimeOverlayDigestItem{
				NodeID:   state.Overlay.NodeID,
				Disabled: state.Overlay.Disabled,
				SortRank: copyInt64Pointer(state.Overlay.SortRank),
			})
		}
	}

	type orderedNode struct {
		node      domain.Node
		sourcePos int
		sortRank  *int64
	}
	ordered := make([]orderedNode, 0, len(nodes))
	for index, node := range nodes {
		if overlay, ok := byNodeID[node.NodeID]; ok {
			if overlay.Overlay.Disabled {
				continue
			}
			ordered = append(ordered, orderedNode{
				node:      node,
				sourcePos: index,
				sortRank:  copyInt64Pointer(overlay.Overlay.SortRank),
			})
			continue
		}
		ordered = append(ordered, orderedNode{
			node:      node,
			sourcePos: index,
		})
	}
	sort.SliceStable(ordered, func(i, j int) bool {
		left := ordered[i]
		right := ordered[j]
		switch {
		case left.sortRank != nil && right.sortRank != nil:
			if *left.sortRank != *right.sortRank {
				return *left.sortRank < *right.sortRank
			}
			return left.sourcePos < right.sourcePos
		case left.sortRank != nil:
			return true
		case right.sortRank != nil:
			return false
		default:
			return left.sourcePos < right.sourcePos
		}
	})
	result := make([]domain.Node, 0, len(ordered))
	for _, item := range ordered {
		result = append(result, item.node)
	}

	hash, err := runtimeOverlayDigest(digestItems)
	if err != nil {
		return nil, "", err
	}
	return result, hash, nil
}

func runtimeOverlayDigest(items []runtimeOverlayDigestItem) (string, error) {
	cloned := append([]runtimeOverlayDigestItem(nil), items...)
	sort.Slice(cloned, func(i, j int) bool {
		return cloned[i].NodeID < cloned[j].NodeID
	})
	encoded, err := json.Marshal(cloned)
	if err != nil {
		return "", fmt.Errorf("marshal runtime node overlay digest: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func copyInt64Pointer(value *int64) *int64 {
	if value == nil {
		return nil
	}
	result := *value
	return &result
}
