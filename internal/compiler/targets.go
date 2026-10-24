package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const (
	DirectOutboundTag          = "out-direct"
	CurrentSelectedOutboundTag = "out-current"
	GlobalURLTestOutboundTag   = "out-global-urltest"
)

var (
	ErrDuplicateTargetID  = errors.New("duplicate target identity")
	ErrDuplicateTargetTag = errors.New("duplicate generated outbound tag")
)

type NodeTargetKey struct {
	ProfileID string
	NodeID    string
}

type TargetCatalog struct {
	DirectTag          string
	CurrentSelectedTag string
	GlobalURLTestTag   string
	CustomURLTestTags  map[string]string
	NodeTags           map[NodeTargetKey]string
}

func NewTargetCatalog(customGroupIDs []string, nodes []NodeTargetKey) (TargetCatalog, error) {
	catalog := TargetCatalog{
		DirectTag:          DirectOutboundTag,
		CurrentSelectedTag: CurrentSelectedOutboundTag,
		GlobalURLTestTag:   GlobalURLTestOutboundTag,
		CustomURLTestTags:  make(map[string]string, len(customGroupIDs)),
		NodeTags:           make(map[NodeTargetKey]string, len(nodes)),
	}

	groups := append([]string(nil), customGroupIDs...)
	sort.Strings(groups)
	for _, groupID := range groups {
		if err := validateTargetID(groupID); err != nil {
			return TargetCatalog{}, fmt.Errorf("custom URLTest group ID %q: %w", groupID, err)
		}
		if _, exists := catalog.CustomURLTestTags[groupID]; exists {
			return TargetCatalog{}, fmt.Errorf("%w: custom URLTest group %q", ErrDuplicateTargetID, groupID)
		}
		catalog.CustomURLTestTags[groupID] = stableTargetTag("out-auto-", "custom", groupID)
	}

	nodeKeys := append([]NodeTargetKey(nil), nodes...)
	sort.Slice(nodeKeys, func(i, j int) bool {
		if nodeKeys[i].ProfileID != nodeKeys[j].ProfileID {
			return nodeKeys[i].ProfileID < nodeKeys[j].ProfileID
		}
		return nodeKeys[i].NodeID < nodeKeys[j].NodeID
	})
	for _, node := range nodeKeys {
		if err := validateTargetID(node.ProfileID); err != nil {
			return TargetCatalog{}, fmt.Errorf("node profile ID %q: %w", node.ProfileID, err)
		}
		if err := validateTargetID(node.NodeID); err != nil {
			return TargetCatalog{}, fmt.Errorf("node ID %q: %w", node.NodeID, err)
		}
		if _, exists := catalog.NodeTags[node]; exists {
			return TargetCatalog{}, fmt.Errorf("%w: node %q/%q", ErrDuplicateTargetID, node.ProfileID, node.NodeID)
		}
		catalog.NodeTags[node] = stableTargetTag("out-node-", "node", node.ProfileID, node.NodeID)
	}

	if err := catalog.Validate(); err != nil {
		return TargetCatalog{}, err
	}
	return catalog, nil
}

func (c TargetCatalog) Validate() error {
	seen := make(map[string]string)
	register := func(identity, tag string) error {
		if err := validateGeneratedTag(tag); err != nil {
			return fmt.Errorf("%s: %w", identity, err)
		}
		if previous, exists := seen[tag]; exists {
			return fmt.Errorf("%w: %q is shared by %s and %s", ErrDuplicateTargetTag, tag, previous, identity)
		}
		seen[tag] = identity
		return nil
	}

	for _, fixed := range []struct {
		identity string
		tag      string
	}{
		{identity: "DIRECT", tag: c.DirectTag},
		{identity: "CurrentSelected", tag: c.CurrentSelectedTag},
		{identity: "GlobalURLTest", tag: c.GlobalURLTestTag},
	} {
		if err := register(fixed.identity, fixed.tag); err != nil {
			return err
		}
	}

	groupIDs := make([]string, 0, len(c.CustomURLTestTags))
	for groupID := range c.CustomURLTestTags {
		groupIDs = append(groupIDs, groupID)
	}
	sort.Strings(groupIDs)
	for _, groupID := range groupIDs {
		if err := validateTargetID(groupID); err != nil {
			return fmt.Errorf("custom URLTest group ID %q: %w", groupID, err)
		}
		if err := register("custom URLTest "+groupID, c.CustomURLTestTags[groupID]); err != nil {
			return err
		}
	}

	nodeKeys := make([]NodeTargetKey, 0, len(c.NodeTags))
	for key := range c.NodeTags {
		nodeKeys = append(nodeKeys, key)
	}
	sort.Slice(nodeKeys, func(i, j int) bool {
		if nodeKeys[i].ProfileID != nodeKeys[j].ProfileID {
			return nodeKeys[i].ProfileID < nodeKeys[j].ProfileID
		}
		return nodeKeys[i].NodeID < nodeKeys[j].NodeID
	})
	for _, key := range nodeKeys {
		if err := validateTargetID(key.ProfileID); err != nil {
			return fmt.Errorf("node profile ID %q: %w", key.ProfileID, err)
		}
		if err := validateTargetID(key.NodeID); err != nil {
			return fmt.Errorf("node ID %q: %w", key.NodeID, err)
		}
		if err := register("node "+key.ProfileID+"/"+key.NodeID, c.NodeTags[key]); err != nil {
			return err
		}
	}
	return nil
}

func (c TargetCatalog) ResolveTarget(target domain.TargetRef) (string, error) {
	if err := target.Validate(); err != nil {
		return "", err
	}
	switch target.Kind {
	case domain.TargetDirect:
		return c.DirectTag, nil
	case domain.TargetCurrentSelected:
		return c.CurrentSelectedTag, nil
	case domain.TargetGlobalURLTest:
		return c.GlobalURLTestTag, nil
	case domain.TargetCustomURLTest:
		tag, exists := c.CustomURLTestTags[target.GroupID]
		if !exists {
			return "", fmt.Errorf("custom URLTest group %q is not in target catalog", target.GroupID)
		}
		return tag, nil
	case domain.TargetSpecificNode:
		key := NodeTargetKey{ProfileID: target.ProfileID, NodeID: target.NodeID}
		tag, exists := c.NodeTags[key]
		if !exists {
			return "", fmt.Errorf("node %q/%q is not in target catalog", target.ProfileID, target.NodeID)
		}
		return tag, nil
	case domain.TargetBlock:
		return "", errors.New("BLOCK is an action and has no outbound tag")
	default:
		return "", fmt.Errorf("unsupported target kind %q", target.Kind)
	}
}

func stableTargetTag(prefix string, parts ...string) string {
	hasher := sha256.New()
	for i, part := range parts {
		if i != 0 {
			_, _ = hasher.Write([]byte{0})
		}
		_, _ = hasher.Write([]byte(part))
	}
	return prefix + hex.EncodeToString(hasher.Sum(nil))
}

func validateTargetID(value string) error {
	if value == "" {
		return errors.New("stable ID must not be empty")
	}
	if len(value) > 512 {
		return errors.New("stable ID exceeds 512 bytes")
	}
	if strings.TrimSpace(value) != value {
		return errors.New("stable ID must not have leading or trailing whitespace")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("stable ID contains a control character")
		}
	}
	return nil
}
