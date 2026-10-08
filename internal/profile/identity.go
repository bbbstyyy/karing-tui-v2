package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const stableNodeIDPrefix = "node-"

var (
	ErrInvalidProfileID      = errors.New("invalid profile ID")
	ErrInvalidSourceNode     = errors.New("invalid source node")
	ErrDuplicateSourceKey    = errors.New("duplicate source node key")
	ErrInvalidPriorIdentity  = errors.New("invalid prior node identity")
	ErrNodeIdentityCollision = errors.New("node identity collision")
)

type SourceNode struct {
	SourceKey   string
	SourceName  string
	PayloadJSON []byte
}

type NodeIdentity struct {
	ProfileID  string
	NodeID     string
	SourceKey  string
	SourceName string
}

type NodeRename struct {
	NodeID     string
	SourceKey  string
	BeforeName string
	AfterName  string
}

type ReconcileResult struct {
	Current []NodeIdentity
	Added   []NodeIdentity
	Removed []NodeIdentity
	Renamed []NodeRename
}

// StableNodeID derives the project-owned identity for a newly observed source
// node. Importers own SourceKey semantics; this function deliberately does not
// use the display name as a fallback identity.
func ValidateProfileID(profileID string) error {
	if err := validateStableID(profileID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProfileID, err)
	}
	return nil
}

func ValidateNodeID(nodeID string) error {
	if err := validateStableID(nodeID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPriorIdentity, err)
	}
	return nil
}

func StableNodeID(profileID, sourceKey string) (string, error) {
	if err := ValidateProfileID(profileID); err != nil {
		return "", err
	}
	if err := validateSourceKey(sourceKey); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte("karing-tui-v2/profile-node/v1\x00" + profileID + "\x00" + sourceKey))
	return stableNodeIDPrefix + hex.EncodeToString(sum[:]), nil
}

// ReconcileNodeIdentities maps one imported source snapshot onto stable
// project-owned node identities. Existing SourceKey -> NodeID mappings are
// preserved exactly, which permits migration from older non-derived IDs. A
// changed SourceKey is always remove+add; matching display names are never used
// as an implicit rebind heuristic.
func ReconcileNodeIdentities(
	profileID string,
	previous []NodeIdentity,
	incoming []SourceNode,
) (ReconcileResult, error) {
	if err := ValidateProfileID(profileID); err != nil {
		return ReconcileResult{}, err
	}

	previousByKey := make(map[string]NodeIdentity, len(previous))
	nodeIDOwner := make(map[string]string, len(previous)+len(incoming))
	for i, identity := range previous {
		if identity.ProfileID != profileID {
			return ReconcileResult{}, fmt.Errorf(
				"%w: previous[%d] belongs to profile %q, want %q",
				ErrInvalidPriorIdentity,
				i,
				identity.ProfileID,
				profileID,
			)
		}
		if err := validateStableID(identity.NodeID); err != nil {
			return ReconcileResult{}, fmt.Errorf("%w: previous[%d] node ID: %v", ErrInvalidPriorIdentity, i, err)
		}
		if err := validateSourceKey(identity.SourceKey); err != nil {
			return ReconcileResult{}, fmt.Errorf("%w: previous[%d]: %v", ErrInvalidPriorIdentity, i, err)
		}
		if err := validateSourceName(identity.SourceName, false); err != nil {
			return ReconcileResult{}, fmt.Errorf("%w: previous[%d]: %v", ErrInvalidPriorIdentity, i, err)
		}
		if _, exists := previousByKey[identity.SourceKey]; exists {
			return ReconcileResult{}, fmt.Errorf("%w: previous source key %q", ErrInvalidPriorIdentity, identity.SourceKey)
		}
		if owner, exists := nodeIDOwner[identity.NodeID]; exists {
			return ReconcileResult{}, fmt.Errorf(
				"%w: prior node ID %q is shared by source keys %q and %q",
				ErrInvalidPriorIdentity,
				identity.NodeID,
				owner,
				identity.SourceKey,
			)
		}
		previousByKey[identity.SourceKey] = identity
		nodeIDOwner[identity.NodeID] = identity.SourceKey
	}

	result := ReconcileResult{
		Current: make([]NodeIdentity, 0, len(incoming)),
		Added:   make([]NodeIdentity, 0),
		Removed: make([]NodeIdentity, 0),
		Renamed: make([]NodeRename, 0),
	}
	seenIncoming := make(map[string]struct{}, len(incoming))
	for i, source := range incoming {
		if err := validateSourceKey(source.SourceKey); err != nil {
			return ReconcileResult{}, fmt.Errorf("%w: incoming[%d]: %v", ErrInvalidSourceNode, i, err)
		}
		if err := validateSourceName(source.SourceName, true); err != nil {
			return ReconcileResult{}, fmt.Errorf("%w: incoming[%d]: %v", ErrInvalidSourceNode, i, err)
		}
		if _, exists := seenIncoming[source.SourceKey]; exists {
			return ReconcileResult{}, fmt.Errorf("%w: %q", ErrDuplicateSourceKey, source.SourceKey)
		}
		seenIncoming[source.SourceKey] = struct{}{}

		if prior, exists := previousByKey[source.SourceKey]; exists {
			current := prior
			current.SourceName = source.SourceName
			result.Current = append(result.Current, current)
			if prior.SourceName != source.SourceName {
				result.Renamed = append(result.Renamed, NodeRename{
					NodeID:     prior.NodeID,
					SourceKey:  source.SourceKey,
					BeforeName: prior.SourceName,
					AfterName:  source.SourceName,
				})
			}
			continue
		}

		nodeID, err := StableNodeID(profileID, source.SourceKey)
		if err != nil {
			return ReconcileResult{}, fmt.Errorf("%w: incoming[%d]: %v", ErrInvalidSourceNode, i, err)
		}
		if owner, exists := nodeIDOwner[nodeID]; exists && owner != source.SourceKey {
			return ReconcileResult{}, fmt.Errorf(
				"%w: derived node ID %q maps source keys %q and %q",
				ErrNodeIdentityCollision,
				nodeID,
				owner,
				source.SourceKey,
			)
		}
		nodeIDOwner[nodeID] = source.SourceKey
		current := NodeIdentity{
			ProfileID:  profileID,
			NodeID:     nodeID,
			SourceKey:  source.SourceKey,
			SourceName: source.SourceName,
		}
		result.Current = append(result.Current, current)
		result.Added = append(result.Added, current)
	}

	for _, prior := range previous {
		if _, exists := seenIncoming[prior.SourceKey]; !exists {
			result.Removed = append(result.Removed, prior)
		}
	}
	return result, nil
}

func validateStableID(value string) error {
	if value == "" {
		return errors.New("stable ID must not be empty")
	}
	if len(value) > 512 {
		return errors.New("stable ID exceeds 512 bytes")
	}
	if strings.TrimSpace(value) != value {
		return errors.New("stable ID must not have leading or trailing whitespace")
	}
	if !utf8.ValidString(value) {
		return errors.New("stable ID is not valid UTF-8")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("stable ID contains a control character")
		}
	}
	return nil
}

func validateSourceKey(value string) error {
	if value == "" {
		return fmt.Errorf("%w: source key must not be empty", ErrInvalidSourceNode)
	}
	if len(value) > 4096 {
		return fmt.Errorf("%w: source key exceeds 4096 bytes", ErrInvalidSourceNode)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: source key must not have leading or trailing whitespace", ErrInvalidSourceNode)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: source key is not valid UTF-8", ErrInvalidSourceNode)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: source key contains a control character", ErrInvalidSourceNode)
		}
	}
	return nil
}

func validateSourceName(value string, required bool) error {
	if required && value == "" {
		return fmt.Errorf("%w: source name must not be empty", ErrInvalidSourceNode)
	}
	if len(value) > 4096 {
		return fmt.Errorf("%w: source name exceeds 4096 bytes", ErrInvalidSourceNode)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: source name is not valid UTF-8", ErrInvalidSourceNode)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: source name contains a control character", ErrInvalidSourceNode)
		}
	}
	return nil
}
