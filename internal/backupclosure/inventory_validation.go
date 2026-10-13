package backupclosure

import (
	"bytes"
	"encoding/json"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

// ParseInertInventory validates the canonical, digest-bound inventory format.
// It validates METADATA ONLY: the caller-provided digest is not a signature,
// and the returned value is never proof of file possession, authenticity,
// restorability, core compatibility, or authority to activate a generation.
// In particular, no inventory may set restore_ready=true.
func ParseInertInventory(encoded []byte, expectedSHA256 string) (Inventory, error) {
	if len(encoded) == 0 || len(encoded) > maxManifestBytes ||
		!validLowerSHA(expectedSHA256) || shaHex(encoded) != expectedSHA256 {
		return Inventory{}, ErrUnsafeClosure
	}
	var inventory Inventory
	if err := json.Unmarshal(encoded, &inventory); err != nil {
		return Inventory{}, ErrUnsafeClosure
	}
	if err := validateInertInventory(inventory); err != nil {
		return Inventory{}, err
	}
	// This also refuses unknown fields, repeated JSON keys, noncanonical
	// encodings, explicit null for omitted fields, and trailing data. The
	// writer always uses encoding/json.Marshal for the exact v1/v2 shapes.
	canonical, err := json.Marshal(inventory)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return Inventory{}, ErrUnsafeClosure
	}
	return inventory, nil
}

func validateInertInventory(inventory Inventory) error {
	if inventory.StorageSchema != supportedStorageSchema ||
		!validLowerSHA(inventory.DatabaseSHA256) ||
		inventory.DatabaseBytes <= 0 ||
		inventory.DatabaseBytes > storage.MaxDatabaseSnapshotBytes ||
		!inventory.ContainsCredentials || inventory.RestoreReady ||
		inventory.Generations == nil || inventory.RuleSets == nil ||
		len(inventory.Generations) > MaxClosureGenerations ||
		len(inventory.RuleSets) > MaxClosureRuleSets {
		return ErrUnsafeClosure
	}
	switch inventory.Format {
	case ManifestVersion:
		if inventory.Core != nil {
			return ErrUnsafeClosure
		}
	case CoreManifestVersion:
		if inventory.Core == nil {
			return ErrUnsafeClosure
		}
	default:
		return ErrUnsafeClosure
	}

	var lastGeneration int64
	for _, generation := range inventory.Generations {
		if generation.ID <= lastGeneration ||
			generation.DeclarationRevision == 0 ||
			!validLowerSHA(generation.ConfigSHA256) ||
			!validLowerSHA(generation.ManifestSHA256) ||
			!validLowerSHA(generation.SourceMapSHA256) {
			return ErrUnsafeClosure
		}
		lastGeneration = generation.ID
	}

	var lastRulePath string
	remaining := MaxClosureRuleBytes
	for _, rule := range inventory.RuleSets {
		var ext string
		switch rule.Format {
		case compiler.RuleSetFormatSource:
			ext = ".json"
		case compiler.RuleSetFormatBinary:
			ext = ".srs"
		default:
			return ErrUnsafeClosure
		}
		expected := "rule-sets/sha256/" + rule.SHA256 + ext
		if !validLowerSHA(rule.SHA256) || rule.RelativePath != expected ||
			rule.RelativePath <= lastRulePath ||
			rule.Size <= 0 || rule.Size > coreartifact.MaxRuleSetUploadBytes ||
			rule.Size > remaining {
			return ErrUnsafeClosure
		}
		remaining -= rule.Size
		lastRulePath = rule.RelativePath
	}

	if core := inventory.Core; core != nil {
		hash, err := coreartifact.ExpectedSHA256(core.Architecture)
		if err != nil || core.SHA256 != hash ||
			core.RelativePath != "core/"+hash+".bin" ||
			core.CandidateCommit != coreartifact.CandidateCommit ||
			core.Version != coreartifact.CandidateVersion ||
			core.Size <= 0 || core.Size > coreartifact.MaxPinnedCoreBytes {
			return ErrUnsafeClosure
		}
	}
	return nil
}
