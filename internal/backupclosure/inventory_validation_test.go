package backupclosure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
)

func sampleInertInventory() Inventory {
	return Inventory{
		Format: ManifestVersion, StorageSchema: supportedStorageSchema,
		DatabaseSHA256: strings.Repeat("a", 64), DatabaseBytes: 4096,
		Generations: []GenerationDigest{{
			ID: 1, ConfigSHA256: strings.Repeat("b", 64),
			ManifestSHA256: strings.Repeat("c", 64),
			SourceMapSHA256: strings.Repeat("d", 64), DeclarationRevision: 1,
		}},
		RuleSets: []RuleDigest{{
			RelativePath: "rule-sets/sha256/" + strings.Repeat("e", 64) + ".json",
			SHA256: strings.Repeat("e", 64), Format: compiler.RuleSetFormatSource, Size: 123,
		}},
		ContainsCredentials: true, RestoreReady: false,
	}
}

func sampleInertCore(t *testing.T) *CoreDigest {
	t.Helper()
	hash, err := coreartifact.ExpectedSHA256(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	return &CoreDigest{
		RelativePath: "core/" + hash + ".bin", Architecture: runtime.GOARCH,
		CandidateCommit: coreartifact.CandidateCommit,
		Version: coreartifact.CandidateVersion, SHA256: hash, Size: 4096,
	}
}

func TestParseInertInventoryCanonicalV1V2(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			inventory := sampleInertInventory()
			if version == "v2" {
				inventory.Format = CoreManifestVersion
				inventory.Core = sampleInertCore(t)
			}
			encoded, err := json.Marshal(inventory)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseInertInventory(encoded, shaHex(encoded))
			if err != nil || !reflect.DeepEqual(parsed, inventory) {
				t.Fatalf("roundtrip refused: %v", err)
			}
			if _, err := ParseInertInventory(encoded, strings.Repeat("f", 64)); !errors.Is(err, ErrUnsafeClosure) {
				t.Fatal("wrong digest accepted")
			}
			if _, err := ParseInertInventory(encoded, strings.ToUpper(shaHex(encoded))); !errors.Is(err, ErrUnsafeClosure) {
				t.Fatal("uppercase digest accepted")
			}
		})
	}
}

func TestParseInertInventoryRejectsInvalidSemanticFields(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Inventory)
	}{
		{"schema", func(i *Inventory) { i.StorageSchema++ }},
		{"format", func(i *Inventory) { i.Format = "unknown" }},
		{"database_hash", func(i *Inventory) { i.DatabaseSHA256 = "abc" }},
		{"database_size_zero", func(i *Inventory) { i.DatabaseBytes = 0 }},
		{"database_size_over", func(i *Inventory) { i.DatabaseBytes = 769 << 20 }},
		{"credentials_flag", func(i *Inventory) { i.ContainsCredentials = false }},
		{"restoration_forgery", func(i *Inventory) { i.RestoreReady = true }},
		{"nil_generations", func(i *Inventory) { i.Generations = nil }},
		{"nil_rules", func(i *Inventory) { i.RuleSets = nil }},
		{"negative_generation", func(i *Inventory) { i.Generations[0].ID = -1 }},
		{"duplicate_generation", func(i *Inventory) { i.Generations = append(i.Generations, i.Generations[0]) }},
		{"unsorted_generation", func(i *Inventory) {
			i.Generations = append([]GenerationDigest{{ID: 2, ConfigSHA256: strings.Repeat("b", 64),
				ManifestSHA256: strings.Repeat("c", 64), SourceMapSHA256: strings.Repeat("d", 64),
				DeclarationRevision: 2}}, i.Generations...)
		}},
		{"missing_declaration", func(i *Inventory) { i.Generations[0].DeclarationRevision = 0 }},
		{"bad_generation_hash", func(i *Inventory) { i.Generations[0].ManifestSHA256 = strings.Repeat("X", 64) }},
		{"rule_traversal", func(i *Inventory) { i.RuleSets[0].RelativePath = "../outside.json" }},
		{"rule_absolute", func(i *Inventory) { i.RuleSets[0].RelativePath = "/private/rule.json" }},
		{"rule_bad_extension", func(i *Inventory) { i.RuleSets[0].RelativePath += ".json" }},
		{"rule_bad_format", func(i *Inventory) { i.RuleSets[0].Format = "unknown" }},
		{"rule_negative", func(i *Inventory) { i.RuleSets[0].Size = -1 }},
		{"rule_zero", func(i *Inventory) { i.RuleSets[0].Size = 0 }},
		{"rule_oversize", func(i *Inventory) { i.RuleSets[0].Size = coreartifact.MaxRuleSetUploadBytes + 1 }},
		{"rule_duplicate", func(i *Inventory) { i.RuleSets = append(i.RuleSets, i.RuleSets[0]) }},
		{"rule_out_of_order", func(i *Inventory) {
			rule := i.RuleSets[0]
			rule.SHA256 = strings.Repeat("a", 64)
			rule.RelativePath = "rule-sets/sha256/" + rule.SHA256 + ".json"
			i.RuleSets = append(i.RuleSets, rule)
		}},
		{"rule_total_budget", func(i *Inventory) {
			i.RuleSets[0].Size = coreartifact.MaxRuleSetUploadBytes
			for _, ch := range []string{"f", "f"} {
				rule := i.RuleSets[0]
				rule.SHA256 = strings.Repeat(ch, 64)
				rule.RelativePath = "rule-sets/sha256/" + rule.SHA256 + ".srs"
				rule.Format = compiler.RuleSetFormatBinary
				i.RuleSets = append(i.RuleSets, rule)
			}
		}},
		{"missing_v2_core", func(i *Inventory) { i.Format = CoreManifestVersion }},
		{"unexpected_v1_core", func(i *Inventory) { i.Core = sampleInertCore(t) }},
		{"core_wrong_hash", func(i *Inventory) {
			i.Format = CoreManifestVersion
			i.Core = sampleInertCore(t)
			i.Core.SHA256 = strings.Repeat("a", 64)
		}},
		{"core_wrong_architecture", func(i *Inventory) {
			i.Format = CoreManifestVersion
			i.Core = sampleInertCore(t)
			i.Core.Architecture = "unsupported"
		}},
		{"core_wrong_version", func(i *Inventory) {
			i.Format = CoreManifestVersion
			i.Core = sampleInertCore(t)
			i.Core.Version = "unapproved"
		}},
		{"core_wrong_commit", func(i *Inventory) {
			i.Format = CoreManifestVersion
			i.Core = sampleInertCore(t)
			i.Core.CandidateCommit = "unapproved"
		}},
		{"core_wrong_path", func(i *Inventory) {
			i.Format = CoreManifestVersion
			i.Core = sampleInertCore(t)
			i.Core.RelativePath = "../../core.bin"
		}},
		{"core_executable_over_budget", func(i *Inventory) {
			i.Format = CoreManifestVersion
			i.Core = sampleInertCore(t)
			i.Core.Size = coreartifact.MaxPinnedCoreBytes + 1
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			inventory := sampleInertInventory()
			tc.change(&inventory)
			encoded, err := json.Marshal(inventory)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ParseInertInventory(encoded, shaHex(encoded)); !errors.Is(err, ErrUnsafeClosure) {
				t.Fatalf("invalid metadata accepted: %+v", inventory)
			}
		})
	}
}

func TestParseInertInventoryRejectsNonCanonicalAndUnknownJSON(t *testing.T) {
	encoded, err := json.Marshal(sampleInertInventory())
	if err != nil {
		t.Fatal(err)
	}
	extras := [][]byte{
		append(append([]byte(nil), encoded...), '\n'),
		append([]byte(" "), encoded...),
		bytes.Replace(encoded, []byte(`"format":"`), []byte(`"format":"` + ManifestVersion + `","format":"`), 1),
		bytes.Replace(encoded, []byte(`"storage_schema":17`), []byte(`"storage_schema":17,"unknown":"secret"`), 1),
		bytes.Replace(encoded, []byte(`"rule_sets":[`), []byte(`"rule_sets":[{"extra":true},`), 1),
		bytes.Replace(encoded, []byte(`"restore_ready":false`), []byte(`"restore_ready":true`), 1),
		append(append([]byte(nil), encoded...), []byte(" {}")...),
		[]byte("null"),
	}
	for index, raw := range extras {
		if bytes.Equal(raw, encoded) {
			t.Fatalf("invalid fixture %d did not change JSON", index)
		}
		if _, err := ParseInertInventory(raw, shaHex(raw)); !errors.Is(err, ErrUnsafeClosure) {
			t.Fatalf("noncanonical or unsupported JSON %d accepted", index)
		}
	}
	tooLarge := bytes.Repeat([]byte(" "), maxManifestBytes+1)
	if _, err := ParseInertInventory(tooLarge, shaHex(tooLarge)); !errors.Is(err, ErrUnsafeClosure) {
		t.Fatal("oversized inventory accepted")
	}
}

func TestClosureVerifyBindsInventoryToOpenedSnapshotAndCopies(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	if _, err := ParseInertInventory(closure.InventoryJSON, closure.InventorySHA256); err != nil {
		t.Fatal(err)
	}
	closure.Inventory.DatabaseBytes++
	if err := closure.Verify(context.Background()); !errors.Is(err, ErrUnsafeClosure) {
		t.Fatal("detached database size accepted")
	}
	closure.Inventory.DatabaseBytes--
	closure.Inventory.RuleSets[0].RelativePath = "rule-sets/sha256/" + strings.Repeat("f", 64) + ".json"
	if err := closure.Verify(context.Background()); !errors.Is(err, ErrUnsafeClosure) {
		t.Fatal("detached rule binding accepted")
	}
}
