//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrInertPortablePathPreview = errors.New("inert archived path relocation preview refused")

// InertPortablePathPreview contains only digest/count evidence. It is never a
// portable generation ID, restoration grant, path lease or activation receipt.
// In particular it never exposes native JSON, user tokens or source paths.
type InertPortablePathPreview struct {
	ArchiveSHA256            string
	InventorySHA256          string
	GenerationCount          int
	RuleSetCount             int
	RelocatedGenerationCount int
	RelocatedConfigDigest    string
	RestoreSupported         bool
	RestoreReady             bool
}

// PreviewPortableRulePaths independently reads authenticated encrypted SQLite
// into memory, verifies its domain model and then computes a path-only native
// config relocation PREVIEW for the supplied hypothetical Linux state root.
// No caller receives a native JSON blob or a writable file. Nothing is
// imported, persisted, linked, executed, migrated or made restore-ready.
//
// The journal-bound ciphertext flock is held across BOTH live-state CAS
// checks and the complete isolated SQLite inspection. As in ADR 0110, a
// post-return digest is not a durable resource pin or write permission.
func (l *InertRestoreResourceLease) PreviewPortableRulePaths(
	ctx context.Context, targetStateRoot string, key [32]byte,
) (InertPortablePathPreview, error) {
	return l.previewPortableRulePaths(ctx, targetStateRoot, key, nil)
}

// afterPlan is private fault injection; there is no public daemon/CLI/TUI API.
func (l *InertRestoreResourceLease) previewPortableRulePaths(
	ctx context.Context, targetStateRoot string, key [32]byte,
	afterPlan func() error,
) (InertPortablePathPreview, error) {
	var none InertPortablePathPreview
	if l == nil || ctx == nil || key == ([32]byte{}) ||
		!validPortablePreviewRoot(targetStateRoot) {
		return none, ErrInertPortablePathPreview
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()

	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.revalidateLocked(bounded, key); err != nil {
		return none, ErrInertPortablePathPreview
	}
	if targetStateRoot == l.candidate.directory ||
		targetStateRoot == l.candidate.parent ||
		strings.HasPrefix(targetStateRoot, l.candidate.parent+string(os.PathSeparator)) {
		return none, ErrInertPortablePathPreview
	}
	receipt := SealedArchiveReceipt{
		ArchiveSHA256:   l.record.ArchiveSHA256,
		InventorySHA256: l.record.InventorySHA256,
		Bytes:           l.record.ArchiveBytes,
		Format:          l.candidate.receipt.Format,
	}
	inventory, err := readAuthenticatedInventory(
		bounded, l.candidate.archive, key, receipt)
	if err != nil {
		return none, ErrInertPortablePathPreview
	}
	sqliteBytes, err := readAuthenticatedSQLiteBytes(
		bounded, l.candidate.archive, key, receipt, inventory)
	if err != nil {
		return none, ErrInertPortablePathPreview
	}
	defer clear(sqliteBytes)
	if _, _, err := verifyInMemoryArchiveSQLite(bounded, sqliteBytes, inventory); err != nil {
		return none, ErrInertPortablePathPreview
	}
	configDigest, relocated, err := previewArchivedConfigRelocations(
		bounded, sqliteBytes, inventory, targetStateRoot)
	if err != nil {
		return none, ErrInertPortablePathPreview
	}
	if afterPlan != nil && afterPlan() != nil {
		return none, ErrInertPortablePathPreview
	}
	if err := l.revalidateLocked(bounded, key); err != nil || bounded.Err() != nil {
		return none, ErrInertPortablePathPreview
	}
	return InertPortablePathPreview{
		ArchiveSHA256:            receipt.ArchiveSHA256,
		InventorySHA256:          receipt.InventorySHA256,
		GenerationCount:          len(inventory.Generations),
		RuleSetCount:             len(inventory.RuleSets),
		RelocatedGenerationCount: relocated,
		RelocatedConfigDigest:    configDigest,
		RestoreSupported:         false,
		RestoreReady:             false,
	}, nil
}

// This is a lexical PREVIEW only: the target root need not exist and no
// ownership or resource path is certified. Any future real import must first
// separately pin a target directory and validate every filesystem component.
func validPortablePreviewRoot(root string) bool {
	if root == "" || len(root) > 1024 || root == "/" ||
		!filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false
	}
	for _, r := range root {
		if r == 0 || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// This is a second isolated in-memory SQL reader. It does not attach to the
// live SQLite database and is never permitted to mutate the archive payload.
func previewArchivedConfigRelocations(
	ctx context.Context, sqliteBytes []byte, inventory Inventory, root string,
) (digest string, relocated int, err error) {
	if ctx == nil || ctx.Err() != nil || !validPortablePreviewRoot(root) ||
		len(sqliteBytes) < 512 ||
		int64(len(sqliteBytes)) > MaxInMemoryArchiveSQLiteBytes ||
		int64(len(sqliteBytes)) != inventory.DatabaseBytes ||
		!bytes.HasPrefix(sqliteBytes, []byte("SQLite format 3\x00")) ||
		shaHex(sqliteBytes) != inventory.DatabaseSHA256 {
		return "", 0, ErrInertPortablePathPreview
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return "", 0, ErrInertPortablePathPreview
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return "", 0, ErrInertPortablePathPreview
	}
	defer conn.Close()
	if err := conn.Raw(func(driverConn any) error {
		deserializer, ok := driverConn.(interface{ Deserialize([]byte) error })
		if !ok {
			return ErrInertPortablePathPreview
		}
		return deserializer.Deserialize(sqliteBytes)
	}); err != nil {
		return "", 0, ErrInertPortablePathPreview
	}
	for _, pragma := range []string{
		"PRAGMA trusted_schema = OFF",
		"PRAGMA temp_store = MEMORY",
		"PRAGMA query_only = ON",
	} {
		if _, err := conn.ExecContext(ctx, pragma); err != nil {
			return "", 0, ErrInertPortablePathPreview
		}
	}
	rows, err := conn.QueryContext(ctx, `
		SELECT id, config_json, config_sha256, manifest_json, manifest_sha256
		FROM generations ORDER BY id LIMIT ?
	`, MaxClosureGenerations+1)
	if err != nil {
		return "", 0, ErrInertPortablePathPreview
	}
	defer rows.Close()
	combined := sha256.New()
	_, _ = io.WriteString(combined, "karing-tui-v2/inert-portable-native-preview/v1\n")
	allowed := make(map[string]bool, len(inventory.RuleSets))
	for _, r := range inventory.RuleSets {
		allowed[r.RelativePath] = true
	}
	var rowsSeen, relocatedCount int
	for rows.Next() {
		if ctx.Err() != nil || rowsSeen >= MaxClosureGenerations ||
			rowsSeen >= len(inventory.Generations) {
			return "", 0, ErrInertPortablePathPreview
		}
		var id int64
		var config, manifest []byte
		var configSHA, manifestSHA string
		if rows.Scan(&id, &config, &configSHA, &manifest, &manifestSHA) != nil {
			return "", 0, ErrInertPortablePathPreview
		}
		// The archive's identity was independently audited before this
		// query; do not accept a different statement's result set.
		want := inventory.Generations[rowsSeen]
		if id != want.ID || configSHA != want.ConfigSHA256 ||
			manifestSHA != want.ManifestSHA256 ||
			!digestMatches(config, configSHA, storage.MaxGenerationConfigBytes) ||
			!digestMatches(manifest, manifestSHA, storage.MaxGenerationMetadataBytes) {
			return "", 0, ErrInertPortablePathPreview
		}
		reboundSHA, changed, rebindErr := previewOneNativeRelocation(
			config, manifest, root, allowed)
		clear(config)
		clear(manifest)
		if rebindErr != nil {
			return "", 0, ErrInertPortablePathPreview
		}
		_, _ = io.WriteString(combined, configSHA+"\n"+manifestSHA+"\n"+reboundSHA+"\n")
		if changed {
			relocatedCount++
		}
		rowsSeen++
	}
	if rows.Err() != nil || rowsSeen != len(inventory.Generations) {
		return "", 0, ErrInertPortablePathPreview
	}
	return hex.EncodeToString(combined.Sum(nil)), relocatedCount, nil
}

func previewOneNativeRelocation(
	configJSON, manifestJSON []byte, targetRoot string, inventoryRules map[string]bool,
) (digest string, changed bool, err error) {
	if !validPortablePreviewRoot(targetRoot) {
		return "", false, ErrInertPortablePathPreview
	}
	var manifest compiler.NativeManifest
	if json.Unmarshal(manifestJSON, &manifest) != nil ||
		manifest.SchemaID != compiler.NativeSchemaID ||
		manifest.ConfigSHA256 != shaHex(configJSON) ||
		manifest.ValidateDeclarationBinding(true) != nil ||
		len(manifest.RuleSets) > MaxClosureRuleSets ||
		validateNativeBindings(configJSON, manifest.RuleSets) != nil {
		return "", false, ErrInertPortablePathPreview
	}
	if len(manifest.RuleSets) == 0 {
		return shaHex(configJSON), false, nil
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(configJSON, &top) != nil {
		return "", false, ErrInertPortablePathPreview
	}
	var route map[string]json.RawMessage
	if json.Unmarshal(top["route"], &route) != nil {
		return "", false, ErrInertPortablePathPreview
	}
	var ruleSets []map[string]json.RawMessage
	if json.Unmarshal(route["rule_set"], &ruleSets) != nil ||
		len(ruleSets) != len(manifest.RuleSets) {
		return "", false, ErrInertPortablePathPreview
	}
	expected := make(map[string]compiler.NativeRuleSetManifest, len(manifest.RuleSets))
	for _, item := range manifest.RuleSets {
		if item.RuntimeTag == "" || expected[item.RuntimeTag].RuntimeTag != "" ||
			!validLowerSHA(item.SHA256) {
			return "", false, ErrInertPortablePathPreview
		}
		expected[item.RuntimeTag] = item
	}
	seen := make(map[string]bool, len(ruleSets))
	newManifests := append([]compiler.NativeRuleSetManifest(nil), manifest.RuleSets...)
	for i, item := range ruleSets {
		var tag, path, kind string
		var format compiler.RuleSetFormat
		if json.Unmarshal(item["tag"], &tag) != nil ||
			json.Unmarshal(item["path"], &path) != nil ||
			json.Unmarshal(item["type"], &kind) != nil ||
			json.Unmarshal(item["format"], &format) != nil {
			return "", false, ErrInertPortablePathPreview
		}
		rule, ok := expected[tag]
		if !ok || seen[tag] || kind != "local" ||
			rule.Format != format || rule.RuntimePath != path {
			return "", false, ErrInertPortablePathPreview
		}
		var extension string
		switch format {
		case compiler.RuleSetFormatSource:
			extension = ".json"
		case compiler.RuleSetFormatBinary:
			extension = ".srs"
		default:
			return "", false, ErrInertPortablePathPreview
		}
		relative := "rule-sets/sha256/" + rule.SHA256 + extension
		if !inventoryRules[relative] {
			return "", false, ErrInertPortablePathPreview
		}
		destination := filepath.Join(targetRoot, "core", relative)
		if len(destination) > 4096 {
			return "", false, ErrInertPortablePathPreview
		}
		if destination != path {
			changed = true
		}
		encoded, err := json.Marshal(destination)
		if err != nil {
			return "", false, ErrInertPortablePathPreview
		}
		ruleSets[i]["path"] = encoded
		for j := range newManifests {
			if newManifests[j].RuntimeTag == tag {
				newManifests[j].RuntimePath = destination
				break
			}
		}
		seen[tag] = true
	}
	if len(seen) != len(expected) {
		return "", false, ErrInertPortablePathPreview
	}
	if !changed {
		// A backup moved back to its original canonical state root needs no
		// JSON rewrite and must preserve its exact original config digest.
		return shaHex(configJSON), false, nil
	}
	route["rule_set"], err = json.Marshal(ruleSets)
	if err != nil {
		return "", false, ErrInertPortablePathPreview
	}
	top["route"], err = json.Marshal(route)
	if err != nil {
		return "", false, ErrInertPortablePathPreview
	}
	relocated, err := json.Marshal(top)
	if err != nil || len(relocated) > storage.MaxGenerationConfigBytes ||
		validateNativeBindings(relocated, newManifests) != nil {
		return "", false, ErrInertPortablePathPreview
	}
	relocatedDigest := shaHex(relocated)
	clear(relocated)
	return relocatedDigest, changed, nil
}
