package backupclosure

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

const (
	ManifestVersion        = "karing-tui-v2-internal-resource-closure-v1"
	CoreManifestVersion    = "karing-tui-v2-internal-resource-closure-v2"
	MaxClosureGenerations  = 32
	MaxClosureRuleSets     = 128
	MaxClosureRuleBytes    = int64(128 << 20)
	maxManifestBytes       = 128 << 10
	maxClosureDuration     = 90 * time.Second
	supportedStorageSchema = 17
)

var ErrUnsafeClosure = errors.New("snapshot resource closure unavailable or changed")

type GenerationDigest struct {
	ID                  int64  `json:"id"`
	ConfigSHA256        string `json:"config_sha256"`
	ManifestSHA256      string `json:"manifest_sha256"`
	SourceMapSHA256     string `json:"source_map_sha256"`
	DeclarationRevision uint64 `json:"declaration_revision"`
}

type RuleDigest struct {
	RelativePath string                 `json:"relative_path"`
	SHA256       string                 `json:"sha256"`
	Format       compiler.RuleSetFormat `json:"format"`
	Size         int64                  `json:"size"`
}

// CoreDigest records the approved core's identity without retaining its
// absolute executable path or granting permission to execute a copied file.
type CoreDigest struct {
	RelativePath    string `json:"relative_path"`
	Architecture    string `json:"architecture"`
	CandidateCommit string `json:"candidate_commit"`
	Version         string `json:"version"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size"`
}

// Inventory contains only bounded hashes and relative content-addressed paths.
// It is internal verification evidence, never an archive, restore token or API.
type Inventory struct {
	Format              string             `json:"format"`
	StorageSchema       int                `json:"storage_schema"`
	DatabaseSHA256      string             `json:"database_sha256"`
	DatabaseBytes       int64              `json:"database_bytes"`
	Generations         []GenerationDigest `json:"generations"`
	RuleSets            []RuleDigest       `json:"rule_sets"`
	Core                *CoreDigest        `json:"core,omitempty"`
	ContainsCredentials bool               `json:"contains_credentials"`
	RestoreReady        bool               `json:"restore_ready"`
}

type pinnedRule struct {
	path   string
	sha    string
	format compiler.RuleSetFormat
	pin    *coreartifact.RuleSetPin
}

// Closure holds the SQLite snapshot and independent, flock-held rule copies.
// The live daemon is never paused, changed or restarted. Close every result.
type Closure struct {
	Database        *storage.DatabaseSnapshot
	Inventory       Inventory
	InventoryJSON   []byte
	InventorySHA256 string
	copies          *coreartifact.RuleSetSnapshot
	pins            []pinnedRule
	corePin         *coreartifact.CorePin
	closed          bool
}

// Build creates an internal, temporary closure. ALL retained generations in
// the database copy are validated; even an uncommitted persisted generation
// cannot contribute an undeclared external dependency. Legacy generations
// without compiler-owned manifest/provenance fail closed.
func Build(ctx context.Context, store *storage.Store, stateRoot, privateSnapshotParent string) (*Closure, error) {
	return build(ctx, store, stateRoot, privateSnapshotParent, nil)
}

// BuildWithApprovedCore binds the repository-locked native Linux executable to
// the SQLite and rule-set closure. The copied binary is inert, private, and
// deliberately non-executable; no daemon or user API invokes this method.
func BuildWithApprovedCore(
	ctx context.Context, store *storage.Store, stateRoot, privateSnapshotParent, approvedCorePath string,
) (*Closure, error) {
	if approvedCorePath == "" {
		return nil, ErrUnsafeClosure
	}
	return buildWithCore(ctx, store, stateRoot, privateSnapshotParent, approvedCorePath, nil)
}

// afterCopy is a deterministic internal test injection seam: it never runs in
// the public Build path and cannot be invoked through a daemon client.
func build(ctx context.Context, store *storage.Store, stateRoot, privateSnapshotParent string, afterCopy func(*Closure)) (*Closure, error) {
	return buildWithCore(ctx, store, stateRoot, privateSnapshotParent, "", afterCopy)
}

func buildWithCore(
	ctx context.Context, store *storage.Store, stateRoot, privateSnapshotParent, approvedCorePath string,
	afterCopy func(*Closure),
) (_ *Closure, err error) {
	if ctx == nil || store == nil || stateRoot == "" || !filepath.IsAbs(stateRoot) ||
		filepath.Clean(stateRoot) != stateRoot {
		return nil, ErrUnsafeClosure
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, maxClosureDuration)
	defer cancel()
	ctx = bounded
	closure := &Closure{}
	defer func() {
		if err != nil {
			if closeErr := closure.Close(); closeErr != nil {
				err = errors.Join(err, ErrUnsafeClosure)
			}
		}
	}()
	closure.Database, err = store.CreateDatabaseSnapshot(ctx, privateSnapshotParent)
	if err != nil {
		return nil, ErrUnsafeClosure
	}
	if err = closure.Database.Verify(ctx); err != nil {
		return nil, ErrUnsafeClosure
	}

	snapshotDB, err := openSnapshotReadOnly(closure.Database.Path)
	if err != nil {
		return nil, ErrUnsafeClosure
	}
	// The source of truth for all references is this one SQLite copy, not
	// separate reads of the live writable store.
	generationRecords, rules, schema, readErr := enumerateSnapshot(ctx, snapshotDB, stateRoot)
	closeErr := snapshotDB.Close()
	if readErr != nil || closeErr != nil {
		return nil, ErrUnsafeClosure
	}

	closure.Inventory = Inventory{
		Format: ManifestVersion, StorageSchema: schema,
		DatabaseSHA256:      closure.Database.SHA256,
		DatabaseBytes:       closure.Database.Size,
		Generations:         generationRecords,
		RuleSets:            make([]RuleDigest, 0, len(rules)),
		ContainsCredentials: true, // conservative even for an empty DB
		RestoreReady:        false,
	}

	if len(rules) != 0 {
		if err := verifyRuleRoot(stateRoot); err != nil {
			return nil, ErrUnsafeClosure
		}
	}
	remaining := MaxClosureRuleBytes
	for _, item := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pin, pinErr := coreartifact.PinRuleSet(item.path, item.sha)
		if pinErr != nil {
			return nil, ErrUnsafeClosure
		}
		closure.pins = append(closure.pins, pinnedRule{path: item.path, sha: item.sha, format: item.format, pin: pin})
		fileInfo, statErr := os.Lstat(item.path)
		if statErr != nil || !fileInfo.Mode().IsRegular() {
			return nil, ErrUnsafeClosure
		}
		linkInfo, ok := fileInfo.Sys().(*syscall.Stat_t)
		if !ok || linkInfo.Nlink != 1 {
			return nil, ErrUnsafeClosure
		}
		size := pin.Size()
		if size < 0 || size > remaining {
			return nil, ErrUnsafeClosure
		}
		remaining -= size
		closure.Inventory.RuleSets = append(closure.Inventory.RuleSets, RuleDigest{
			RelativePath: "rule-sets/sha256/" + filepath.Base(item.path),
			SHA256:       item.sha, Format: item.format, Size: size,
		})
	}
	if approvedCorePath != "" {
		closure.corePin, err = coreartifact.PinApprovedCore(ctx, approvedCorePath)
		if err != nil {
			return nil, ErrUnsafeClosure
		}
		closure.Inventory.Format = CoreManifestVersion
		closure.Inventory.Core = &CoreDigest{
			RelativePath:    "core/" + closure.corePin.SHA256() + ".bin",
			Architecture:    closure.corePin.Architecture(),
			CandidateCommit: coreartifact.CandidateCommit,
			Version:         coreartifact.CandidateVersion,
			SHA256:          closure.corePin.SHA256(),
			Size:            closure.corePin.Size(),
		}
	}
	if len(closure.pins) != 0 || closure.corePin != nil {
		pins := make([]*coreartifact.RuleSetPin, 0, len(closure.pins))
		for _, pin := range closure.pins {
			pins = append(pins, pin.pin)
		}
		if closure.corePin != nil {
			closure.copies, err = coreartifact.StagePinnedRuleSetSnapshotWithCore(
				ctx, filepath.Join(stateRoot, "core"), pins, closure.corePin)
		} else {
			closure.copies, err = coreartifact.StagePinnedRuleSetSnapshot(
				ctx, filepath.Join(stateRoot, "core"), pins)
		}
		if err != nil {
			return nil, ErrUnsafeClosure
		}
	}
	if afterCopy != nil {
		afterCopy(closure)
	}
	if err := closure.Verify(ctx); err != nil {
		return nil, err
	}
	closure.InventoryJSON, err = json.Marshal(closure.Inventory)
	if err != nil || len(closure.InventoryJSON) > maxManifestBytes {
		return nil, ErrUnsafeClosure
	}
	sum := sha256.Sum256(closure.InventoryJSON)
	closure.InventorySHA256 = hex.EncodeToString(sum[:])
	if err := closure.Verify(ctx); err != nil {
		return nil, err
	}
	return closure, nil
}

func openSnapshotReadOnly(path string) (*sql.DB, error) {
	uri := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&immutable=1"}
	db, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA trusted_schema = OFF"); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}

type candidateRule struct {
	path   string
	sha    string
	format compiler.RuleSetFormat
}

func enumerateSnapshot(ctx context.Context, db *sql.DB, stateRoot string) ([]GenerationDigest, []candidateRule, int, error) {
	var schema int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&schema); err != nil || schema != supportedStorageSchema {
		return nil, nil, 0, ErrUnsafeClosure
	}
	rows, err := db.QueryContext(ctx, `SELECT id, config_json, config_sha256, manifest_json, manifest_sha256, source_map_json, source_map_sha256 FROM generations ORDER BY id ASC LIMIT ?`, MaxClosureGenerations+1)
	if err != nil {
		return nil, nil, 0, ErrUnsafeClosure
	}
	// Avoid concurrently querying the same one-connection SQLite database:
	// materialize a bounded number of digest-checked rows, close rows, then
	// look up historical declaration revisions in this SAME copied database.
	type rowData struct {
		digest         GenerationDigest
		declarationSHA string
	}
	records := make([]rowData, 0, MaxClosureGenerations)
	allRules := map[string]candidateRule{}
	root := filepath.Join(stateRoot, "core", "rule-sets", "sha256")
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			_ = rows.Close()
			return nil, nil, 0, err
		}
		if len(records) >= MaxClosureGenerations {
			_ = rows.Close()
			return nil, nil, 0, ErrUnsafeClosure
		}
		var id int64
		var config, manifest, sourceMap []byte
		var configSHA string
		var manifestSHA, sourceSHA sql.NullString
		if err := rows.Scan(&id, &config, &configSHA, &manifest, &manifestSHA, &sourceMap, &sourceSHA); err != nil {
			_ = rows.Close()
			return nil, nil, 0, ErrUnsafeClosure
		}
		if id <= 0 || !digestMatches(config, configSHA, storage.MaxGenerationConfigBytes) ||
			!digestMatches(manifest, manifestSHA.String, storage.MaxGenerationMetadataBytes) ||
			!digestMatches(sourceMap, sourceSHA.String, storage.MaxGenerationMetadataBytes) ||
			!json.Valid(config) || !json.Valid(sourceMap) {
			_ = rows.Close()
			return nil, nil, 0, ErrUnsafeClosure
		}
		var native compiler.NativeManifest
		if json.Unmarshal(manifest, &native) != nil || native.SchemaID != compiler.NativeSchemaID ||
			native.ConfigSHA256 != configSHA || native.ValidateDeclarationBinding(true) != nil ||
			len(native.RuleSets) > MaxClosureRuleSets ||
			!validLowerSHA(native.DeclarationSHA256) || native.DeclarationRevision == 0 {
			_ = rows.Close()
			return nil, nil, 0, ErrUnsafeClosure
		}
		if err := validateNativeBindings(config, native.RuleSets); err != nil {
			_ = rows.Close()
			return nil, nil, 0, ErrUnsafeClosure
		}
		seenTags := map[string]bool{}
		for _, rule := range native.RuleSets {
			if !validLowerSHA(rule.SHA256) || rule.Ref == "" || len(rule.Ref) > 1024 ||
				rule.RuntimeTag == "" || len(rule.RuntimeTag) > 1024 ||
				rule.RuntimeTag != "rs-"+shaHex([]byte(rule.Ref)) || seenTags[rule.RuntimeTag] {
				_ = rows.Close()
				return nil, nil, 0, ErrUnsafeClosure
			}
			seenTags[rule.RuntimeTag] = true
			var ext string
			switch rule.Format {
			case compiler.RuleSetFormatSource:
				ext = ".json"
			case compiler.RuleSetFormatBinary:
				ext = ".srs"
			default:
				_ = rows.Close()
				return nil, nil, 0, ErrUnsafeClosure
			}
			expected := filepath.Join(root, rule.SHA256+ext)
			if rule.RuntimePath != expected {
				_ = rows.Close()
				return nil, nil, 0, ErrUnsafeClosure
			}
			if _, exists := allRules[expected]; !exists {
				if len(allRules) >= MaxClosureRuleSets {
					_ = rows.Close()
					return nil, nil, 0, ErrUnsafeClosure
				}
				allRules[expected] = candidateRule{path: expected, sha: rule.SHA256, format: rule.Format}
			}
		}
		records = append(records, rowData{digest: GenerationDigest{
			ID: id, ConfigSHA256: configSHA, ManifestSHA256: manifestSHA.String,
			SourceMapSHA256: sourceSHA.String, DeclarationRevision: native.DeclarationRevision,
		}, declarationSHA: native.DeclarationSHA256})
	}
	rowErr := rows.Err()
	closeErr := rows.Close()
	if rowErr != nil || closeErr != nil {
		return nil, nil, 0, ErrUnsafeClosure
	}

	for _, record := range records {
		var document []byte
		var sha string
		if err := db.QueryRowContext(ctx, `SELECT document_json, document_sha256 FROM declaration_revisions WHERE revision = ?`, record.digest.DeclarationRevision).Scan(&document, &sha); err != nil ||
			sha != record.declarationSHA || !digestMatches(document, sha, storage.MaxDeclarationBytes) || !json.Valid(document) {
			return nil, nil, 0, ErrUnsafeClosure
		}
	}
	gens := make([]GenerationDigest, 0, len(records))
	for _, record := range records {
		gens = append(gens, record.digest)
	}
	keys := make([]string, 0, len(allRules))
	for key := range allRules {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rules := make([]candidateRule, 0, len(keys))
	for _, key := range keys {
		rules = append(rules, allRules[key])
	}
	return gens, rules, schema, nil
}

// The compiler-owned manifest must enumerate exactly the local native
// rule_set bindings. A forged manifest cannot omit or redirect native files.
func validateNativeBindings(config []byte, declared []compiler.NativeRuleSetManifest) error {
	var native struct {
		Route struct {
			Rules []struct {
				Type   string                 `json:"type"`
				Tag    string                 `json:"tag"`
				Path   string                 `json:"path"`
				Format compiler.RuleSetFormat `json:"format"`
			} `json:"rule_set"`
		} `json:"route"`
	}
	if err := json.Unmarshal(config, &native); err != nil || len(native.Route.Rules) != len(declared) {
		return ErrUnsafeClosure
	}
	expected := make(map[string]compiler.NativeRuleSetManifest, len(declared))
	for _, rule := range declared {
		if _, exists := expected[rule.RuntimeTag]; exists {
			return ErrUnsafeClosure
		}
		expected[rule.RuntimeTag] = rule
	}
	seen := make(map[string]bool, len(declared))
	for _, item := range native.Route.Rules {
		want, ok := expected[item.Tag]
		if !ok || seen[item.Tag] || item.Type != "local" || item.Path != want.RuntimePath || item.Format != want.Format {
			return ErrUnsafeClosure
		}
		seen[item.Tag] = true
	}
	return nil
}

func validLowerSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	bytes, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(bytes) == s
}

func digestMatches(data []byte, expected string, limit int) bool {
	if len(data) == 0 || len(data) > limit || !validLowerSHA(expected) {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == expected
}

func verifyRuleRoot(stateRoot string) error {
	for _, path := range []string{
		stateRoot, filepath.Join(stateRoot, "core"),
		filepath.Join(stateRoot, "core", "rule-sets"),
		filepath.Join(stateRoot, "core", "rule-sets", "sha256"),
	} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
			return ErrUnsafeClosure
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Getuid() {
			return ErrUnsafeClosure
		}
	}
	return nil
}

// Verify checks every original descriptor and independent copied rule file,
// plus the SQLite snapshot's inode, digest and quick_check. A successful
// Verify does NOT bind these resources across a process restart.
func (c *Closure) Verify(ctx context.Context) error {
	if c == nil || c.closed || c.Database == nil || ctx == nil {
		return ErrUnsafeClosure
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateInertInventory(c.Inventory); err != nil ||
		c.Inventory.DatabaseSHA256 != c.Database.SHA256 ||
		c.Inventory.DatabaseBytes != c.Database.Size ||
		len(c.Inventory.RuleSets) != len(c.pins) {
		return ErrUnsafeClosure
	}
	for index, item := range c.pins {
		digest := c.Inventory.RuleSets[index]
		if digest.SHA256 != item.sha || digest.Format != item.format ||
			digest.RelativePath != "rule-sets/sha256/"+filepath.Base(item.path) ||
			item.pin == nil || digest.Size != item.pin.Size() {
			return ErrUnsafeClosure
		}
	}
	if err := c.Database.Verify(ctx); err != nil {
		return ErrUnsafeClosure
	}
	for _, item := range c.pins {
		if err := item.pin.Reverify(ctx); err != nil {
			return ErrUnsafeClosure
		}
	}
	if c.corePin != nil {
		core := c.Inventory.Core
		if core == nil || c.Inventory.Format != CoreManifestVersion ||
			core.SHA256 != c.corePin.SHA256() ||
			core.Size != c.corePin.Size() ||
			core.Architecture != c.corePin.Architecture() ||
			core.CandidateCommit != coreartifact.CandidateCommit ||
			core.Version != coreartifact.CandidateVersion ||
			core.RelativePath != "core/"+c.corePin.SHA256()+".bin" ||
			c.corePin.Reverify(ctx) != nil || c.copies == nil {
			return ErrUnsafeClosure
		}
		copyPath, exists := c.copies.CoreFile()
		if !exists || copyPath == "" {
			return ErrUnsafeClosure
		}
	} else if c.Inventory.Core != nil || c.Inventory.Format != ManifestVersion {
		return ErrUnsafeClosure
	}
	if c.copies != nil {
		if err := c.copies.Verify(ctx); err != nil {
			return ErrUnsafeClosure
		}
		for _, item := range c.pins {
			if _, exists := c.copies.FileFor(item.path); !exists {
				return ErrUnsafeClosure
			}
		}
	}
	if len(c.InventoryJSON) != 0 {
		expected, err := json.Marshal(c.Inventory)
		if err != nil || c.InventorySHA256 != shaHex(expected) ||
			!bytes.Equal(expected, c.InventoryJSON) {
			return ErrUnsafeClosure
		}
	}
	return nil
}

func shaHex(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// Close releases copied resources, original descriptors and sensitive DB
// snapshot even if a previous close step failed. Never remove unknown files.
func (c *Closure) Close() error {
	if c == nil || c.closed {
		return nil
	}
	var errs []error
	if c.copies != nil {
		if err := c.copies.Close(); err != nil {
			errs = append(errs, ErrUnsafeClosure)
		}
	}
	for _, item := range c.pins {
		if err := item.pin.Close(); err != nil {
			errs = append(errs, ErrUnsafeClosure)
		}
	}
	if c.corePin != nil {
		if err := c.corePin.Close(); err != nil {
			errs = append(errs, ErrUnsafeClosure)
		}
	}
	if c.Database != nil {
		if err := c.Database.Close(); err != nil {
			errs = append(errs, ErrUnsafeClosure)
		}
	}
	c.closed = true
	c.InventoryJSON = nil
	return errors.Join(errs...)
}
