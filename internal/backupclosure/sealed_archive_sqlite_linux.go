//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

// This memory-only verification stage intentionally accepts a smaller bound
// than the archive transport. Deserialize duplicates SQLite pages in the
// driver. Refuse larger archives rather than exhausting the running daemon.
const MaxInMemoryArchiveSQLiteBytes = int64(64 << 20)
const maxArchiveDeclarationRevisions = 4096

var ErrArchiveLogicalVerification = errors.New("inert archive SQLite logical verification refused")

// readAuthenticatedSQLiteBytes is called only AFTER VerifyInertArchive has
// authenticated every byte and every resource digest, and after the canonical
// inventory has been SHA-bound to a full second read. The third pass streams
// the entire ciphertext into a SHA-256 digest before returning any decrypted
// SQLite bytes. The bytes are never written to a disk file.
func readAuthenticatedSQLiteBytes(
	ctx context.Context, path string, key [32]byte,
	receipt SealedArchiveReceipt, inventory Inventory,
) (result []byte, err error) {
	if ctx == nil || !validSealedArchivePath(path) || key == ([32]byte{}) ||
		inventory.DatabaseBytes < 512 ||
		inventory.DatabaseBytes > MaxInMemoryArchiveSQLiteBytes ||
		receipt.Bytes > MaxSealedArchiveBytes ||
		!validLowerSHA(receipt.ArchiveSHA256) ||
		receipt.InventorySHA256 == "" {
		return nil, ErrArchiveLogicalVerification
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if verifySealedArchiveParent(filepath.Dir(path)) != nil {
		return nil, ErrArchiveLogicalVerification
	}
	file, err := openSealedArchiveNoFollow(path)
	if err != nil {
		return nil, ErrArchiveLogicalVerification
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || before.Size() != receipt.Bytes ||
		verifySealedFile(file, path, before, receipt.Bytes, true) != nil {
		return nil, ErrArchiveLogicalVerification
	}
	sha := sha256.New()
	reader := io.TeeReader(sealedContextReader{ctx: ctx, src: file}, sha)
	header := make([]byte, sealedArchiveHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil ||
		!bytes.Equal(header[:len(sealedArchiveMagic)], []byte(sealedArchiveMagic)) {
		return nil, ErrArchiveLogicalVerification
	}
	nonce := header[len(sealedArchiveMagic):]
	cipherBytes := receipt.Bytes - int64(sealedArchiveHeaderBytes+sealedArchiveTagBytes)
	if cipherBytes < 4+inventory.DatabaseBytes ||
		cipherBytes > MaxSealedArchiveBytes {
		return nil, ErrArchiveLogicalVerification
	}
	encKey, _ := sealedKeys(key, nonce)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, ErrArchiveLogicalVerification
	}
	ciphertext := &io.LimitedReader{R: reader, N: cipherBytes}
	plain := &cipher.StreamReader{S: cipher.NewCTR(block, nonce), R: ciphertext}
	var size [4]byte
	if _, err := io.ReadFull(plain, size[:]); err != nil {
		return nil, ErrArchiveLogicalVerification
	}
	manifestLen := int(binary.BigEndian.Uint32(size[:]))
	if manifestLen == 0 || manifestLen > maxManifestBytes ||
		int64(4+manifestLen)+inventory.DatabaseBytes > cipherBytes {
		return nil, ErrArchiveLogicalVerification
	}
	manifest := make([]byte, manifestLen)
	if _, err := io.ReadFull(plain, manifest); err != nil ||
		shaHex(manifest) != receipt.InventorySHA256 {
		return nil, ErrArchiveLogicalVerification
	}
	parsed, err := ParseInertInventory(manifest, receipt.InventorySHA256)
	if err != nil || !reflect.DeepEqual(parsed, inventory) {
		return nil, ErrArchiveLogicalVerification
	}
	database := make([]byte, int(inventory.DatabaseBytes))
	defer func() {
		if err != nil {
			clear(database)
			result = nil
		}
	}()
	if _, err := io.ReadFull(plain, database); err != nil ||
		shaHex(database) != inventory.DatabaseSHA256 {
		return nil, ErrArchiveLogicalVerification
	}
	// The previously authenticated manifest tells us how many rule/core
	// bytes follow. We hash ALL remaining ciphertext, including its MAC.
	if _, err := io.Copy(io.Discard, ciphertext); err != nil ||
		ciphertext.N != 0 {
		return nil, ErrArchiveLogicalVerification
	}
	tag := make([]byte, sealedArchiveTagBytes)
	if _, err := io.ReadFull(reader, tag); err != nil {
		return nil, ErrArchiveLogicalVerification
	}
	var extra [1]byte
	if _, err := reader.Read(extra[:]); !errors.Is(err, io.EOF) ||
		hex.EncodeToString(sha.Sum(nil)) != receipt.ArchiveSHA256 ||
		ctx.Err() != nil {
		return nil, ErrArchiveLogicalVerification
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) ||
		before.Size() != after.Size() || before.Mode() != after.Mode() ||
		!before.ModTime().Equal(after.ModTime()) ||
		verifySealedFile(file, path, before, receipt.Bytes, true) != nil {
		return nil, ErrArchiveLogicalVerification
	}
	return database, nil
}

// verifyInMemoryArchiveSQLite loads a bounded, pre-authenticated snapshot
// through the project's existing modernc SQLite driver Deserialize hook.
// There is no CREATE/ATTACH/VACUUM, disk plaintext, recovery mutation or
// connection to the authoritative live database.
func verifyInMemoryArchiveSQLite(
	ctx context.Context, sqliteBytes []byte, inventory Inventory,
) (declarations int, domains storage.ArchiveDomainCounts, err error) {
	if ctx == nil || len(sqliteBytes) < 512 ||
		int64(len(sqliteBytes)) > MaxInMemoryArchiveSQLiteBytes ||
		int64(len(sqliteBytes)) != inventory.DatabaseBytes ||
		!bytes.HasPrefix(sqliteBytes, []byte("SQLite format 3\x00")) ||
		shaHex(sqliteBytes) != inventory.DatabaseSHA256 {
		return 0, storage.ArchiveDomainCounts{}, ErrArchiveLogicalVerification
	}
	if err := ctx.Err(); err != nil {
		return 0, storage.ArchiveDomainCounts{}, err
	}
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return 0, storage.ArchiveDomainCounts{}, ErrArchiveLogicalVerification
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(ctx)
	if err != nil {
		return 0, storage.ArchiveDomainCounts{}, ErrArchiveLogicalVerification
	}
	defer conn.Close()
	if err := conn.Raw(func(driverConn any) error {
		deserializer, ok := driverConn.(interface{ Deserialize([]byte) error })
		if !ok {
			return ErrArchiveLogicalVerification
		}
		return deserializer.Deserialize(sqliteBytes)
	}); err != nil {
		return 0, storage.ArchiveDomainCounts{}, ErrArchiveLogicalVerification
	}
	for _, pragma := range []string{
		"PRAGMA trusted_schema = OFF",
		"PRAGMA temp_store = MEMORY",
		"PRAGMA query_only = ON",
		"PRAGMA foreign_keys = ON",
	} {
		if _, err := conn.ExecContext(ctx, pragma); err != nil {
			return 0, storage.ArchiveDomainCounts{}, ErrArchiveLogicalVerification
		}
	}
	if err := checkArchiveSQLitePragma(ctx, conn, "PRAGMA integrity_check", true); err != nil {
		return 0, storage.ArchiveDomainCounts{}, err
	}
	if err := checkArchiveSQLitePragma(ctx, conn, "PRAGMA foreign_key_check", false); err != nil {
		return 0, storage.ArchiveDomainCounts{}, err
	}
	if err := validateArchiveMigrations(ctx, conn, inventory.StorageSchema); err != nil {
		return 0, storage.ArchiveDomainCounts{}, err
	}
	// Compare the entire SQL DDL/index catalog against a separately
	// migrated :memory: reference, then inspect bounded subscription/profile
	// domain rows before accepting even an otherwise valid SQLite image.
	domains, err = storage.VerifyArchivedSchemaAndDomains(ctx, conn, inventory.StorageSchema)
	if err != nil {
		return 0, storage.ArchiveDomainCounts{}, ErrArchiveLogicalVerification
	}
	declarations, err = validateArchiveDeclarations(ctx, conn)
	if err != nil {
		return 0, storage.ArchiveDomainCounts{}, err
	}
	if err := validateArchiveSingletonState(ctx, conn, declarations); err != nil {
		return 0, storage.ArchiveDomainCounts{}, err
	}
	root, err := inferArchivedStateRoot(ctx, conn)
	if err != nil {
		return 0, storage.ArchiveDomainCounts{}, err
	}
	generations, rules, schema, err := enumerateSnapshot(ctx, conn, root)
	if err != nil || schema != inventory.StorageSchema ||
		!reflect.DeepEqual(generations, inventory.Generations) ||
		len(rules) != len(inventory.RuleSets) {
		return 0, storage.ArchiveDomainCounts{}, ErrArchiveLogicalVerification
	}
	for i, rule := range rules {
		digest := inventory.RuleSets[i]
		if digest.RelativePath != "rule-sets/sha256/"+filepath.Base(rule.path) ||
			digest.SHA256 != rule.sha || digest.Format != rule.format {
			return 0, storage.ArchiveDomainCounts{}, ErrArchiveLogicalVerification
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, storage.ArchiveDomainCounts{}, err
	}
	return declarations, domains, nil
}

func checkArchiveSQLitePragma(
	ctx context.Context, conn *sql.Conn, query string, expectOK bool,
) error {
	rows, err := conn.QueryContext(ctx, query)
	if err != nil {
		return ErrArchiveLogicalVerification
	}
	defer rows.Close()
	if expectOK {
		if !rows.Next() {
			return ErrArchiveLogicalVerification
		}
		var value string
		if err := rows.Scan(&value); err != nil || value != "ok" {
			return ErrArchiveLogicalVerification
		}
		if rows.Next() {
			return ErrArchiveLogicalVerification
		}
	} else if rows.Next() {
		return ErrArchiveLogicalVerification
	}
	if rows.Err() != nil {
		return ErrArchiveLogicalVerification
	}
	return nil
}

func validateArchiveMigrations(ctx context.Context, conn *sql.Conn, wanted int) error {
	if !storage.SupportedArchiveSchema(wanted) {
		return ErrArchiveLogicalVerification
	}
	rows, err := conn.QueryContext(ctx,
		"SELECT version FROM schema_migrations ORDER BY version LIMIT ?", wanted+1)
	if err != nil {
		return ErrArchiveLogicalVerification
	}
	defer rows.Close()
	for i := 1; i <= wanted; i++ {
		if !rows.Next() {
			return ErrArchiveLogicalVerification
		}
		var version int
		if rows.Scan(&version) != nil || version != i {
			return ErrArchiveLogicalVerification
		}
	}
	if rows.Next() || rows.Err() != nil {
		return ErrArchiveLogicalVerification
	}
	return nil
}

func validateArchiveDeclarations(ctx context.Context, conn *sql.Conn) (int, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT revision, parent_revision, document_json, document_sha256
		FROM declaration_revisions ORDER BY revision LIMIT ?`,
		maxArchiveDeclarationRevisions+1)
	if err != nil {
		return 0, ErrArchiveLogicalVerification
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		count++
		if count > maxArchiveDeclarationRevisions {
			return 0, ErrArchiveLogicalVerification
		}
		var revision int64
		var parent sql.NullInt64
		var document []byte
		var sha string
		if rows.Scan(&revision, &parent, &document, &sha) != nil ||
			revision != int64(count) ||
			(parent.Valid && (count == 1 || parent.Int64 != revision-1)) ||
			(!parent.Valid && count != 1) ||
			!digestMatches(document, sha, storage.MaxDeclarationBytes) ||
			!json.Valid(document) {
			return 0, ErrArchiveLogicalVerification
		}
	}
	if rows.Err() != nil {
		return 0, ErrArchiveLogicalVerification
	}
	return count, nil
}

func validateArchiveSingletonState(
	ctx context.Context, conn *sql.Conn, declarations int,
) error {
	var revision sql.NullInt64
	if err := conn.QueryRowContext(ctx,
		"SELECT current_revision FROM declaration_state WHERE singleton = 1",
	).Scan(&revision); err != nil ||
		(revision.Valid && revision.Int64 != int64(declarations)) ||
		(!revision.Valid && declarations != 0) {
		return ErrArchiveLogicalVerification
	}
	var configRevision int64
	var recoveryRequired int
	if err := conn.QueryRowContext(ctx, `
		SELECT config_revision, recovery_required FROM daemon_state
		WHERE singleton = 1`,
	).Scan(&configRevision, &recoveryRequired); err != nil ||
		configRevision < 0 || (recoveryRequired != 0 && recoveryRequired != 1) {
		return ErrArchiveLogicalVerification
	}
	var selectionRevision int64
	if err := conn.QueryRowContext(ctx,
		"SELECT revision FROM selection_state WHERE singleton = 1",
	).Scan(&selectionRevision); err != nil || selectionRevision < 0 {
		return ErrArchiveLogicalVerification
	}
	return nil
}

// The original compiler-owned manifests contain absolute local paths. This
// validator derives only the common root needed by the existing strict
// manifest/native binding validator. It NEVER stats or opens these paths.
func inferArchivedStateRoot(ctx context.Context, conn *sql.Conn) (string, error) {
	rows, err := conn.QueryContext(ctx,
		"SELECT manifest_json FROM generations ORDER BY id LIMIT ?",
		MaxClosureGenerations+1)
	if err != nil {
		return "", ErrArchiveLogicalVerification
	}
	defer rows.Close()
	root := ""
	seen := 0
	for rows.Next() {
		seen++
		if seen > MaxClosureGenerations {
			return "", ErrArchiveLogicalVerification
		}
		var encoded []byte
		if rows.Scan(&encoded) != nil ||
			len(encoded) == 0 || len(encoded) > storage.MaxGenerationMetadataBytes {
			return "", ErrArchiveLogicalVerification
		}
		var manifest compiler.NativeManifest
		if json.Unmarshal(encoded, &manifest) != nil ||
			len(manifest.RuleSets) > MaxClosureRuleSets {
			return "", ErrArchiveLogicalVerification
		}
		for _, rule := range manifest.RuleSets {
			path := rule.RuntimePath
			if !validLowerSHA(rule.SHA256) || !filepath.IsAbs(path) ||
				filepath.Clean(path) != path {
				return "", ErrArchiveLogicalVerification
			}
			base := path
			for i := 0; i < 4; i++ {
				base = filepath.Dir(base)
			}
			if base == "/" || base == "." ||
				(base != root && root != "") {
				return "", ErrArchiveLogicalVerification
			}
			root = base
		}
	}
	if rows.Err() != nil {
		return "", ErrArchiveLogicalVerification
	}
	if root == "" {
		// Nothing consumes the root when the manifest has no local rules.
		root = "/archive-inert-no-rules"
	}
	return root, nil
}
