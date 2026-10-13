//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// mutateInMemorySQLite updates an ephemeral, private in-process SQLite
// database, solely to build intentionally INCONSISTENT but reauthenticated
// encrypted fixtures. No plaintext database file is created.
func mutateInMemorySQLite(t *testing.T, source []byte, query string) []byte {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.Raw(func(driverConn any) error {
		parser, ok := driverConn.(interface{ Deserialize([]byte) error })
		if !ok {
			return ErrArchiveLogicalVerification
		}
		return parser.Deserialize(source)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "PRAGMA foreign_keys = OFF"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	var mutated []byte
	if err := conn.Raw(func(driverConn any) error {
		serializer, ok := driverConn.(interface{ Serialize() ([]byte, error) })
		if !ok {
			return ErrArchiveLogicalVerification
		}
		var resultErr error
		mutated, resultErr = serializer.Serialize()
		return resultErr
	}); err != nil {
		t.Fatal(err)
	}
	if len(mutated) == 0 {
		t.Fatal("mutated in-memory SQLite serialization returned empty data")
	}
	return mutated
}

func tamperAndResealArchive(
	t *testing.T, originalPath, destination string, key [32]byte,
	mutate func([]byte) []byte,
) {
	t.Helper()
	archive, err := os.ReadFile(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(archive) < sealedArchiveHeaderBytes+sealedArchiveTagBytes+4 {
		t.Fatal("invalid test archive")
	}
	originalNonce := archive[len(sealedArchiveMagic):sealedArchiveHeaderBytes]
	originalEncKey, _ := sealedKeys(key, originalNonce)
	block, err := aes.NewCipher(originalEncKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := archive[sealedArchiveHeaderBytes : len(archive)-sealedArchiveTagBytes]
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCTR(block, originalNonce).XORKeyStream(plaintext, ciphertext)
	manifestSize := int(binary.BigEndian.Uint32(plaintext[:4]))
	if manifestSize <= 0 || manifestSize > maxManifestBytes {
		t.Fatal("test manifest length invalid")
	}
	var inventory Inventory
	if err := json.Unmarshal(plaintext[4:4+manifestSize], &inventory); err != nil {
		t.Fatal(err)
	}
	start := 4 + manifestSize
	end := start + int(inventory.DatabaseBytes)
	if end > len(plaintext) {
		t.Fatal("test SQLite record length invalid")
	}
	altered := mutate(bytes.Clone(plaintext[start:end]))
	inventory.DatabaseBytes = int64(len(altered))
	inventory.DatabaseSHA256 = shaHex(altered)
	manifest, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	updated := make([]byte, 4+len(manifest)+len(altered)+len(plaintext[end:]))
	binary.BigEndian.PutUint32(updated[:4], uint32(len(manifest)))
	copy(updated[4:], manifest)
	copy(updated[4+len(manifest):], altered)
	copy(updated[4+len(manifest)+len(altered):], plaintext[end:])
	clear(plaintext)
	var nonce [aes.BlockSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	encKey, macKey := sealedKeys(key, nonce[:])
	block, err = aes.NewCipher(encKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext = make([]byte, len(updated))
	cipher.NewCTR(block, nonce[:]).XORKeyStream(ciphertext, updated)
	clear(updated)
	header := append([]byte(sealedArchiveMagic), nonce[:]...)
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(header)
	_, _ = mac.Write(ciphertext)
	result := make([]byte, 0, len(header)+len(ciphertext)+sealedArchiveTagBytes)
	result = append(result, header...)
	result = append(result, ciphertext...)
	result = append(result, mac.Sum(nil)...)
	if err := os.WriteFile(destination, result, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReauthenticatedInconsistentSQLiteArchiveIsRefused(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	parent := testSealedDir(t, f)
	original := filepath.Join(parent, "original.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), original, key); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []struct {
		name string
		query string
		alter func([]byte) []byte
	}{
		{"declaration_hash", "UPDATE declaration_revisions SET document_sha256 = '"+strings.Repeat("f", 64)+"' WHERE revision = 1", nil},
		{"generation_hash", "UPDATE generations SET config_sha256 = '"+strings.Repeat("a", 64)+"' WHERE id = 1", nil},
		{"schema_version", "UPDATE schema_migrations SET version = 18 WHERE version = 17", nil},
		{"orphan_foreign_key", "UPDATE daemon_state SET applied_generation_id = 999999 WHERE singleton = 1", nil},
		{"invalid_sqlite_header", "", func(input []byte) []byte {
			input[0] ^= 0x20
			return input
		}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			path := filepath.Join(parent, scenario.name+".ktbackup")
			tamperAndResealArchive(t, original, path, key, func(input []byte) []byte {
				if scenario.alter != nil {
					return scenario.alter(input)
				}
				return mutateInMemorySQLite(t, input, scenario.query)
			})
			// Metadata, encryption, MAC and all record SHA-256 are valid.
			if _, err := VerifyInertArchive(context.Background(), path, key); err != nil {
				t.Fatalf("logical corruption fixture is not cryptographically valid: %v", err)
			}
			// The new independent SQL inspection must refuse its claims.
			report, err := PreflightInertArchive(context.Background(), path, key, nil)
			if !errors.Is(err, ErrUnsafeSealedArchive) ||
				!reflect.DeepEqual(report, InertArchivePreflight{}) {
				t.Fatalf("internally consistent but invalid SQLite was accepted: %+v %v", report, err)
			}
		})
	}
}

func TestInMemorySQLiteOnlyRequiresBoundedAuthenticatedBytes(t *testing.T) {
	fixture := sampleInertInventory()
	fixture.DatabaseBytes = MaxInMemoryArchiveSQLiteBytes + 1
	var key [32]byte
	key[0] = 1
	receipt := SealedArchiveReceipt{
		ArchiveSHA256: strings.Repeat("b", 64),
		InventorySHA256: strings.Repeat("c", 64),
		Bytes: 1024,
	}
	if _, err := readAuthenticatedSQLiteBytes(context.Background(),
		"/not-an-archive.ktbackup", key, receipt, fixture); !errors.Is(err, ErrArchiveLogicalVerification) {
		t.Fatalf("oversized in-memory snapshot accepted: %v", err)
	}
}
