//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// InertDigestDifference compares content identities, not imported database
// row IDs or node/profile names. It never exposes credentials or paths.
type InertDigestDifference struct {
	OnlyInArchive int
	OnlyInCurrent int
	Shared        int
}

// InertArchivePreflight is a bounded, non-secret report about a read-only
// compatibility inspection. TargetMetadataCompatible is NOT restore
// eligibility. RestoreSupported and RestoreReady are always false.
type InertArchivePreflight struct {
	ArchiveSHA256            string
	InventorySHA256          string
	ArchiveBytes             int64
	Format                   string
	StorageSchema            int
	GenerationCount          int
	RuleSetCount             int
	RuleSetBytes             int64
	CoreIncluded             bool
	CoreArchitecture         string
	ContainsCredentials      bool
	ResourceDigestsVerified  bool
	SQLiteLogicalVerified    bool
	DeclarationCount         int
	TargetMetadataCompatible bool
	Blockers                 []string
	ComparedWithCurrent      bool
	DatabaseDifferent        bool
	Generations              InertDigestDifference
	RuleSets                 InertDigestDifference
	RestoreSupported         bool
	RestoreReady             bool
}

// PreflightInertArchive verifies encrypted resource bytes, then independently
// re-reads the exact authenticated ciphertext to inspect its canonical
// inventory. An optional current closure must itself still be pinned and
// valid. No plaintext database, rule file or core is written to disk; no
// daemon, storage transaction or runtime core is invoked.
//
// The result documents only lock-version metadata compatibility and
// digest-level differences. It never permits an import, restore or activation.
func PreflightInertArchive(
	ctx context.Context, path string, key [32]byte, current *Closure,
) (InertArchivePreflight, error) {
	return preflightInertArchive(ctx, path, key, current, nil)
}

// afterAuth is an internal fault-injection hook used only by tests. It cannot
// be supplied through a public daemon, CLI, or TUI endpoint.
func preflightInertArchive(
	ctx context.Context, path string, key [32]byte, current *Closure,
	afterAuth func(),
) (InertArchivePreflight, error) {
	var empty InertArchivePreflight
	if ctx == nil {
		return empty, ErrUnsafeSealedArchive
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	ctx, cancel := context.WithTimeout(ctx, sealedArchiveTimeout)
	defer cancel()
	if current != nil && current.Verify(ctx) != nil {
		return empty, ErrUnsafeSealedArchive
	}
	// VerifyInertArchive checks the full HMAC, SHA-256 of every decrypted
	// resource, exact record lengths and trailing bytes before returning.
	receipt, err := VerifyInertArchive(ctx, path, key)
	if err != nil {
		return empty, err
	}
	if afterAuth != nil {
		afterAuth()
	}
	// This second read compares SHA-256 of the ENTIRE ciphertext with the
	// authenticated pass. Merely reopening and parsing the first record
	// would introduce a path-swap and post-verification mutation window.
	inventory, err := readAuthenticatedInventory(ctx, path, key, receipt)
	if err != nil {
		return empty, ErrUnsafeSealedArchive
	}
	sqliteBytes, err := readAuthenticatedSQLiteBytes(ctx, path, key, receipt, inventory)
	if err != nil {
		return empty, ErrUnsafeSealedArchive
	}
	defer clear(sqliteBytes)
	declarationCount, err := verifyInMemoryArchiveSQLite(ctx, sqliteBytes, inventory)
	if err != nil {
		return empty, ErrUnsafeSealedArchive
	}
	if current != nil && current.Verify(ctx) != nil {
		return empty, ErrUnsafeSealedArchive
	}
	report := InertArchivePreflight{
		ArchiveSHA256:           receipt.ArchiveSHA256,
		InventorySHA256:         receipt.InventorySHA256,
		ArchiveBytes:            receipt.Bytes,
		Format:                  inventory.Format,
		StorageSchema:           inventory.StorageSchema,
		GenerationCount:         len(inventory.Generations),
		RuleSetCount:            len(inventory.RuleSets),
		CoreIncluded:            inventory.Core != nil,
		ContainsCredentials:     true,
		ResourceDigestsVerified: true,
		SQLiteLogicalVerified:   true,
		DeclarationCount:        declarationCount,
		RestoreSupported:        false,
		RestoreReady:            false,
		Blockers:                []string{"transactional_restore_not_implemented", "durable_restore_resource_lease_not_implemented"},
	}
	for _, rule := range inventory.RuleSets {
		report.RuleSetBytes += rule.Size
	}
	assessArchiveTarget(&report, inventory)
	if current != nil {
		report.ComparedWithCurrent = true
		report.DatabaseDifferent = inventory.DatabaseSHA256 != current.Inventory.DatabaseSHA256
		report.Generations = compareGenerationDigests(inventory.Generations, current.Inventory.Generations)
		report.RuleSets = compareDigestCounts(inventory.RuleSets, current.Inventory.RuleSets)
	}
	return report, nil
}

// assessArchiveTarget checks only the architecture of the cryptographically
// verified, pinned v2 core. This does not perform an executable core check
// or grant a restore/activation permission.
func assessArchiveTarget(report *InertArchivePreflight, inventory Inventory) {
	if inventory.Core == nil {
		report.Blockers = append(report.Blockers, "approved_core_missing_from_archive")
		return
	}
	report.CoreArchitecture = inventory.Core.Architecture
	if inventory.Core.Architecture != runtime.GOARCH {
		report.Blockers = append(report.Blockers, "core_architecture_mismatch")
		return
	}
	report.TargetMetadataCompatible = true
}

// readAuthenticatedInventory never interprets a replayed manifest until the
// complete file SHA-256 matches the first, MAC-verified pass. It buffers no
// more than the small canonical inventory prefix, not the database or rules.
func readAuthenticatedInventory(
	ctx context.Context, path string, key [32]byte, receipt SealedArchiveReceipt,
) (Inventory, error) {
	var none Inventory
	if ctx == nil || !validSealedArchivePath(path) || key == ([32]byte{}) ||
		!validLowerSHA(receipt.ArchiveSHA256) || !validLowerSHA(receipt.InventorySHA256) ||
		receipt.Bytes <= int64(sealedArchiveHeaderBytes+sealedArchiveTagBytes+4) ||
		receipt.Bytes > MaxSealedArchiveBytes {
		return none, ErrUnsafeSealedArchive
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if verifySealedArchiveParent(filepath.Dir(path)) != nil {
		return none, ErrUnsafeSealedArchive
	}
	file, err := openSealedArchiveNoFollow(path)
	if err != nil {
		return none, ErrUnsafeSealedArchive
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || before.Size() != receipt.Bytes ||
		verifySealedFile(file, path, before, receipt.Bytes, true) != nil {
		return none, ErrUnsafeSealedArchive
	}
	maxPrefix := int64(sealedArchiveHeaderBytes + 4 + maxManifestBytes)
	if withoutTag := receipt.Bytes - int64(sealedArchiveTagBytes); maxPrefix > withoutTag {
		maxPrefix = withoutTag
	}
	prefix := make([]byte, int(maxPrefix))
	reader := sealedContextReader{ctx: ctx, src: file}
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return none, ErrUnsafeSealedArchive
	}
	hash := sha256.New()
	if _, err := hash.Write(prefix); err != nil {
		return none, ErrUnsafeSealedArchive
	}
	n, err := io.Copy(hash, io.LimitReader(reader, MaxSealedArchiveBytes+1))
	if err != nil || int64(len(prefix))+n != receipt.Bytes ||
		hex.EncodeToString(hash.Sum(nil)) != receipt.ArchiveSHA256 ||
		ctx.Err() != nil {
		return none, ErrUnsafeSealedArchive
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) ||
		verifySealedFile(file, path, before, receipt.Bytes, true) != nil {
		return none, ErrUnsafeSealedArchive
	}
	if len(prefix) < sealedArchiveHeaderBytes+4 ||
		!bytes.Equal(prefix[:len(sealedArchiveMagic)], []byte(sealedArchiveMagic)) {
		return none, ErrUnsafeSealedArchive
	}
	nonce := prefix[len(sealedArchiveMagic):sealedArchiveHeaderBytes]
	encryptionKey, _ := sealedKeys(key, nonce)
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return none, ErrUnsafeSealedArchive
	}
	plaintextPrefix := make([]byte, len(prefix)-sealedArchiveHeaderBytes)
	cipher.NewCTR(block, nonce).XORKeyStream(plaintextPrefix, prefix[sealedArchiveHeaderBytes:])
	size := binary.BigEndian.Uint32(plaintextPrefix[:4])
	if size == 0 || size > maxManifestBytes ||
		int(size)+4 > len(plaintextPrefix) {
		return none, ErrUnsafeSealedArchive
	}
	inventory, err := ParseInertInventory(plaintextPrefix[4:4+int(size)], receipt.InventorySHA256)
	if err != nil || inventory.Format != receipt.Format {
		return none, ErrUnsafeSealedArchive
	}
	return inventory, nil
}

type generationContentIdentity struct {
	ConfigSHA256    string
	ManifestSHA256  string
	SourceMapSHA256 string
	DeclarationRev  uint64
}

func compareGenerationDigests(archive, current []GenerationDigest) InertDigestDifference {
	a := make([]generationContentIdentity, 0, len(archive))
	b := make([]generationContentIdentity, 0, len(current))
	for _, gen := range archive {
		a = append(a, generationContentIdentity{
			ConfigSHA256: gen.ConfigSHA256, ManifestSHA256: gen.ManifestSHA256,
			SourceMapSHA256: gen.SourceMapSHA256, DeclarationRev: gen.DeclarationRevision,
		})
	}
	for _, gen := range current {
		b = append(b, generationContentIdentity{
			ConfigSHA256: gen.ConfigSHA256, ManifestSHA256: gen.ManifestSHA256,
			SourceMapSHA256: gen.SourceMapSHA256, DeclarationRev: gen.DeclarationRevision,
		})
	}
	return compareDigestCounts(a, b)
}

func compareDigestCounts[T comparable](archive, current []T) InertDigestDifference {
	var diff InertDigestDifference
	baseline := make(map[T]int, len(current))
	for _, item := range current {
		baseline[item]++
	}
	for _, item := range archive {
		if baseline[item] > 0 {
			baseline[item]--
			diff.Shared++
		} else {
			diff.OnlyInArchive++
		}
	}
	for _, count := range baseline {
		diff.OnlyInCurrent += count
	}
	return diff
}
