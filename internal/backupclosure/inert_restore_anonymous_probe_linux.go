//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

var ErrInertRestoreAnonymousProbe = errors.New("inert restore anonymous resource probe refused")

// InertRestoreAnonymousProbe reports only non-secret, non-authorizing evidence.
// Every anonymous file is CLOSED before returning; no rule/core pathname,
// plaintext SQLite file, executable or restore transaction is created.
type InertRestoreAnonymousProbe struct {
	ArchiveSHA256         string
	InventorySHA256       string
	RuleSetCount          int
	RuleSetBytes          int64
	CoreIncluded          bool
	CoreBytes             int64
	AnonymousFilesChecked bool
	RestoreSupported      bool
	RestoreReady          bool
}

// ProbeAnonymousResources streams each authenticated rule and optional core
// into a PRIVATE, UNLINKED Linux O_TMPFILE inode, rehashes it, then closes it.
// The caller supplies a separate existing UID-owned 0700 directory supporting
// O_TMPFILE. Unsupported filesystems fail closed; NO named-file fallback.
// The SQLite record is inspected in memory by the preceding Revalidate.
// Nothing can be retained for an activation or used as an actual restore.
func (l *InertRestoreResourceLease) ProbeAnonymousResources(
	ctx context.Context, scratchParent string, key [32]byte,
) (InertRestoreAnonymousProbe, error) {
	return l.probeAnonymousResources(ctx, scratchParent, key, nil)
}

// afterStage is a private fault-injection hook, never a daemon/API entrypoint.
func (l *InertRestoreResourceLease) probeAnonymousResources(
	ctx context.Context, scratchParent string, key [32]byte,
	afterStage func() error,
) (InertRestoreAnonymousProbe, error) {
	var none InertRestoreAnonymousProbe
	if l == nil || ctx == nil || key == ([32]byte{}) ||
		!filepath.IsAbs(scratchParent) || filepath.Clean(scratchParent) != scratchParent ||
		verifySealedArchiveParent(scratchParent) != nil {
		return none, ErrInertRestoreAnonymousProbe
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()

	// Keep the actual directory flock throughout both live CAS checks and
	// the entire streaming probe. Close cannot race between them.
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.revalidateLocked(bounded, key); err != nil {
		return none, ErrInertRestoreAnonymousProbe
	}
	if scratchParent == l.candidate.directory ||
		scratchParent == l.candidate.parent ||
		scratchParent == filepath.Dir(l.candidate.parent) ||
		strings.HasPrefix(scratchParent, l.candidate.parent+string(os.PathSeparator)) {
		return none, ErrInertRestoreAnonymousProbe
	}
	scratch, identity, err := openAnonymousScratchParent(scratchParent)
	if err != nil {
		return none, ErrInertRestoreAnonymousProbe
	}
	defer scratch.Close()

	receipt := SealedArchiveReceipt{
		ArchiveSHA256:   l.record.ArchiveSHA256,
		InventorySHA256: l.record.InventorySHA256,
		Bytes:           l.record.ArchiveBytes,
		Format:          l.candidate.receipt.Format,
	}
	inventory, err := readAuthenticatedInventory(
		bounded, l.candidate.archive, key, receipt)
	if err != nil {
		return none, ErrInertRestoreAnonymousProbe
	}
	var ruleBytes, coreBytes int64
	for _, rule := range inventory.RuleSets {
		ruleBytes += rule.Size
	}
	if inventory.Core != nil {
		coreBytes = inventory.Core.Size
	}
	if ruleBytes+coreBytes > 0 &&
		requireSealedArchiveSpace(scratchParent, ruleBytes+coreBytes) != nil {
		return none, ErrInertRestoreAnonymousProbe
	}
	if err := streamAnonymousArchiveResources(
		bounded, l.candidate.archive, key, receipt, inventory, scratch); err != nil {
		return none, ErrInertRestoreAnonymousProbe
	}
	if afterStage != nil && afterStage() != nil {
		return none, ErrInertRestoreAnonymousProbe
	}
	if verifyAnonymousScratchParent(scratchParent, scratch, identity) != nil ||
		l.revalidateLocked(bounded, key) != nil ||
		verifyAnonymousScratchParent(scratchParent, scratch, identity) != nil ||
		bounded.Err() != nil {
		return none, ErrInertRestoreAnonymousProbe
	}
	return InertRestoreAnonymousProbe{
		ArchiveSHA256:         receipt.ArchiveSHA256,
		InventorySHA256:       receipt.InventorySHA256,
		RuleSetCount:          len(inventory.RuleSets),
		RuleSetBytes:          ruleBytes,
		CoreIncluded:          inventory.Core != nil,
		CoreBytes:             coreBytes,
		AnonymousFilesChecked: true,
		RestoreSupported:      false,
		RestoreReady:          false,
	}, nil
}

func openAnonymousScratchParent(path string) (*os.File, os.FileInfo, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|
		unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, ErrInertRestoreAnonymousProbe
	}
	dir := os.NewFile(uintptr(fd), path)
	if dir == nil {
		_ = unix.Close(fd)
		return nil, nil, ErrInertRestoreAnonymousProbe
	}
	info, err := dir.Stat()
	if err != nil || verifyAnonymousScratchParent(path, dir, info) != nil {
		_ = dir.Close()
		return nil, nil, ErrInertRestoreAnonymousProbe
	}
	return dir, info, nil
}

func verifyAnonymousScratchParent(path string, dir *os.File, original os.FileInfo) error {
	if dir == nil || original == nil || verifySealedArchiveParent(path) != nil {
		return ErrInertRestoreAnonymousProbe
	}
	atFD, err := dir.Stat()
	if err != nil || !atFD.IsDir() || atFD.Mode().Perm() != 0o700 ||
		!os.SameFile(original, atFD) {
		return ErrInertRestoreAnonymousProbe
	}
	atPath, err := os.Lstat(path)
	if err != nil || !os.SameFile(atFD, atPath) {
		return ErrInertRestoreAnonymousProbe
	}
	return nil
}

// This fourth whole-file read recomputes SHA and HMAC after staging resources.
// A mutation, swap or truncation prevents returning even an audit receipt.
func streamAnonymousArchiveResources(
	ctx context.Context, path string, key [32]byte,
	receipt SealedArchiveReceipt, expected Inventory, scratch *os.File,
) error {
	return streamAnonymousArchiveResourcesWithConsumer(
		ctx, path, key, receipt, expected, scratch,
		func(ctx context.Context, src io.Reader, dir *os.File, size int64, sha string, _ bool) error {
			return materializeOneAnonymousResource(ctx, src, dir, size, sha)
		})
}

// All consumers receive plaintext rule/core resource bytes from the exact
// MAC-verified and inventory-bound ciphertext stream. Callbacks MUST either
// close their anonymous descriptors or retain them in a non-authorizing
// in-process lease that cleans up on every partial failure.
func streamAnonymousArchiveResourcesWithConsumer(
	ctx context.Context, path string, key [32]byte,
	receipt SealedArchiveReceipt, expected Inventory, scratch *os.File,
	consume func(context.Context, io.Reader, *os.File, int64, string, bool) error,
) error {
	if ctx == nil || scratch == nil || consume == nil || key == ([32]byte{}) ||
		!validSealedArchivePath(path) || receipt.Bytes <= 0 ||
		!validLowerSHA(receipt.ArchiveSHA256) ||
		!validLowerSHA(receipt.InventorySHA256) {
		return ErrInertRestoreAnonymousProbe
	}
	file, err := openSealedArchiveNoFollow(path)
	if err != nil {
		return ErrInertRestoreAnonymousProbe
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || verifySealedFile(file, path, before, receipt.Bytes, true) != nil {
		return ErrInertRestoreAnonymousProbe
	}
	fullHash := sha256.New()
	reader := io.TeeReader(sealedContextReader{ctx: ctx, src: file}, fullHash)
	header := make([]byte, sealedArchiveHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil ||
		!bytes.Equal(header[:len(sealedArchiveMagic)], []byte(sealedArchiveMagic)) {
		return ErrInertRestoreAnonymousProbe
	}
	nonce := header[len(sealedArchiveMagic):]
	encryption, authentication := sealedKeys(key, nonce)
	block, err := aes.NewCipher(encryption)
	if err != nil {
		return ErrInertRestoreAnonymousProbe
	}
	mac := hmac.New(sha256.New, authentication)
	_, _ = mac.Write(header)
	cipherBytes := receipt.Bytes - int64(sealedArchiveHeaderBytes+sealedArchiveTagBytes)
	if cipherBytes <= 4 || cipherBytes > MaxSealedArchiveBytes {
		return ErrInertRestoreAnonymousProbe
	}
	limited := &io.LimitedReader{R: io.TeeReader(reader, mac), N: cipherBytes}
	plain := &cipher.StreamReader{S: cipher.NewCTR(block, nonce), R: limited}
	var length [4]byte
	if _, err := io.ReadFull(plain, length[:]); err != nil {
		return ErrInertRestoreAnonymousProbe
	}
	manifestLen := int(binary.BigEndian.Uint32(length[:]))
	if manifestLen <= 0 || manifestLen > maxManifestBytes {
		return ErrInertRestoreAnonymousProbe
	}
	manifest := make([]byte, manifestLen)
	if _, err := io.ReadFull(plain, manifest); err != nil ||
		shaHex(manifest) != receipt.InventorySHA256 {
		return ErrInertRestoreAnonymousProbe
	}
	inventory, err := ParseInertInventory(manifest, receipt.InventorySHA256)
	if err != nil || !reflect.DeepEqual(inventory, expected) ||
		inventory.Format != receipt.Format {
		return ErrInertRestoreAnonymousProbe
	}
	expectedPlain, err := sealedPlainBytes(inventory, manifestLen)
	if err != nil || expectedPlain != cipherBytes {
		return ErrInertRestoreAnonymousProbe
	}
	if err := hashSealedPlain(ctx, plain,
		inventory.DatabaseBytes, inventory.DatabaseSHA256); err != nil {
		return ErrInertRestoreAnonymousProbe
	}
	for _, rule := range inventory.RuleSets {
		if err := consume(ctx, plain, scratch,
			rule.Size, rule.SHA256, false); err != nil {
			return ErrInertRestoreAnonymousProbe
		}
	}
	if inventory.Core != nil {
		if err := consume(ctx, plain, scratch,
			inventory.Core.Size, inventory.Core.SHA256, true); err != nil {
			return ErrInertRestoreAnonymousProbe
		}
	}
	if limited.N != 0 {
		return ErrInertRestoreAnonymousProbe
	}
	tag := make([]byte, sealedArchiveTagBytes)
	if _, err := io.ReadFull(reader, tag); err != nil ||
		!hmac.Equal(mac.Sum(nil), tag) {
		return ErrInertRestoreAnonymousProbe
	}
	var trailing [1]byte
	if _, err := reader.Read(trailing[:]); !errors.Is(err, io.EOF) ||
		hex.EncodeToString(fullHash.Sum(nil)) != receipt.ArchiveSHA256 ||
		ctx.Err() != nil {
		return ErrInertRestoreAnonymousProbe
	}
	after, err := file.Stat()
	if err != nil || !sameLeasedFile(before, after) ||
		verifySealedFile(file, path, before, receipt.Bytes, true) != nil {
		return ErrInertRestoreAnonymousProbe
	}
	return nil
}

// Linux O_TMPFILE has no pathname. An unsupported filesystem is refused,
// rather than replacing this guarantee with a visible temporary file.
func materializeOneAnonymousResource(
	ctx context.Context, src io.Reader, scratch *os.File, size int64, expectedSHA string,
) (err error) {
	if ctx == nil || src == nil || scratch == nil || size <= 0 ||
		!validLowerSHA(expectedSHA) {
		return ErrInertRestoreAnonymousProbe
	}
	fd, err := unix.Openat(int(scratch.Fd()), ".",
		unix.O_TMPFILE|unix.O_RDWR|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return ErrInertRestoreAnonymousProbe
	}
	file := os.NewFile(uintptr(fd), "inert-anonymous-resource")
	if file == nil {
		_ = unix.Close(fd)
		return ErrInertRestoreAnonymousProbe
	}
	defer func() {
		if file.Close() != nil {
			err = ErrInertRestoreAnonymousProbe
		}
	}()
	before, err := file.Stat()
	if err != nil || !validAnonymousResourceFile(before, 0, 0o600) {
		return ErrInertRestoreAnonymousProbe
	}
	hash := sha256.New()
	n, err := io.CopyN(io.MultiWriter(file, hash),
		sealedContextReader{ctx: ctx, src: src}, size)
	if err != nil || n != size ||
		hex.EncodeToString(hash.Sum(nil)) != expectedSHA {
		return ErrInertRestoreAnonymousProbe
	}
	if file.Chmod(0o400) != nil || file.Sync() != nil {
		return ErrInertRestoreAnonymousProbe
	}
	after, err := file.Stat()
	if err != nil || !validAnonymousResourceFile(after, size, 0o400) ||
		!os.SameFile(before, after) {
		return ErrInertRestoreAnonymousProbe
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrInertRestoreAnonymousProbe
	}
	recheck := sha256.New()
	n, err = io.CopyN(recheck, sealedContextReader{ctx: ctx, src: file}, size)
	if err != nil || n != size ||
		hex.EncodeToString(recheck.Sum(nil)) != expectedSHA {
		return ErrInertRestoreAnonymousProbe
	}
	var extra [1]byte
	if _, err := file.Read(extra[:]); !errors.Is(err, io.EOF) {
		return ErrInertRestoreAnonymousProbe
	}
	final, err := file.Stat()
	if err != nil || !validAnonymousResourceFile(final, size, 0o400) ||
		!os.SameFile(after, final) || ctx.Err() != nil {
		return ErrInertRestoreAnonymousProbe
	}
	return nil
}

func validAnonymousResourceFile(info os.FileInfo, size int64, mode os.FileMode) bool {
	if info == nil || !info.Mode().IsRegular() || info.Mode().Perm() != mode ||
		info.Size() != size {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid() && st.Nlink == 0
}
