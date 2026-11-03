//go:build linux

package backupclosure

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
	"golang.org/x/sys/unix"
)

const (
	sealedArchiveMagic            = "KTUI-SEAL-AESCT1"
	sealedArchiveHeaderBytes      = len(sealedArchiveMagic) + aes.BlockSize
	sealedArchiveTagBytes         = sha256.Size
	sealedArchiveTimeout          = 90 * time.Second
	sealedArchiveFreeSpaceReserve = uint64(64 << 20)
	MaxSealedArchiveBytes         = storage.MaxDatabaseSnapshotBytes +
		MaxClosureRuleBytes + coreartifact.MaxPinnedCoreBytes +
		int64(maxManifestBytes+4+sealedArchiveHeaderBytes+sealedArchiveTagBytes)
)

var ErrUnsafeSealedArchive = errors.New("encrypted internal archive refused")

// SealedArchiveReceipt exposes only ciphertext and inventory digests, never
// credentials, file contents or the encryption key. It is not a restore permit.
type SealedArchiveReceipt struct {
	ArchiveSHA256   string
	InventorySHA256 string
	Bytes           int64
	Format          string
}

// SealInertArchive writes a bounded, authenticated encrypted copy of one
// already-pinned closure to a NEW private file. No plaintext archive is
// written, and no daemon/CLI/TUI route invokes this internal prerequisite.
// The caller MUST supply and securely retain a high-entropy unique 32-byte
// key; no passphrase KDF, key custody, restoration or scheduling is offered.
//
// v1 inventories remain identifiable as rules-only/incomplete. v2 includes
// the approved, non-executable core copy. Neither is restoration-ready.
func (c *Closure) SealInertArchive(
	ctx context.Context, destination string, key [32]byte,
) (receipt SealedArchiveReceipt, err error) {
	if ctx == nil || key == ([32]byte{}) || !validSealedArchivePath(destination) ||
		c == nil || c.Database == nil || c.closed {
		return receipt, ErrUnsafeSealedArchive
	}
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	parent := filepath.Dir(destination)
	if err := verifySealedArchiveParent(parent); err != nil ||
		parent == filepath.Dir(filepath.Dir(c.Database.Path)) {
		return receipt, ErrUnsafeSealedArchive
	}
	ctx, cancel := context.WithTimeout(ctx, sealedArchiveTimeout)
	defer cancel()
	if err := c.Verify(ctx); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	if len(c.InventoryJSON) == 0 ||
		c.InventorySHA256 != shaHex(c.InventoryJSON) {
		return receipt, ErrUnsafeSealedArchive
	}
	inventory, err := ParseInertInventory(c.InventoryJSON, c.InventorySHA256)
	if err != nil || inventory.Format != c.Inventory.Format {
		return receipt, ErrUnsafeSealedArchive
	}
	plainBytes, err := sealedPlainBytes(inventory, len(c.InventoryJSON))
	if err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	totalBytes := plainBytes + int64(sealedArchiveHeaderBytes+sealedArchiveTagBytes)
	if err := requireSealedArchiveSpace(parent, totalBytes); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	// Do not overwrite an existing backup, including a symlink. The atomic
	// no-replace hard-link below is authoritative against competing creators.
	if _, err := os.Lstat(destination); err == nil || !errors.Is(err, os.ErrNotExist) {
		return receipt, ErrUnsafeSealedArchive
	}
	// Before writing another archive, safely scavenge only unlocked v2
	// ciphertext staging files. No published archive is ever pruned.
	if _, err := ReclaimAbandonedSealedArchives(ctx, parent); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	file, err := createLeasedSealedArchiveTemp(ctx, parent, totalBytes)
	if err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	path := file.Name()
	identity, statErr := file.Stat()
	// Keep an independent descriptor for the parent inode containing this
	// exact temp file. The short quota-reservation flock has already ended;
	// this descriptor does not hold it across the expensive ciphertext IO.
	publishParent, pinErr := openSealedArchivePublicationParent(file)
	if pinErr != nil {
		_ = file.Close()
		return receipt, ErrUnsafeSealedArchive
	}
	published := false
	defer func() {
		// The file flock remains held until the final link/unlink/fsync
		// result. On a failed, pre-link write, remove only the original
		// known inode via parent fd; never os.Remove a mutable pathname.
		if !published {
			if cleanupErr := unlinkJustCreatedSealedTemp(publishParent, file); cleanupErr != nil {
				err = errors.Join(err, ErrUnsafeSealedArchive)
			}
		}
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, ErrUnsafeSealedArchive)
		}
		if closeErr := publishParent.Close(); closeErr != nil {
			err = errors.Join(err, ErrUnsafeSealedArchive)
		}
	}()
	if statErr != nil || file.Chmod(0o600) != nil ||
		verifySealedFile(file, path, identity, 0, false) != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	var nonce [aes.BlockSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	encryptKey, authKey := sealedKeys(key, nonce[:])
	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	mac := hmac.New(sha256.New, authKey)
	archiveHash := sha256.New()
	header := append([]byte(sealedArchiveMagic), nonce[:]...)
	if _, err := io.MultiWriter(file, mac, archiveHash).Write(header); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	stream := &cipher.StreamWriter{
		S: cipher.NewCTR(block, nonce[:]),
		W: io.MultiWriter(file, mac, archiveHash),
	}
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(c.InventoryJSON)))
	if _, err := stream.Write(length[:]); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	if _, err := stream.Write(c.InventoryJSON); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	if err := copySealedSource(ctx, stream, c.Database.Path,
		c.Inventory.DatabaseBytes, c.Inventory.DatabaseSHA256, 0o600); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	for index, rule := range c.Inventory.RuleSets {
		if c.copies == nil || index >= len(c.pins) {
			return receipt, ErrUnsafeSealedArchive
		}
		copied, ok := c.copies.FileFor(c.pins[index].path)
		if !ok || copySealedSource(ctx, stream, copied,
			rule.Size, rule.SHA256, 0o400) != nil {
			return receipt, ErrUnsafeSealedArchive
		}
	}
	if c.Inventory.Core != nil {
		if c.copies == nil {
			return receipt, ErrUnsafeSealedArchive
		}
		copied, ok := c.copies.CoreFile()
		if !ok || copySealedSource(ctx, stream, copied, c.Inventory.Core.Size,
			c.Inventory.Core.SHA256, 0o400) != nil {
			return receipt, ErrUnsafeSealedArchive
		}
	}
	if err := c.Verify(ctx); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	tag := mac.Sum(nil)
	if _, err := io.MultiWriter(file, archiveHash).Write(tag); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	if err := file.Sync(); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	if err := verifySealedFile(file, path, identity, totalBytes, true); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	// Link, remove the v2 temp name and fsync through the original
	// pinned parent inode. Once the hard link exists, even a later
	// refusal is an uncertain publication; NEVER blindly unlink it.
	linked, publishErr := publishSealedArchiveAtPinnedParentProbed(
		publishParent, file, destination, nil, nil)
	if linked {
		published = true
	}
	if publishErr != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	return SealedArchiveReceipt{
		ArchiveSHA256:   hex.EncodeToString(archiveHash.Sum(nil)),
		InventorySHA256: c.InventorySHA256,
		Bytes:           totalBytes,
		Format:          c.Inventory.Format,
	}, nil
}

// VerifyInertArchive authenticates the COMPLETE ciphertext, hashes every
// decrypted record into discard, and returns only nonsecret metadata. It never
// creates files or applies a generation. The MAC MUST be accepted before any
// future importer acts upon decrypted data.
func VerifyInertArchive(
	ctx context.Context, path string, key [32]byte,
) (receipt SealedArchiveReceipt, err error) {
	if ctx == nil || key == ([32]byte{}) || !validSealedArchivePath(path) {
		return receipt, ErrUnsafeSealedArchive
	}
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	ctx, cancel := context.WithTimeout(ctx, sealedArchiveTimeout)
	defer cancel()
	if err := verifySealedArchiveParent(filepath.Dir(path)); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	file, err := openSealedArchiveNoFollow(path)
	if err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || verifySealedFile(file, path, info, 0, false) != nil ||
		info.Size() <= int64(sealedArchiveHeaderBytes+sealedArchiveTagBytes+4) ||
		info.Size() > MaxSealedArchiveBytes {
		return receipt, ErrUnsafeSealedArchive
	}
	archiveHash := sha256.New()
	reader := io.TeeReader(file, archiveHash)
	header := make([]byte, sealedArchiveHeaderBytes)
	if _, err := io.ReadFull(reader, header); err != nil ||
		string(header[:len(sealedArchiveMagic)]) != sealedArchiveMagic {
		return receipt, ErrUnsafeSealedArchive
	}
	nonce := header[len(sealedArchiveMagic):]
	encryptKey, authKey := sealedKeys(key, nonce)
	block, err := aes.NewCipher(encryptKey)
	if err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	mac := hmac.New(sha256.New, authKey)
	if _, err := mac.Write(header); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	cipherBytes := info.Size() - int64(sealedArchiveHeaderBytes+sealedArchiveTagBytes)
	limited := &io.LimitedReader{R: io.TeeReader(reader, mac), N: cipherBytes}
	plain := &cipher.StreamReader{S: cipher.NewCTR(block, nonce), R: limited}
	var length [4]byte
	if _, err := io.ReadFull(plain, length[:]); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	n := binary.BigEndian.Uint32(length[:])
	if n == 0 || n > maxManifestBytes {
		return receipt, ErrUnsafeSealedArchive
	}
	encoded := make([]byte, int(n))
	if _, err := io.ReadFull(plain, encoded); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	inventory, err := ParseInertInventory(encoded, shaHex(encoded))
	if err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	expected, err := sealedPlainBytes(inventory, len(encoded))
	if err != nil || expected != cipherBytes {
		return receipt, ErrUnsafeSealedArchive
	}
	if err := hashSealedPlain(ctx, plain,
		inventory.DatabaseBytes, inventory.DatabaseSHA256); err != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	for _, rule := range inventory.RuleSets {
		if err := hashSealedPlain(ctx, plain, rule.Size, rule.SHA256); err != nil {
			return receipt, ErrUnsafeSealedArchive
		}
	}
	if inventory.Core != nil {
		if err := hashSealedPlain(ctx, plain,
			inventory.Core.Size, inventory.Core.SHA256); err != nil {
			return receipt, ErrUnsafeSealedArchive
		}
	}
	if limited.N != 0 {
		return receipt, ErrUnsafeSealedArchive
	}
	tag := make([]byte, sealedArchiveTagBytes)
	if _, err := io.ReadFull(reader, tag); err != nil ||
		!hmac.Equal(mac.Sum(nil), tag) {
		return receipt, ErrUnsafeSealedArchive
	}
	var trailing [1]byte
	if _, err := reader.Read(trailing[:]); !errors.Is(err, io.EOF) {
		return receipt, ErrUnsafeSealedArchive
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(info, after) ||
		info.Size() != after.Size() || info.Mode() != after.Mode() ||
		!info.ModTime().Equal(after.ModTime()) ||
		verifySealedFile(file, path, info, info.Size(), true) != nil ||
		ctx.Err() != nil {
		return receipt, ErrUnsafeSealedArchive
	}
	return SealedArchiveReceipt{
		ArchiveSHA256:   hex.EncodeToString(archiveHash.Sum(nil)),
		InventorySHA256: shaHex(encoded),
		Bytes:           info.Size(),
		Format:          inventory.Format,
	}, nil
}

func sealedKeys(master [32]byte, nonce []byte) (encryption, authentication []byte) {
	derive := func(label string) []byte {
		mac := hmac.New(sha256.New, master[:])
		_, _ = mac.Write([]byte("karing-tui-v2/internal-sealed-archive-v1/" + label))
		_, _ = mac.Write(nonce)
		return mac.Sum(nil)
	}
	return derive("encryption"), derive("authentication")
}

func sealedPlainBytes(inventory Inventory, manifestBytes int) (int64, error) {
	if validateInertInventory(inventory) != nil || manifestBytes <= 0 ||
		manifestBytes > maxManifestBytes {
		return 0, ErrUnsafeSealedArchive
	}
	n := int64(4+manifestBytes) + inventory.DatabaseBytes
	for _, rule := range inventory.RuleSets {
		n += rule.Size
	}
	if inventory.Core != nil {
		n += inventory.Core.Size
	}
	if n <= 0 || n+int64(sealedArchiveHeaderBytes+sealedArchiveTagBytes) > MaxSealedArchiveBytes {
		return 0, ErrUnsafeSealedArchive
	}
	return n, nil
}

type sealedContextReader struct {
	ctx context.Context
	src io.Reader
}

func (r sealedContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.src.Read(p)
}

func hashSealedPlain(ctx context.Context, src io.Reader, size int64, expected string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	hash := sha256.New()
	n, err := io.CopyN(hash, sealedContextReader{ctx: ctx, src: src}, size)
	if err != nil || n != size || hex.EncodeToString(hash.Sum(nil)) != expected {
		return ErrUnsafeSealedArchive
	}
	return ctx.Err()
}

func copySealedSource(
	ctx context.Context, dst io.Writer, path string, size int64, expected string, mode os.FileMode,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := openSealedArchiveNoFollow(path)
	if err != nil {
		return ErrUnsafeSealedArchive
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() ||
		before.Mode().Perm() != mode || before.Size() != size ||
		!singleOwnedSealedFile(before) {
		return ErrUnsafeSealedArchive
	}
	atPath, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, atPath) {
		return ErrUnsafeSealedArchive
	}
	hasher := sha256.New()
	n, err := io.CopyN(io.MultiWriter(dst, hasher),
		sealedContextReader{ctx: ctx, src: file}, size)
	if err != nil || n != size || hex.EncodeToString(hasher.Sum(nil)) != expected {
		return ErrUnsafeSealedArchive
	}
	var extra [1]byte
	if _, err := file.Read(extra[:]); !errors.Is(err, io.EOF) {
		return ErrUnsafeSealedArchive
	}
	after, err := file.Stat()
	atPath, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(before, after) ||
		!os.SameFile(after, atPath) || before.Mode() != after.Mode() ||
		before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return ErrUnsafeSealedArchive
	}
	return ctx.Err()
}

func validSealedArchivePath(path string) bool {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	name := filepath.Base(path)
	if len(name) < len(".ktbackup")+1 || len(name) > 128 ||
		!strings.HasSuffix(name, ".ktbackup") {
		return false
	}
	for i, ch := range name {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' ||
			ch >= '0' && ch <= '9' || (i != 0 && (ch == '-' || ch == '_' || ch == '.')) {
			continue
		}
		return false
	}
	return true
}

func verifySealedArchiveParent(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafeSealedArchive
		}
		if current == path {
			identity, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int(identity.Uid) != os.Getuid() ||
				info.Mode().Perm() != 0o700 {
				return ErrUnsafeSealedArchive
			}
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

func singleOwnedSealedFile(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Getuid() && st.Nlink == 1
}

func openSealedArchiveNoFollow(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafeSealedArchive
	}
	return os.NewFile(uintptr(fd), path), nil
}

func verifySealedFile(
	file *os.File, path string, original os.FileInfo, length int64, exact bool,
) error {
	if file == nil || original == nil {
		return ErrUnsafeSealedArchive
	}
	atFD, err := file.Stat()
	if err != nil || !atFD.Mode().IsRegular() || atFD.Mode().Perm() != 0o600 ||
		!singleOwnedSealedFile(atFD) || !os.SameFile(original, atFD) {
		return ErrUnsafeSealedArchive
	}
	atPath, err := os.Lstat(path)
	if err != nil || !os.SameFile(atFD, atPath) {
		return ErrUnsafeSealedArchive
	}
	if exact && atFD.Size() != length {
		return ErrUnsafeSealedArchive
	}
	return nil
}

// openSealedArchivePublicationParent pins the private directory inode
// which currently owns the exact live writer's temp file. Do NOT acquire
// an exclusive parent flock across the expensive archive copy: active
// writers need concurrent reservations; the new fd is only an identity
// and durability anchor. Unknown or moved paths are refused.
func openSealedArchivePublicationParent(file *os.File) (*os.File, error) {
	if file == nil || !recognizedSealedArchiveTemporary(filepath.Base(file.Name())) {
		return nil, ErrUnsafeSealedArchive
	}
	parentPath := filepath.Dir(file.Name())
	if verifySealedArchiveParent(parentPath) != nil {
		return nil, ErrUnsafeSealedArchive
	}
	fd, err := syscall.Open(parentPath,
		syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafeSealedArchive
	}
	parent := os.NewFile(uintptr(fd), parentPath)
	if parent == nil {
		_ = syscall.Close(fd)
		return nil, ErrUnsafeSealedArchive
	}
	if !sameLeasedSealedArchiveParent(parentPath, parent) ||
		!sameSealedArchiveWriterEntry(parent, file, true) {
		_ = parent.Close()
		return nil, ErrUnsafeSealedArchive
	}
	return parent, nil
}

// sameSealedArchiveWriterEntry verifies that a temp directory entry
// opened via the pinned parent fd is still the current writer inode.
// After a hard-link publication the source has two links until cleanup;
// pre-publication checks require exactly one.
func sameSealedArchiveWriterEntry(parent, file *os.File, requireSingleLink bool) bool {
	if parent == nil || file == nil || filepath.Dir(file.Name()) != parent.Name() ||
		!recognizedSealedArchiveTemporary(filepath.Base(file.Name())) ||
		!sameLeasedSealedArchiveParent(parent.Name(), parent) {
		return false
	}
	fd, err := syscall.Openat(int(parent.Fd()), filepath.Base(file.Name()),
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	child := os.NewFile(uintptr(fd), file.Name())
	if child == nil {
		_ = syscall.Close(fd)
		return false
	}
	onEntry, statErr := child.Stat()
	closeErr := child.Close()
	onFile, fileErr := file.Stat()
	onPath, pathErr := os.Lstat(file.Name())
	if statErr != nil || closeErr != nil || fileErr != nil || pathErr != nil ||
		!onEntry.Mode().IsRegular() || onEntry.Mode().Perm() != 0o600 ||
		!os.SameFile(onEntry, onFile) || !os.SameFile(onFile, onPath) {
		return false
	}
	info, ok := onEntry.Sys().(*syscall.Stat_t)
	if !ok || int(info.Uid) != os.Getuid() ||
		(requireSingleLink && info.Nlink != 1) ||
		(!requireSingleLink && info.Nlink != 2) {
		return false
	}
	return sameLeasedSealedArchiveParent(parent.Name(), parent)
}

// publishSealedArchiveAtPinnedParentProbed hard-links an authenticated,
// fsynced sealed temp into a previously absent archive filename. Only the
// package-private hooks inject filesystem path drift at deterministic
// boundaries; production always calls them nil.
func publishSealedArchiveAtPinnedParentProbed(
	parent, file *os.File, destination string, beforeLink, afterLink func(),
) (linked bool, err error) {
	if parent == nil || file == nil || !validSealedArchivePath(destination) ||
		filepath.Dir(destination) != parent.Name() ||
		!sameSealedArchiveWriterEntry(parent, file, true) {
		return false, ErrUnsafeSealedArchive
	}
	// Linkat(O_EXCL semantics) is authoritative: even if a competing
	// publisher creates this name after the precheck, it is never replaced.
	if _, err := os.Lstat(destination); err == nil || !errors.Is(err, os.ErrNotExist) {
		return false, ErrUnsafeSealedArchive
	}
	if beforeLink != nil {
		beforeLink()
	}
	tempName := filepath.Base(file.Name())
	destName := filepath.Base(destination)
	if err := unix.Linkat(int(parent.Fd()), tempName, int(parent.Fd()), destName, 0); err != nil {
		return false, ErrUnsafeSealedArchive
	}
	// The destination hard link now exists. Do not clean it up, even if
	// subsequent identity/durability checks fail or the parent was moved.
	linked = true
	if afterLink != nil {
		afterLink()
	}
	if !sameLeasedSealedArchiveParent(parent.Name(), parent) ||
		!sameSealedArchiveWriterEntry(parent, file, false) {
		return true, ErrUnsafeSealedArchive
	}
	fd, err := syscall.Openat(int(parent.Fd()), destName,
		syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return true, ErrUnsafeSealedArchive
	}
	dest := os.NewFile(uintptr(fd), destination)
	if dest == nil {
		_ = syscall.Close(fd)
		return true, ErrUnsafeSealedArchive
	}
	atDest, statErr := dest.Stat()
	closeErr := dest.Close()
	atFile, fileErr := file.Stat()
	onPath, pathErr := os.Lstat(destination)
	if statErr != nil || closeErr != nil || fileErr != nil || pathErr != nil ||
		!os.SameFile(atDest, atFile) || !os.SameFile(atDest, onPath) ||
		!sameLeasedSealedArchiveParent(parent.Name(), parent) {
		return true, ErrUnsafeSealedArchive
	}
	// Retain the writer's flock through this fd-relative temp unlink and
	// durability barrier, preventing the guarded reclaimer from racing it.
	if err := unix.Unlinkat(int(parent.Fd()), tempName, 0); err != nil {
		return true, ErrUnsafeSealedArchive
	}
	if err := parent.Sync(); err != nil ||
		!sameLeasedSealedArchiveParent(parent.Name(), parent) {
		return true, ErrUnsafeSealedArchive
	}
	return true, nil
}

func requireSealedArchiveSpace(parent string, bytes int64) error {
	var free syscall.Statfs_t
	if bytes <= 0 || syscall.Statfs(parent, &free) != nil || free.Bsize <= 0 {
		return ErrUnsafeSealedArchive
	}
	blockBytes := uint64(free.Bsize)
	required := uint64(bytes) + sealedArchiveFreeSpaceReserve
	blocks := required / blockBytes
	if required%blockBytes != 0 {
		blocks++
	}
	if free.Bavail < blocks {
		return ErrUnsafeSealedArchive
	}
	return nil
}

func syncSealedArchiveDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return ErrUnsafeSealedArchive
	}
	return errors.Join(dir.Sync(), dir.Close())
}
