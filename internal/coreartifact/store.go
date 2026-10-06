package coreartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

var (
	ErrGenerationImmutable  = errors.New("generation config is immutable")
	ErrConfigHashMismatch   = errors.New("generation config hash mismatch")
	ErrUnsafeGenerationPath = errors.New("unsafe generation path")
)

type Store struct {
	root string
}

func NewStore(root string) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, errors.New("generation store root must be an absolute path")
	}
	return &Store{root: filepath.Clean(root)}, nil
}

func (s *Store) Stage(ctx context.Context, generationID int64, config []byte, expectedSHA256 string) (string, error) {
	if generationID <= 0 {
		return "", errors.New("generation id must be positive")
	}
	expected, err := normalizeSHA256(expectedSHA256)
	if err != nil {
		return "", err
	}
	actual := sha256.Sum256(config)
	if hex.EncodeToString(actual[:]) != expected {
		return "", ErrConfigHashMismatch
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	generationsDir := filepath.Join(s.root, "generations")
	if err := ensurePrivateDir(s.root); err != nil {
		return "", err
	}
	if err := ensurePrivateDir(generationsDir); err != nil {
		return "", err
	}

	generationDir := filepath.Join(generationsDir, strconv.FormatInt(generationID, 10))
	if err := ensurePrivateDir(generationDir); err != nil {
		return "", err
	}
	configPath := filepath.Join(generationDir, "config.json")

	if _, err := os.Lstat(configPath); err == nil {
		return verifyExistingConfig(configPath, expected)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect generation config: %w", err)
	}

	tmp, err := os.CreateTemp(generationDir, ".config-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create generation temp file: %w", err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("secure generation temp file: %w", err)
	}
	if _, err := tmp.Write(config); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write generation config: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("sync generation config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close generation config: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if err := os.Link(tmpPath, configPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return verifyExistingConfig(configPath, expected)
		}
		return "", fmt.Errorf("publish immutable generation config: %w", err)
	}
	if err := os.Remove(tmpPath); err != nil {
		return "", fmt.Errorf("remove generation temp link: %w", err)
	}
	cleanup = false

	for _, dir := range []string{generationDir, generationsDir, s.root} {
		if err := syncDir(dir); err != nil {
			return "", err
		}
	}
	return configPath, nil
}


func (s *Store) PruneStagedGenerations(ctx context.Context, protectedIDs []int64, keepRecent int) ([]int64, error) {
	if keepRecent < 0 {
		return nil, errors.New("generation retention must not be negative")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	generationsDir := filepath.Join(s.root, "generations")
	if _, err := os.Lstat(generationsDir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("inspect generation store: %w", err)
	}
	if err := ensurePrivateDir(s.root); err != nil {
		return nil, err
	}
	if err := ensurePrivateDir(generationsDir); err != nil {
		return nil, err
	}

	protected := make(map[int64]struct{}, len(protectedIDs)+keepRecent)
	for _, id := range protectedIDs {
		if id <= 0 {
			return nil, fmt.Errorf("protected generation id must be positive: %d", id)
		}
		protected[id] = struct{}{}
	}

	entries, err := os.ReadDir(generationsDir)
	if err != nil {
		return nil, fmt.Errorf("list staged generations: %w", err)
	}
	ids := make([]int64, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id, err := strconv.ParseInt(entry.Name(), 10, 64)
		if err != nil || id <= 0 || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
			return nil, fmt.Errorf("%w: unexpected generation-store entry %q", ErrUnsafeGenerationPath, entry.Name())
		}
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] > ids[j] })

	for index, id := range ids {
		if index >= keepRecent {
			break
		}
		protected[id] = struct{}{}
	}

	type prunePlan struct {
		id      int64
		dir     string
		entries []string
	}
	plans := make([]prunePlan, 0)
	for _, id := range ids {
		if _, keep := protected[id]; keep {
			continue
		}
		dir := filepath.Join(generationsDir, strconv.FormatInt(id, 10))
		names, err := validatePrunableGenerationDir(dir)
		if err != nil {
			return nil, err
		}
		plans = append(plans, prunePlan{id: id, dir: dir, entries: names})
	}

	removed := make([]int64, 0, len(plans))
	for _, plan := range plans {
		if err := ctx.Err(); err != nil {
			return removed, err
		}
		for _, name := range plan.entries {
			if err := os.Remove(filepath.Join(plan.dir, name)); err != nil {
				return removed, fmt.Errorf("remove staged generation %d entry %q: %w", plan.id, name, err)
			}
		}
		if err := syncDir(plan.dir); err != nil {
			return removed, err
		}
		if err := os.Remove(plan.dir); err != nil {
			return removed, fmt.Errorf("remove staged generation %d directory: %w", plan.id, err)
		}
		removed = append(removed, plan.id)
	}
	if len(removed) != 0 {
		if err := syncDir(generationsDir); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

func validatePrunableGenerationDir(path string) ([]string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect staged generation directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a real directory", ErrUnsafeGenerationPath, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: directory %s mode %04o is too permissive", ErrUnsafeGenerationPath, path, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%w: cannot verify ownership of %s", ErrUnsafeGenerationPath, path)
	}
	if int(stat.Uid) != os.Getuid() {
		return nil, fmt.Errorf("%w: directory %s is owned by uid %d", ErrUnsafeGenerationPath, path, stat.Uid)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("list staged generation directory %s: %w", path, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name != "config.json" && !(strings.HasPrefix(name, ".config-") && strings.HasSuffix(name, ".tmp")) {
			return nil, fmt.Errorf("%w: unexpected entry %q in %s", ErrUnsafeGenerationPath, name, path)
		}
		entryPath := filepath.Join(path, name)
		entryInfo, err := os.Lstat(entryPath)
		if err != nil {
			return nil, fmt.Errorf("inspect staged generation entry %s: %w", entryPath, err)
		}
		if entryInfo.Mode()&os.ModeSymlink != 0 || !entryInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: %s is not a regular file", ErrUnsafeGenerationPath, entryPath)
		}
		if entryInfo.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%w: file %s mode %04o is too permissive", ErrUnsafeGenerationPath, entryPath, entryInfo.Mode().Perm())
		}
		entryStat, ok := entryInfo.Sys().(*syscall.Stat_t)
		if !ok {
			return nil, fmt.Errorf("%w: cannot verify ownership of %s", ErrUnsafeGenerationPath, entryPath)
		}
		if int(entryStat.Uid) != os.Getuid() {
			return nil, fmt.Errorf("%w: file %s is owned by uid %d", ErrUnsafeGenerationPath, entryPath, entryStat.Uid)
		}
		names = append(names, name)
	}
	return names, nil
}

func (s *Store) ConfigPath(generationID int64) (string, error) {
	if generationID <= 0 {
		return "", errors.New("generation id must be positive")
	}
	return filepath.Join(s.root, "generations", strconv.FormatInt(generationID, 10), "config.json"), nil
}

func VerifyGenerationConfig(path, expectedSHA256 string) error {
	expected, err := normalizeSHA256(expectedSHA256)
	if err != nil {
		return err
	}
	if path == "" || !filepath.IsAbs(path) {
		return fmt.Errorf("%w: generation config path must be absolute", ErrUnsafeGenerationPath)
	}

	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("%w: open generation config without following symlink: %v", ErrUnsafeGenerationPath, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return errors.New("wrap generation config file descriptor")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect opened generation config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%w: generation config is not a regular file", ErrUnsafeGenerationPath)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: generation config mode %04o is too permissive", ErrUnsafeGenerationPath, info.Mode().Perm())
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%w: generation config owner uid %d is not current uid %d", ErrUnsafeGenerationPath, stat.Uid, os.Getuid())
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("hash generation config: %w", err)
	}
	if hex.EncodeToString(hasher.Sum(nil)) != expected {
		return ErrConfigHashMismatch
	}
	return nil
}

func verifyExistingConfig(path, expected string) (string, error) {
	if err := VerifyGenerationConfig(path, expected); err != nil {
		if errors.Is(err, ErrConfigHashMismatch) {
			return "", ErrGenerationImmutable
		}
		return "", err
	}
	return path, nil
}

func ensurePrivateDir(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(path, 0o700); err != nil {
			return fmt.Errorf("create private directory %s: %w", path, err)
		}
		info, err = os.Lstat(path)
	}
	if err != nil {
		return fmt.Errorf("inspect private directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: %s is not a real directory", ErrUnsafeGenerationPath, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: directory %s mode %04o is too permissive", ErrUnsafeGenerationPath, path, info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot verify ownership of %s", ErrUnsafeGenerationPath, path)
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("%w: directory %s is owned by uid %d", ErrUnsafeGenerationPath, path, stat.Uid)
	}
	return nil
}

func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory %s for sync: %w", path, err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync directory %s: %w", path, err)
	}
	return nil
}

func normalizeSHA256(value string) (string, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		return "", errors.New("expected SHA-256 must be 64 hexadecimal characters")
	}
	return hex.EncodeToString(decoded), nil
}
