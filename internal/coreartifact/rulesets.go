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
	"syscall"
)

const MaxRuleSetUploadBytes int64 = 64 << 20

var (
	ErrRuleSetHashMismatch = errors.New("rule-set hash mismatch")
	ErrRuleSetImmutable    = errors.New("content-addressed rule-set is immutable")
	ErrUnsafeRuleSetPath   = errors.New("unsafe rule-set path")
	ErrRuleSetExtension    = errors.New("unsupported rule-set extension")
	ErrRuleSetNotFound     = errors.New("rule-set artifact not found")
	ErrRuleSetTooLarge     = errors.New("rule-set artifact exceeds size limit")
)

func (s *Store) PutRuleSet(
	ctx context.Context,
	content io.Reader,
	expectedSHA256 string,
	format string,
) (string, int64, error) {
	if content == nil {
		return "", 0, errors.New("rule-set content reader is nil")
	}
	extension, err := ruleSetExtension(format)
	if err != nil {
		return "", 0, err
	}
	return s.publishRuleSet(ctx, content, extension, expectedSHA256, MaxRuleSetUploadBytes)
}

func (s *Store) ResolveRuleSet(
	ctx context.Context,
	expectedSHA256 string,
	format string,
) (string, error) {
	extension, err := ruleSetExtension(format)
	if err != nil {
		return "", err
	}
	expected, err := normalizeSHA256(expectedSHA256)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	path := filepath.Join(s.root, "rule-sets", "sha256", expected+extension)
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("%w: %s %s", ErrRuleSetNotFound, format, expected)
		}
		return "", fmt.Errorf("inspect content-addressed rule-set: %w", err)
	}
	if err := VerifyRuleSet(path, expected); err != nil {
		return "", err
	}
	return path, nil
}

func (s *Store) publishRuleSet(
	ctx context.Context,
	content io.Reader,
	extension string,
	expectedSHA256 string,
	maxBytes int64,
) (string, int64, error) {
	expected, err := normalizeSHA256(expectedSHA256)
	if err != nil {
		return "", 0, err
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	if err := ensurePrivateDir(s.root); err != nil {
		return "", 0, err
	}
	ruleSetsDir := filepath.Join(s.root, "rule-sets")
	if err := ensurePrivateDir(ruleSetsDir); err != nil {
		return "", 0, err
	}
	shaDir := filepath.Join(ruleSetsDir, "sha256")
	if err := ensurePrivateDir(shaDir); err != nil {
		return "", 0, err
	}

	destination := filepath.Join(shaDir, expected+extension)
	if info, err := os.Lstat(destination); err == nil {
		if err := VerifyRuleSet(destination, expected); err != nil {
			if errors.Is(err, ErrRuleSetHashMismatch) {
				return "", 0, ErrRuleSetImmutable
			}
			return "", 0, err
		}
		return destination, info.Size(), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", 0, fmt.Errorf("inspect content-addressed rule-set: %w", err)
	}

	tmp, err := os.CreateTemp(shaDir, ".ruleset-upload-*.tmp")
	if err != nil {
		return "", 0, fmt.Errorf("create rule-set upload temp file: %w", err)
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
		return "", 0, fmt.Errorf("secure rule-set upload temp file: %w", err)
	}

	hasher := sha256.New()
	reader := io.Reader(&contextReader{ctx: ctx, reader: content})
	if maxBytes > 0 {
		reader = io.LimitReader(reader, maxBytes+1)
	}
	written, err := io.Copy(io.MultiWriter(tmp, hasher), reader)
	if err != nil {
		_ = tmp.Close()
		return "", 0, fmt.Errorf("copy rule-set upload: %w", err)
	}
	if maxBytes > 0 && written > maxBytes {
		_ = tmp.Close()
		return "", 0, fmt.Errorf("%w: %d bytes > %d bytes", ErrRuleSetTooLarge, written, maxBytes)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != expected {
		_ = tmp.Close()
		return "", 0, fmt.Errorf("%w: got %s want %s", ErrRuleSetHashMismatch, actual, expected)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", 0, fmt.Errorf("sync rule-set upload temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", 0, fmt.Errorf("close rule-set upload temp file: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	if err := os.Link(tmpPath, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			if err := VerifyRuleSet(destination, expected); err != nil {
				if errors.Is(err, ErrRuleSetHashMismatch) {
					return "", 0, ErrRuleSetImmutable
				}
				return "", 0, err
			}
			info, statErr := os.Stat(destination)
			if statErr != nil {
				return "", 0, fmt.Errorf("inspect existing rule-set after publish race: %w", statErr)
			}
			return destination, info.Size(), nil
		}
		return "", 0, fmt.Errorf("publish content-addressed rule-set: %w", err)
	}
	if err := os.Remove(tmpPath); err != nil {
		return "", 0, fmt.Errorf("remove rule-set upload temp link: %w", err)
	}
	cleanup = false
	for _, dir := range []string{shaDir, ruleSetsDir, s.root} {
		if err := syncDir(dir); err != nil {
			return "", 0, err
		}
	}
	return destination, written, nil
}

func ruleSetExtension(format string) (string, error) {
	switch format {
	case "source":
		return ".json", nil
	case "binary":
		return ".srs", nil
	default:
		return "", fmt.Errorf("%w: format %q", ErrRuleSetExtension, format)
	}
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

func (s *Store) StageRuleSet(ctx context.Context, sourcePath, expectedSHA256 string) (string, error) {
	if sourcePath == "" || !filepath.IsAbs(sourcePath) || filepath.Clean(sourcePath) != sourcePath {
		return "", fmt.Errorf("%w: source path must be a clean absolute path", ErrUnsafeRuleSetPath)
	}
	extension := filepath.Ext(sourcePath)
	switch extension {
	case ".json", ".srs":
	default:
		return "", fmt.Errorf("%w: %q", ErrRuleSetExtension, extension)
	}
	expected, err := normalizeSHA256(expectedSHA256)
	if err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if err := ensurePrivateDir(s.root); err != nil {
		return "", err
	}
	ruleSetsDir := filepath.Join(s.root, "rule-sets")
	if err := ensurePrivateDir(ruleSetsDir); err != nil {
		return "", err
	}
	shaDir := filepath.Join(ruleSetsDir, "sha256")
	if err := ensurePrivateDir(shaDir); err != nil {
		return "", err
	}

	destination := filepath.Join(shaDir, expected+extension)
	if _, err := os.Lstat(destination); err == nil {
		if err := VerifyRuleSet(destination, expected); err != nil {
			if errors.Is(err, ErrRuleSetHashMismatch) {
				return "", ErrRuleSetImmutable
			}
			return "", err
		}
		return destination, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect content-addressed rule-set: %w", err)
	}

	source, err := openRuleSetSourceNoFollow(sourcePath)
	if err != nil {
		return "", err
	}
	defer source.Close()

	tmp, err := os.CreateTemp(shaDir, ".ruleset-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create rule-set temp file: %w", err)
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
		return "", fmt.Errorf("secure rule-set temp file: %w", err)
	}

	hasher := sha256.New()
	writer := io.MultiWriter(tmp, hasher)
	if _, err := io.Copy(writer, source); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("copy rule-set source: %w", err)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != expected {
		_ = tmp.Close()
		return "", fmt.Errorf("%w: got %s want %s", ErrRuleSetHashMismatch, actual, expected)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("sync rule-set temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close rule-set temp file: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}

	if err := os.Link(tmpPath, destination); err != nil {
		if errors.Is(err, os.ErrExist) {
			if err := VerifyRuleSet(destination, expected); err != nil {
				if errors.Is(err, ErrRuleSetHashMismatch) {
					return "", ErrRuleSetImmutable
				}
				return "", err
			}
			return destination, nil
		}
		return "", fmt.Errorf("publish content-addressed rule-set: %w", err)
	}
	if err := os.Remove(tmpPath); err != nil {
		return "", fmt.Errorf("remove rule-set temp link: %w", err)
	}
	cleanup = false

	for _, dir := range []string{shaDir, ruleSetsDir, s.root} {
		if err := syncDir(dir); err != nil {
			return "", err
		}
	}
	return destination, nil
}

func VerifyRuleSet(path, expectedSHA256 string) error {
	expected, err := normalizeSHA256(expectedSHA256)
	if err != nil {
		return err
	}
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: rule-set path must be a clean absolute path", ErrUnsafeRuleSetPath)
	}
	extension := filepath.Ext(path)
	switch extension {
	case ".json", ".srs":
	default:
		return fmt.Errorf("%w: %q", ErrRuleSetExtension, extension)
	}

	file, err := openPrivateRuleSetNoFollow(path)
	if err != nil {
		return err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("hash rule-set artifact: %w", err)
	}
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != expected {
		return fmt.Errorf("%w: got %s want %s", ErrRuleSetHashMismatch, actual, expected)
	}
	return nil
}

func openRuleSetSourceNoFollow(path string) (*os.File, error) {
	file, info, err := openRegularRuleSetNoFollow(path)
	if err != nil {
		return nil, err
	}
	_ = info
	return file, nil
}

func openPrivateRuleSetNoFollow(path string) (*os.File, error) {
	file, info, err := openRegularRuleSetNoFollow(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return nil, fmt.Errorf("%w: rule-set mode %04o is too permissive", ErrUnsafeRuleSetPath, info.Mode().Perm())
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: rule-set owner uid %d is not current uid %d", ErrUnsafeRuleSetPath, stat.Uid, os.Getuid())
	}
	return file, nil
}

func openRegularRuleSetNoFollow(path string) (*os.File, os.FileInfo, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: open rule-set without following symlink: %v", ErrUnsafeRuleSetPath, err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, nil, errors.New("wrap rule-set file descriptor")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("inspect rule-set artifact: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, fmt.Errorf("%w: rule-set is not a regular file", ErrUnsafeRuleSetPath)
	}
	return file, info, nil
}
