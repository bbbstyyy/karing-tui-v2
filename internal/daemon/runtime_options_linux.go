//go:build linux

package daemon

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
)

const (
	corePathEnv        = "KARING_TUI_CORE_PATH"
	coreControlPortEnv = "KARING_TUI_CORE_CONTROL_PORT"
	defaultControlPort = 3057
)

func resolveManagedCoreOptions(paths runtimepath.Paths) (*ManagedCoreOptions, error) {
	return resolveManagedCoreOptionsWithVerify(paths, coreartifact.Verify)
}

func resolveManagedCoreOptionsWithVerify(paths runtimepath.Paths, verify core.ArtifactVerifyFunc) (*ManagedCoreOptions, error) {
	executable := strings.TrimSpace(os.Getenv(corePathEnv))
	if executable == "" {
		return nil, nil
	}
	if !filepath.IsAbs(executable) {
		return nil, fmt.Errorf("%s must be an absolute path", corePathEnv)
	}
	if verify == nil {
		return nil, errors.New("core artifact verifier is nil")
	}
	if err := verify(executable); err != nil {
		return nil, fmt.Errorf("verify configured core artifact: %w", err)
	}

	inbounds := domain.DefaultInboundSet()
	if err := inbounds.Validate(); err != nil {
		return nil, fmt.Errorf("validate default proxy inbounds: %w", err)
	}
	controlPort, err := resolveControlPort(inbounds)
	if err != nil {
		return nil, err
	}
	controlAddress := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), controlPort)
	secretPath := filepath.Join(paths.State, "core-control.secret")
	secret, err := loadOrCreateControlSecret(secretPath)
	if err != nil {
		return nil, err
	}

	return &ManagedCoreOptions{
		Executable:      executable,
		StateRoot:       filepath.Join(paths.State, "core"),
		ControlEndpoint: "http://" + controlAddress.String(),
		ControlSecret:   secret,
		Inbounds:        inbounds,
		Policy:          core.DefaultPolicy(),
		LogCapacity:     256 << 10,
	}, nil
}

func resolveControlPort(inbounds domain.InboundSet) (uint16, error) {
	port := uint64(defaultControlPort)
	if raw := strings.TrimSpace(os.Getenv(coreControlPortEnv)); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || parsed == 0 {
			return 0, fmt.Errorf("%s must be an integer between 1 and 65535", coreControlPortEnv)
		}
		port = parsed
	}
	value := uint16(port)
	if value == inbounds.RulePort || value == inbounds.DirectPort || value == inbounds.SelectedPort {
		return 0, fmt.Errorf("%s conflicts with a proxy inbound port", coreControlPortEnv)
	}
	return value, nil
}

func loadOrCreateControlSecret(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("core control secret path must be absolute")
	}
	if err := ensureSecretParent(path); err != nil {
		return "", err
	}

	secret, err := readControlSecret(path)
	if err == nil {
		return secret, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}

	var random [32]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return "", fmt.Errorf("generate core control secret: %w", err)
	}
	secret = hex.EncodeToString(random[:])

	fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return readControlSecret(path)
		}
		return "", fmt.Errorf("create core control secret: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return "", errors.New("wrap core control secret file descriptor")
	}
	if _, err := file.WriteString(secret); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write core control secret: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("sync core control secret: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close core control secret: %w", err)
	}
	if err := syncPrivateDirectory(filepath.Dir(path)); err != nil {
		return "", err
	}
	return secret, nil
}

func readControlSecret(path string) (string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return "", os.ErrNotExist
		}
		return "", fmt.Errorf("open core control secret without following symlink: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return "", errors.New("wrap core control secret file descriptor")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect core control secret: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("core control secret is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("core control secret mode %04o is too permissive", info.Mode().Perm())
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return "", fmt.Errorf("core control secret owner uid %d is not current uid %d", stat.Uid, os.Getuid())
	}

	content, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil {
		return "", fmt.Errorf("read core control secret: %w", err)
	}
	if len(content) != 64 {
		return "", errors.New("core control secret must contain exactly 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(string(content)); err != nil {
		return "", errors.New("core control secret is not valid hexadecimal")
	}
	return string(content), nil
}

func ensureSecretParent(path string) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect core control secret directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("core control secret directory is not a real directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("core control secret directory mode %04o is too permissive", info.Mode().Perm())
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("core control secret directory owner uid %d is not current uid %d", stat.Uid, os.Getuid())
	}
	return nil
}

func syncPrivateDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open private directory for sync: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync private directory: %w", err)
	}
	return nil
}
