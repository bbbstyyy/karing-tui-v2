package runtimepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

const appName = "karing-tui-v2"

var ErrRuntimeDirUnavailable = errors.New("secure runtime directory unavailable")

type Paths struct {
	Config   string
	Data     string
	State    string
	Cache    string
	Runtime  string
	Socket   string
	Database string
}

func Resolve() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("resolve home directory: %w", err)
	}

	configBase := firstNonEmpty(os.Getenv("XDG_CONFIG_HOME"), filepath.Join(home, ".config"))
	dataBase := firstNonEmpty(os.Getenv("XDG_DATA_HOME"), filepath.Join(home, ".local", "share"))
	stateBase := firstNonEmpty(os.Getenv("XDG_STATE_HOME"), filepath.Join(home, ".local", "state"))
	cacheBase := firstNonEmpty(os.Getenv("XDG_CACHE_HOME"), filepath.Join(home, ".cache"))

	runtimeBase := os.Getenv("KARING_TUI_RUNTIME_DIR")
	if runtimeBase == "" {
		runtimeBase = os.Getenv("XDG_RUNTIME_DIR")
	}
	if runtimeBase == "" {
		return Paths{}, fmt.Errorf("%w: set XDG_RUNTIME_DIR or KARING_TUI_RUNTIME_DIR to a directory owned by the current user", ErrRuntimeDirUnavailable)
	}
	if err := validateOwnedPrivateDir(runtimeBase); err != nil {
		return Paths{}, fmt.Errorf("%w: %v", ErrRuntimeDirUnavailable, err)
	}

	configDir := filepath.Join(configBase, appName)
	dataDir := filepath.Join(dataBase, appName)
	stateDir := filepath.Join(stateBase, appName)
	cacheDir := filepath.Join(cacheBase, appName)
	runtimeDir := filepath.Join(runtimeBase, appName)
	return Paths{
		Config:   configDir,
		Data:     dataDir,
		State:    stateDir,
		Cache:    cacheDir,
		Runtime:  runtimeDir,
		Socket:   filepath.Join(runtimeDir, "daemon.sock"),
		Database: filepath.Join(stateDir, "state.db"),
	}, nil
}

func (p Paths) Ensure() error {
	for _, dir := range []string{p.Config, p.Data, p.State, p.Cache, p.Runtime} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := validateOwnedPrivateDir(dir); err != nil {
			return err
		}
	}
	return nil
}

func validateOwnedPrivateDir(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat runtime directory %s: %w", path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("runtime path %s is not a directory", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify ownership of %s", path)
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("runtime directory %s is owned by uid %d, expected uid %d", path, stat.Uid, os.Getuid())
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("runtime directory %s is writable by group or others (mode %04o)", path, info.Mode().Perm())
	}
	return nil
}

func firstNonEmpty(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
