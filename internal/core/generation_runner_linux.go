//go:build linux

package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
)

var ErrGenerationConfigUnset = errors.New("core generation config is not set")

type GenerationRunner struct {
	mu           sync.RWMutex
	executable   string
	verify       ArtifactVerifyFunc
	stdout       io.Writer
	stderr       io.Writer
	configPath   string
	configSHA256 string
}

func NewGenerationRunner(executable string, verify ArtifactVerifyFunc, stdout, stderr io.Writer) (*GenerationRunner, error) {
	if executable == "" || !filepath.IsAbs(executable) {
		return nil, errors.New("core executable must be an absolute path")
	}
	if verify == nil {
		return nil, errors.New("core artifact verifier is nil")
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	return &GenerationRunner{
		executable: executable,
		verify:     verify,
		stdout:     stdout,
		stderr:     stderr,
	}, nil
}

func (r *GenerationRunner) BindConfig(path, expectedSHA256 string) error {
	if err := coreartifact.VerifyGenerationConfig(path, expectedSHA256); err != nil {
		return err
	}
	r.mu.Lock()
	r.configPath = path
	r.configSHA256 = expectedSHA256
	r.mu.Unlock()
	return nil
}

func (r *GenerationRunner) BoundConfig() (string, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.configPath, r.configSHA256
}

func (r *GenerationRunner) Start(ctx context.Context) (Process, error) {
	configPath, configSHA256 := r.BoundConfig()
	if configPath == "" || configSHA256 == "" {
		return nil, ErrGenerationConfigUnset
	}
	if err := coreartifact.VerifyGenerationConfig(configPath, configSHA256); err != nil {
		return nil, fmt.Errorf("verify bound generation config before start: %w", err)
	}
	runner, err := NewVerifiedExecRunner(ExecConfig{
		Executable: r.executable,
		Args:       []string{"run", "-c", configPath},
		Dir:        filepath.Dir(configPath),
		Stdout:     r.stdout,
		Stderr:     r.stderr,
	}, r.verify)
	if err != nil {
		return nil, err
	}
	return runner.Start(ctx)
}

func CheckGenerationConfig(ctx context.Context, executable string, verify ArtifactVerifyFunc, configPath, expectedSHA256 string, stdout, stderr io.Writer) error {
	if executable == "" || !filepath.IsAbs(executable) {
		return errors.New("core executable must be an absolute path")
	}
	if verify == nil {
		return errors.New("core artifact verifier is nil")
	}
	if err := coreartifact.VerifyGenerationConfig(configPath, expectedSHA256); err != nil {
		return fmt.Errorf("verify generation config before check: %w", err)
	}
	if err := verify(executable); err != nil {
		return fmt.Errorf("verify core artifact before check: %w", err)
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	cmd := exec.CommandContext(ctx, executable, "check", "-c", configPath)
	cmd.Dir = filepath.Dir(configPath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("check generation config: %w", err)
	}
	return nil
}
