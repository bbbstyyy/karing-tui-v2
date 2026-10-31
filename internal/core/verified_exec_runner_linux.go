//go:build linux

package core

import (
	"context"
	"errors"
	"fmt"
)

type ArtifactVerifyFunc func(string) error

type VerifiedExecRunner struct {
	executable string
	verify     ArtifactVerifyFunc
	runner     *ExecRunner
}

func NewVerifiedExecRunner(config ExecConfig, verify ArtifactVerifyFunc) (*VerifiedExecRunner, error) {
	if verify == nil {
		return nil, errors.New("core artifact verifier is nil")
	}
	runner, err := NewExecRunner(config)
	if err != nil {
		return nil, err
	}
	return &VerifiedExecRunner{
		executable: config.Executable,
		verify:     verify,
		runner:     runner,
	}, nil
}

func (r *VerifiedExecRunner) Start(ctx context.Context) (Process, error) {
	if err := r.verify(r.executable); err != nil {
		return nil, fmt.Errorf("verify core artifact before start: %w", err)
	}
	return r.runner.Start(ctx)
}
