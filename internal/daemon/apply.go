package daemon

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type applyStore interface {
	PrepareApply(context.Context, uint64, []byte) (storage.Attempt, error)
	GenerationConfig(context.Context, int64) ([]byte, string, error)
	AbortPrepared(context.Context, int64, string) error
	BeginActivation(context.Context, int64) error
	BeginVerification(context.Context, int64) error
	BeginRollback(context.Context, int64, string) error
	FinishRollback(context.Context, int64) error
	FailRollback(context.Context, int64, string) error
	CommitApplied(context.Context, int64, bool) error
}

type metadataApplyStore interface {
	PrepareApplyWithMetadata(context.Context, uint64, []byte, []byte, []byte) (storage.Attempt, error)
}

type CompiledGenerationArtifacts struct {
	Config    []byte
	Manifest  []byte
	SourceMap []byte
}

type Generation struct {
	ID     int64
	Config []byte
	SHA256 string
}

type applyCore interface {
	Check(context.Context, Generation) error
	Activate(context.Context, Generation) error
	Verify(context.Context, Generation) error
	Rollback(context.Context, *Generation) error
}

type ApplyPolicy struct {
	StateTimeout    time.Duration
	CheckTimeout    time.Duration
	ActivateTimeout time.Duration
	VerifyTimeout   time.Duration
	RollbackTimeout time.Duration
}

func DefaultApplyPolicy() ApplyPolicy {
	return ApplyPolicy{
		StateTimeout:    5 * time.Second,
		CheckTimeout:    15 * time.Second,
		ActivateTimeout: 15 * time.Second,
		VerifyTimeout:   10 * time.Second,
		RollbackTimeout: 15 * time.Second,
	}
}

func (p ApplyPolicy) Validate() error {
	if p.StateTimeout <= 0 {
		return errors.New("apply state timeout must be positive")
	}
	if p.CheckTimeout <= 0 {
		return errors.New("apply check timeout must be positive")
	}
	if p.ActivateTimeout <= 0 {
		return errors.New("apply activation timeout must be positive")
	}
	if p.VerifyTimeout <= 0 {
		return errors.New("apply verification timeout must be positive")
	}
	if p.RollbackTimeout <= 0 {
		return errors.New("apply rollback timeout must be positive")
	}
	return nil
}

type ApplyCoordinator struct {
	store  applyStore
	core   applyCore
	policy ApplyPolicy
}

func NewApplyCoordinator(store applyStore, core applyCore, policy ApplyPolicy) (*ApplyCoordinator, error) {
	if store == nil {
		return nil, errors.New("apply store is nil")
	}
	if core == nil {
		return nil, errors.New("apply core is nil")
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return &ApplyCoordinator{store: store, core: core, policy: policy}, nil
}

func (c *ApplyCoordinator) Apply(ctx context.Context, expectedRevision uint64, config []byte) (storage.Attempt, error) {
	return c.applyPrepared(ctx, expectedRevision, config, func(prepareCtx context.Context) (storage.Attempt, error) {
		return c.store.PrepareApply(prepareCtx, expectedRevision, config)
	})
}

func (c *ApplyCoordinator) ApplyCompiled(
	ctx context.Context,
	expectedRevision uint64,
	artifacts CompiledGenerationArtifacts,
) (storage.Attempt, error) {
	store, ok := c.store.(metadataApplyStore)
	if !ok {
		return storage.Attempt{}, errors.New("apply store does not support generation metadata")
	}
	config := append([]byte(nil), artifacts.Config...)
	manifest := append([]byte(nil), artifacts.Manifest...)
	sourceMap := append([]byte(nil), artifacts.SourceMap...)
	return c.applyPrepared(ctx, expectedRevision, config, func(prepareCtx context.Context) (storage.Attempt, error) {
		return store.PrepareApplyWithMetadata(prepareCtx, expectedRevision, config, manifest, sourceMap)
	})
}

func (c *ApplyCoordinator) applyPrepared(
	ctx context.Context,
	expectedRevision uint64,
	config []byte,
	prepare func(context.Context) (storage.Attempt, error),
) (storage.Attempt, error) {
	attempt, err := prepare(ctx)
	if err != nil {
		return storage.Attempt{}, err
	}

	candidate := Generation{
		ID:     attempt.GenerationID,
		Config: append([]byte(nil), config...),
		SHA256: attempt.ConfigSHA256,
	}

	previous, err := c.previousGeneration(ctx, attempt.PreviousGenerationID)
	if err != nil {
		cleanupErr := c.abortPrepared(ctx, attempt.ID, fmt.Sprintf("load previous generation: %v", err))
		return attempt, errors.Join(fmt.Errorf("load previous applied generation: %w", err), cleanupErr)
	}

	if err := c.withTimeout(ctx, c.policy.CheckTimeout, func(opCtx context.Context) error {
		return c.core.Check(opCtx, candidate)
	}); err != nil {
		cause := fmt.Errorf("candidate check failed: %w", err)
		cleanupErr := c.abortPrepared(ctx, attempt.ID, cause.Error())
		return attempt, errors.Join(cause, cleanupErr)
	}

	if err := c.stateStep(ctx, func(stateCtx context.Context) error {
		return c.store.BeginActivation(stateCtx, attempt.ID)
	}); err != nil {
		cleanupErr := c.abortPrepared(ctx, attempt.ID, fmt.Sprintf("record activation intent: %v", err))
		return attempt, errors.Join(fmt.Errorf("record activation intent: %w", err), cleanupErr)
	}

	if err := c.withTimeout(ctx, c.policy.ActivateTimeout, func(opCtx context.Context) error {
		return c.core.Activate(opCtx, candidate)
	}); err != nil {
		cause := fmt.Errorf("activate candidate generation: %w", err)
		return attempt, errors.Join(cause, c.rollback(ctx, attempt, previous, cause))
	}

	if err := c.stateStep(ctx, func(stateCtx context.Context) error {
		return c.store.BeginVerification(stateCtx, attempt.ID)
	}); err != nil {
		cause := fmt.Errorf("record verification phase: %w", err)
		return attempt, errors.Join(cause, c.rollback(ctx, attempt, previous, cause))
	}

	if err := c.withTimeout(ctx, c.policy.VerifyTimeout, func(opCtx context.Context) error {
		return c.core.Verify(opCtx, candidate)
	}); err != nil {
		cause := fmt.Errorf("verify candidate generation: %w", err)
		return attempt, errors.Join(cause, c.rollback(ctx, attempt, previous, cause))
	}

	if err := c.stateStep(ctx, func(stateCtx context.Context) error {
		return c.store.CommitApplied(stateCtx, attempt.ID, true)
	}); err != nil {
		cause := fmt.Errorf("commit verified generation: %w", err)
		return attempt, errors.Join(cause, c.rollback(ctx, attempt, previous, cause))
	}

	return attempt, nil
}

func (c *ApplyCoordinator) previousGeneration(ctx context.Context, generationID *int64) (*Generation, error) {
	if generationID == nil {
		return nil, nil
	}
	var (
		config []byte
		hash   string
		err    error
	)
	err = c.withTimeout(ctx, c.policy.StateTimeout, func(opCtx context.Context) error {
		config, hash, err = c.store.GenerationConfig(opCtx, *generationID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &Generation{
		ID:     *generationID,
		Config: append([]byte(nil), config...),
		SHA256: hash,
	}, nil
}

func (c *ApplyCoordinator) abortPrepared(ctx context.Context, attemptID int64, cause string) error {
	return c.cleanupStateStep(ctx, func(stateCtx context.Context) error {
		if err := c.store.AbortPrepared(stateCtx, attemptID, cause); err != nil {
			return fmt.Errorf("abort prepared generation: %w", err)
		}
		return nil
	})
}

func (c *ApplyCoordinator) rollback(ctx context.Context, attempt storage.Attempt, previous *Generation, cause error) error {
	var errs []error

	if err := c.cleanupStateStep(ctx, func(stateCtx context.Context) error {
		return c.store.BeginRollback(stateCtx, attempt.ID, cause.Error())
	}); err != nil {
		errs = append(errs, fmt.Errorf("record rollback intent: %w", err))
	}

	rollbackErr := c.withCleanupTimeout(ctx, c.policy.RollbackTimeout, func(rollbackCtx context.Context) error {
		return c.core.Rollback(rollbackCtx, previous)
	})
	if rollbackErr != nil {
		errs = append(errs, fmt.Errorf("restore previous generation: %w", rollbackErr))
		if err := c.cleanupStateStep(ctx, func(stateCtx context.Context) error {
			return c.store.FailRollback(stateCtx, attempt.ID, rollbackErr.Error())
		}); err != nil {
			errs = append(errs, fmt.Errorf("mark rollback failure: %w", err))
		}
		return errors.Join(errs...)
	}

	if err := c.cleanupStateStep(ctx, func(stateCtx context.Context) error {
		return c.store.FinishRollback(stateCtx, attempt.ID)
	}); err != nil {
		errs = append(errs, fmt.Errorf("record rollback completion: %w", err))
	}
	return errors.Join(errs...)
}

func (c *ApplyCoordinator) stateStep(ctx context.Context, step func(context.Context) error) error {
	return c.withTimeout(ctx, c.policy.StateTimeout, step)
}

func (c *ApplyCoordinator) cleanupStateStep(ctx context.Context, step func(context.Context) error) error {
	return c.withCleanupTimeout(ctx, c.policy.StateTimeout, step)
}

func (c *ApplyCoordinator) withTimeout(ctx context.Context, timeout time.Duration, operation func(context.Context) error) error {
	opCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return operation(opCtx)
}

func (c *ApplyCoordinator) withCleanupTimeout(ctx context.Context, timeout time.Duration, operation func(context.Context) error) error {
	base := context.WithoutCancel(ctx)
	opCtx, cancel := context.WithTimeout(base, timeout)
	defer cancel()
	return operation(opCtx)
}
