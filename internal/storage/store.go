package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const (
	MaxGenerationConfigBytes   = 64 << 20
	MaxGenerationMetadataBytes = 16 << 20
)

var (
	ErrInvalidConfig              = errors.New("invalid compiled configuration")
	ErrConfigTooLarge             = errors.New("compiled configuration exceeds size limit")
	ErrRevisionConflict           = errors.New("configuration revision conflict")
	ErrApplyInProgress            = errors.New("configuration apply already in progress")
	ErrRecoveryRequired           = errors.New("configuration recovery required")
	ErrAttemptNotFound            = errors.New("apply attempt not found")
	ErrInvalidTransition          = errors.New("invalid apply journal transition")
	ErrInvalidGenerationMetadata  = errors.New("invalid generation metadata")
	ErrGenerationMetadataTooLarge = errors.New("generation metadata exceeds size limit")
	ErrGenerationStorageBudget     = errors.New("generation storage budget exceeded")
)

var ErrInvalidCoreDesiredState = errors.New("invalid core desired state")

type Phase string

const (
	PhasePrepared    Phase = "prepared"
	PhaseActivating  Phase = "activating"
	PhaseVerifying   Phase = "verifying"
	PhaseRollingBack Phase = "rolling_back"
	PhaseCommitted   Phase = "committed"
	PhaseRolledBack  Phase = "rolled_back"
	PhaseFailed      Phase = "failed"
	PhaseInterrupted Phase = "interrupted"
)

type CoreDesiredState string

const CoreDesiredStopped CoreDesiredState = "stopped"
const CoreDesiredRunning CoreDesiredState = "running"

type Snapshot struct {
	Revision                  uint64
	AppliedGenerationID       *int64
	LastKnownGoodGenerationID *int64
	RecoveryRequired          bool
	CoreDesiredState          CoreDesiredState
	ActiveAttemptID           *int64
}

type Attempt struct {
	ID                   int64
	GenerationID         int64
	PreviousGenerationID *int64
	BaseRevision         uint64
	TargetRevision       uint64
	Phase                Phase
	ConfigSHA256         string
	Error                string
	StartedAt            time.Time
	UpdatedAt            time.Time
}

type Recovery struct {
	InterruptedAttemptIDs []int64
	NeedsReconcile        bool
	AppliedGenerationID   *int64
}

type GenerationArtifacts struct {
	ConfigJSON      []byte
	ConfigSHA256    string
	ManifestJSON    []byte
	ManifestSHA256  string
	SourceMapJSON   []byte
	SourceMapSHA256 string
}

type Store struct {
	db        *sql.DB
	path      string
	retention RetentionPolicy
}

func Open(ctx context.Context, path string) (*Store, error) {
	return OpenWithRetention(ctx, path, DefaultRetentionPolicy())
}

func OpenWithRetention(ctx context.Context, path string, retention RetentionPolicy) (*Store, error) {
	if err := retention.Validate(); err != nil {
		return nil, err
	}
	if err := prepareDatabaseFile(path); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite state database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	store := &Store{db: db, path: path, retention: retention}
	if err := store.configure(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := store.quickCheck(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) Path() string {
	return s.path
}

func (s *Store) Snapshot(ctx context.Context) (Snapshot, error) {
	var (
		revision         int64
		applied          sql.NullInt64
		lastKnownGood    sql.NullInt64
		recoveryRequired int
		coreDesired      string
	)
	if err := s.db.QueryRowContext(ctx, `
		SELECT config_revision, applied_generation_id, last_known_good_generation_id, recovery_required, core_desired_state
		FROM daemon_state
		WHERE singleton = 1
	`).Scan(&revision, &applied, &lastKnownGood, &recoveryRequired, &coreDesired); err != nil {
		return Snapshot{}, fmt.Errorf("read daemon state: %w", err)
	}

	var active sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `
		SELECT id
		FROM apply_journal
		WHERE active_slot = 1
		LIMIT 1
	`).Scan(&active); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Snapshot{}, fmt.Errorf("read active apply attempt: %w", err)
	}

	return Snapshot{
		Revision:                  uint64(revision),
		AppliedGenerationID:       nullInt64Ptr(applied),
		LastKnownGoodGenerationID: nullInt64Ptr(lastKnownGood),
		RecoveryRequired:          recoveryRequired != 0,
		CoreDesiredState:          CoreDesiredState(coreDesired),
		ActiveAttemptID:           nullInt64Ptr(active),
	}, nil
}

func (s *Store) SetCoreDesiredState(ctx context.Context, state CoreDesiredState) error {
	if state != CoreDesiredStopped && state != CoreDesiredRunning {
		return fmt.Errorf("%w: %q", ErrInvalidCoreDesiredState, state)
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE daemon_state
		SET core_desired_state = ?
		WHERE singleton = 1
	`, state)
	if err != nil {
		return fmt.Errorf("persist core desired state: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read core desired state update result: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("persist core desired state: updated %d daemon_state rows", affected)
	}
	return nil
}

func (s *Store) PrepareApply(ctx context.Context, expectedRevision uint64, config []byte) (Attempt, error) {
	return s.prepareApply(ctx, expectedRevision, config, nil, nil)
}

func (s *Store) PrepareApplyWithMetadata(
	ctx context.Context,
	expectedRevision uint64,
	config []byte,
	manifest []byte,
	sourceMap []byte,
) (Attempt, error) {
	if len(manifest) == 0 || !json.Valid(manifest) {
		return Attempt{}, fmt.Errorf("%w: manifest must be non-empty valid JSON", ErrInvalidGenerationMetadata)
	}
	if len(sourceMap) == 0 || !json.Valid(sourceMap) {
		return Attempt{}, fmt.Errorf("%w: source map must be non-empty valid JSON", ErrInvalidGenerationMetadata)
	}
	if len(manifest) > MaxGenerationMetadataBytes {
		return Attempt{}, fmt.Errorf("%w: manifest %d bytes > %d bytes", ErrGenerationMetadataTooLarge, len(manifest), MaxGenerationMetadataBytes)
	}
	if len(sourceMap) > MaxGenerationMetadataBytes {
		return Attempt{}, fmt.Errorf("%w: source map %d bytes > %d bytes", ErrGenerationMetadataTooLarge, len(sourceMap), MaxGenerationMetadataBytes)
	}
	return s.prepareApply(ctx, expectedRevision, config, manifest, sourceMap)
}

func (s *Store) prepareApply(
	ctx context.Context,
	expectedRevision uint64,
	config []byte,
	manifest []byte,
	sourceMap []byte,
) (Attempt, error) {
	if len(config) == 0 || !json.Valid(config) {
		return Attempt{}, ErrInvalidConfig
	}
	if len(config) > MaxGenerationConfigBytes {
		return Attempt{}, fmt.Errorf("%w: %d bytes > %d bytes", ErrConfigTooLarge, len(config), MaxGenerationConfigBytes)
	}
	if err := s.ensureGenerationBudget(ctx, int64(len(config)+len(manifest)+len(sourceMap))); err != nil {
		return Attempt{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Attempt{}, fmt.Errorf("begin prepare apply transaction: %w", err)
	}
	defer tx.Rollback()

	var (
		currentRevision   int64
		appliedGeneration sql.NullInt64
		recoveryRequired  int
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT config_revision, applied_generation_id, recovery_required
		FROM daemon_state
		WHERE singleton = 1
	`).Scan(&currentRevision, &appliedGeneration, &recoveryRequired); err != nil {
		return Attempt{}, fmt.Errorf("read state before apply: %w", err)
	}
	if recoveryRequired != 0 {
		return Attempt{}, ErrRecoveryRequired
	}
	if uint64(currentRevision) != expectedRevision {
		return Attempt{}, fmt.Errorf("%w: expected %d, current %d", ErrRevisionConflict, expectedRevision, currentRevision)
	}

	var activeCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM apply_journal WHERE active_slot = 1`).Scan(&activeCount); err != nil {
		return Attempt{}, fmt.Errorf("check active apply: %w", err)
	}
	if activeCount != 0 {
		return Attempt{}, ErrApplyInProgress
	}

	now := time.Now().UTC()
	targetRevision := expectedRevision + 1
	configHashBytes := sha256.Sum256(config)
	configHash := hex.EncodeToString(configHashBytes[:])
	var manifestHash, sourceMapHash any
	if len(manifest) != 0 {
		sum := sha256.Sum256(manifest)
		manifestHash = hex.EncodeToString(sum[:])
	}
	if len(sourceMap) != 0 {
		sum := sha256.Sum256(sourceMap)
		sourceMapHash = hex.EncodeToString(sum[:])
	}

	generationResult, err := tx.ExecContext(ctx, `
		INSERT INTO generations(
			base_revision,
			target_revision,
			config_json,
			config_sha256,
			manifest_json,
			manifest_sha256,
			source_map_json,
			source_map_sha256,
			created_at
		)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		expectedRevision,
		targetRevision,
		config,
		configHash,
		nullableBytes(manifest),
		manifestHash,
		nullableBytes(sourceMap),
		sourceMapHash,
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return Attempt{}, fmt.Errorf("insert generation: %w", err)
	}
	generationID, err := generationResult.LastInsertId()
	if err != nil {
		return Attempt{}, fmt.Errorf("read generation id: %w", err)
	}

	attemptResult, err := tx.ExecContext(ctx, `
		INSERT INTO apply_journal(
			generation_id,
			previous_generation_id,
			base_revision,
			target_revision,
			phase,
			active_slot,
			error,
			started_at,
			updated_at
		)
		VALUES(?, ?, ?, ?, ?, 1, '', ?, ?)
	`, generationID, nullableValue(appliedGeneration), expectedRevision, targetRevision, PhasePrepared, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return Attempt{}, ErrApplyInProgress
		}
		return Attempt{}, fmt.Errorf("insert apply journal: %w", err)
	}
	attemptID, err := attemptResult.LastInsertId()
	if err != nil {
		return Attempt{}, fmt.Errorf("read apply attempt id: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return Attempt{}, fmt.Errorf("commit prepared apply: %w", err)
	}
	return Attempt{
		ID:                   attemptID,
		GenerationID:         generationID,
		PreviousGenerationID: nullInt64Ptr(appliedGeneration),
		BaseRevision:         expectedRevision,
		TargetRevision:       targetRevision,
		Phase:                PhasePrepared,
		ConfigSHA256:         configHash,
		StartedAt:            now,
		UpdatedAt:            now,
	}, nil
}

func (s *Store) BeginActivation(ctx context.Context, attemptID int64) error {
	return s.advance(ctx, attemptID, PhasePrepared, PhaseActivating, "")
}

func (s *Store) BeginVerification(ctx context.Context, attemptID int64) error {
	return s.advance(ctx, attemptID, PhaseActivating, PhaseVerifying, "")
}

func (s *Store) BeginRollback(ctx context.Context, attemptID int64, cause string) error {
	return s.advanceFromAny(ctx, attemptID, []Phase{PhaseActivating, PhaseVerifying}, PhaseRollingBack, cause, false)
}

func (s *Store) FinishRollback(ctx context.Context, attemptID int64) error {
	return s.advance(ctx, attemptID, PhaseRollingBack, PhaseRolledBack, "")
}

func (s *Store) FailRollback(ctx context.Context, attemptID int64, cause string) error {
	if cause == "" {
		cause = "rollback failed"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin failed rollback transaction: %w", err)
	}
	defer tx.Rollback()

	attempt, err := readAttemptTx(ctx, tx, attemptID)
	if err != nil {
		return err
	}
	if attempt.Phase != PhaseRollingBack {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, attempt.Phase, PhaseFailed)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	detail := "rollback failed: " + cause
	result, err := tx.ExecContext(ctx, `
		UPDATE apply_journal
		SET phase = ?,
			active_slot = NULL,
			error = CASE WHEN error = '' THEN ? ELSE error || '; ' || ? END,
			updated_at = ?
		WHERE id = ? AND phase = ? AND active_slot = 1
	`, PhaseFailed, detail, detail, now, attemptID, PhaseRollingBack)
	if err != nil {
		return fmt.Errorf("record failed rollback: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read failed rollback update result: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("%w: rollback attempt %d is no longer active", ErrInvalidTransition, attemptID)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE daemon_state
		SET recovery_required = 1
		WHERE singleton = 1
	`); err != nil {
		return fmt.Errorf("mark recovery required after failed rollback: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit failed rollback state: %w", err)
	}
	return nil
}

func (s *Store) AbortPrepared(ctx context.Context, attemptID int64, cause string) error {
	return s.advanceFromAny(ctx, attemptID, []Phase{PhasePrepared}, PhaseFailed, cause, true)
}

func (s *Store) CommitApplied(ctx context.Context, attemptID int64, promoteLastKnownGood bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin commit applied transaction: %w", err)
	}
	defer tx.Rollback()

	attempt, err := readAttemptTx(ctx, tx, attemptID)
	if err != nil {
		return err
	}
	if attempt.Phase != PhaseVerifying {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, attempt.Phase, PhaseCommitted)
	}

	var (
		currentRevision  int64
		recoveryRequired int
	)
	if err := tx.QueryRowContext(ctx, `
		SELECT config_revision, recovery_required
		FROM daemon_state
		WHERE singleton = 1
	`).Scan(&currentRevision, &recoveryRequired); err != nil {
		return fmt.Errorf("read state before commit applied: %w", err)
	}
	if recoveryRequired != 0 {
		return ErrRecoveryRequired
	}
	if uint64(currentRevision) != attempt.BaseRevision {
		return fmt.Errorf("%w: attempt base %d, current %d", ErrRevisionConflict, attempt.BaseRevision, currentRevision)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := tx.ExecContext(ctx, `
		UPDATE apply_journal
		SET phase = ?,  active_slot = NULL, updated_at = ?
		WHERE id = ? AND phase = ? AND active_slot = 1
	`, PhaseCommitted, now, attemptID, PhaseVerifying); err != nil {
		return fmt.Errorf("commit apply journal: %w", err)
	}

	if promoteLastKnownGood {
		if _, err := tx.ExecContext(ctx, `
			UPDATE daemon_state
			SET config_revision = ?, applied_generation_id = ?, last_known_good_generation_id = ?
			WHERE singleton = 1
		`, attempt.TargetRevision, attempt.GenerationID, attempt.GenerationID); err != nil {
			return fmt.Errorf("advance applied and last-known-good generation: %w", err)
		}
	} else {
		if _, err := tx.ExecContext(ctx, `
			UPDATE daemon_state
			SET config_revision = ?, applied_generation_id = ?
			WHERE singleton = 1
		`, attempt.TargetRevision, attempt.GenerationID); err != nil {
			return fmt.Errorf("advance applied generation: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit applied state: %w", err)
	}
	return nil
}

func (s *Store) RecoverInterrupted(ctx context.Context) (Recovery, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Recovery{}, fmt.Errorf("begin recovery transaction: %w", err)
	}
	defer tx.Rollback()

	var applied sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT applied_generation_id FROM daemon_state WHERE singleton = 1`).Scan(&applied); err != nil {
		return Recovery{}, fmt.Errorf("read applied generation during recovery: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT id, phase
		FROM apply_journal
		WHERE active_slot = 1
		ORDER BY id
	`)
	if err != nil {
		return Recovery{}, fmt.Errorf("list interrupted apply attempts: %w", err)
	}
	var (
		interrupted    []int64
		needsReconcile bool
	)
	for rows.Next() {
		var id int64
		var phase Phase
		if err := rows.Scan(&id, &phase); err != nil {
			return Recovery{}, fmt.Errorf("scan interrupted apply attempt: %w", err)
		}
		interrupted = append(interrupted, id)
		if phase == PhaseActivating || phase == PhaseVerifying || phase == PhaseRollingBack {
			needsReconcile = true
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return Recovery{}, fmt.Errorf("iterate interrupted apply attempts: %w", err)
	}
	if err := rows.Close(); err != nil {
		return Recovery{}, fmt.Errorf("close interrupted apply rows: %w", err)
	}

	if len(interrupted) != 0 {
		now := time.Now().UTC().Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `
			UPDATE apply_journal
			SET phase = ?,  active_slot = NULL,
				error = CASE WHEN error = '' THEN 'daemon restarted before apply completed' ELSE error END,
				updated_at = ?
			WHERE active_slot = 1
		`, PhaseInterrupted, now); err != nil {
			return Recovery{}, fmt.Errorf("mark interrupted applies: %w", err)
		}
	}
	if needsReconcile {
		if _, err := tx.ExecContext(ctx, `UPDATE daemon_state SET recovery_required = 1 WHERE singleton = 1`); err != nil {
			return Recovery{}, fmt.Errorf("mark recovery required: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return Recovery{}, fmt.Errorf("commit interrupted apply recovery: %w", err)
	}
	return Recovery{
		InterruptedAttemptIDs: interrupted,
		NeedsReconcile:        needsReconcile,
		AppliedGenerationID:   nullInt64Ptr(applied),
	}, nil
}

func (s *Store) ResolveRecovery(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `
		UPDATE daemon_state
		SET recovery_required = 0
		WHERE singleton = 1 AND recovery_required = 1
	`); err != nil {
		return fmt.Errorf("clear recovery-required state: %w", err)
	}
	return nil
}

func (s *Store) GenerationConfig(ctx context.Context, generationID int64) ([]byte, string, error) {
	artifacts, err := s.GenerationArtifacts(ctx, generationID)
	if err != nil {
		return nil, "", err
	}
	return artifacts.ConfigJSON, artifacts.ConfigSHA256, nil
}

func (s *Store) GenerationArtifacts(ctx context.Context, generationID int64) (GenerationArtifacts, error) {
	var (
		config        []byte
		configHash    string
		manifest      []byte
		manifestHash  sql.NullString
		sourceMap     []byte
		sourceMapHash sql.NullString
	)
	if err := s.db.QueryRowContext(ctx, `
		SELECT
			config_json,
			config_sha256,
			manifest_json,
			manifest_sha256,
			source_map_json,
			source_map_sha256
		FROM generations
		WHERE id = ?
	`, generationID).Scan(
		&config,
		&configHash,
		&manifest,
		&manifestHash,
		&sourceMap,
		&sourceMapHash,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return GenerationArtifacts{}, fmt.Errorf("generation %d not found", generationID)
		}
		return GenerationArtifacts{}, fmt.Errorf("read generation %d artifacts: %w", generationID, err)
	}
	return GenerationArtifacts{
		ConfigJSON:      append([]byte(nil), config...),
		ConfigSHA256:    configHash,
		ManifestJSON:    append([]byte(nil), manifest...),
		ManifestSHA256:  manifestHash.String,
		SourceMapJSON:   append([]byte(nil), sourceMap...),
		SourceMapSHA256: sourceMapHash.String,
	}, nil
}

func (s *Store) Attempt(ctx context.Context, attemptID int64) (Attempt, error) {
	row := s.db.QueryRowContext(ctx, attemptSelect+` WHERE j.id = ?`, attemptID)
	attempt, err := scanAttempt(row)
	if err == nil || !errors.Is(err, ErrAttemptNotFound) {
		return attempt, err
	}
	archived := s.db.QueryRowContext(ctx, archivedAttemptSelect+` WHERE h.id = ?`, attemptID)
	return scanAttempt(archived)
}

func (s *Store) advance(ctx context.Context, attemptID int64, from, to Phase, cause string) error {
	return s.advanceFromAny(ctx, attemptID, []Phase{from}, to, cause, isTerminal(to))
}

func (s *Store) advanceFromAny(ctx context.Context, attemptID int64, allowed []Phase, to Phase, cause string, clearActive bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin journal transition: %w", err)
	}
	defer tx.Rollback()

	attempt, err := readAttemptTx(ctx, tx, attemptID)
	if err != nil {
		return err
	}
	if !phaseAllowed(attempt.Phase, allowed) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, attempt.Phase, to)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	activeClause := "active_slot = 1"
	if clearActive {
		activeClause = "active_slot = NULL"
	}
	query := `UPDATE apply_journal SET phase = ?,  ` + activeClause + `, error = CASE WHEN ? = '' THEN error ELSE ? END, updated_at = ? WHERE id = ?`
	if _, err := tx.ExecContext(ctx, query, to, cause, cause, now, attemptID); err != nil {
		return fmt.Errorf("advance apply journal: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit apply journal transition: %w", err)
	}
	return nil
}

func readAttemptTx(ctx context.Context, tx *sql.Tx, attemptID int64) (Attempt, error) {
	row := tx.QueryRowContext(ctx, attemptSelect+` WHERE j.id = ?`, attemptID)
	return scanAttempt(row)
}

const attemptSelect = `
	SELECT
		j.id,
		j.generation_id,
		j.previous_generation_id,
		j.base_revision,
		j.target_revision,
		j.phase,
		g.config_sha256,
		j.error,
		j.started_at,
		j.updated_at
	FROM apply_journal j
	JOIN generations g ON g.id = j.generation_id
`

const archivedAttemptSelect = `
	SELECT
		h.id,
		h.generation_id,
		h.previous_generation_id,
		h.base_revision,
		h.target_revision,
		h.phase,
		h.config_sha256,
		h.error,
		h.started_at,
		h.updated_at
	FROM apply_history h
`

type scanner interface {
	Scan(dest ...any) error
}

func scanAttempt(row scanner) (Attempt, error) {
	var (
		attempt            Attempt
		previousGeneration sql.NullInt64
		baseRevision       int64
		targetRevision     int64
		startedAt          string
		updatedAt          string
	)
	if err := row.Scan(
		&attempt.ID,
		&attempt.GenerationID,
		&previousGeneration,
		&baseRevision,
		&targetRevision,
		&attempt.Phase,
		&attempt.ConfigSHA256,
		&attempt.Error,
		&startedAt,
		&updatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Attempt{}, ErrAttemptNotFound
		}
		return Attempt{}, fmt.Errorf("read apply attempt: %w", err)
	}
	parsedStarted, err := time.Parse(time.RFC3339Nano, startedAt)
	if err != nil {
		return Attempt{}, fmt.Errorf("parse apply started_at: %w", err)
	}
	parsedUpdated, err := time.Parse(time.RFC3339Nano, updatedAt)
	if err != nil {
		return Attempt{}, fmt.Errorf("parse apply updated_at: %w", err)
	}
	attempt.PreviousGenerationID = nullInt64Ptr(previousGeneration)
	attempt.BaseRevision = uint64(baseRevision)
	attempt.TargetRevision = uint64(targetRevision)
	attempt.StartedAt = parsedStarted
	attempt.UpdatedAt = parsedUpdated
	return attempt, nil
}

func (s *Store) configure(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping sqlite state database: %w", err)
	}
	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA synchronous = FULL",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA wal_autocheckpoint = 1000",
		"PRAGMA journal_size_limit = 16777216",
		"PRAGMA trusted_schema = OFF",
	}
	for _, pragma := range pragmas {
		if _, err := s.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("configure sqlite with %q: %w", pragma, err)
		}
	}
	var journalMode string
	if err := s.db.QueryRowContext(ctx, "PRAGMA journal_mode = WAL").Scan(&journalMode); err != nil {
		return fmt.Errorf("enable sqlite WAL mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		return fmt.Errorf("sqlite WAL mode unavailable: got %q", journalMode)
	}
	return nil
}

const currentSchemaVersion = 5

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin sqlite migration: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create schema migration table: %w", err)
	}

	var version sql.NullInt64
	if err := tx.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version.Valid && version.Int64 > currentSchemaVersion {
		return fmt.Errorf("state database schema %d is newer than supported version %d", version.Int64, currentSchemaVersion)
	}

	if !version.Valid || version.Int64 < 1 {
		statements := []string{
			`CREATE TABLE generations (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
				target_revision INTEGER NOT NULL CHECK(target_revision = base_revision + 1),
				config_json BLOB NOT NULL,
				config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
				created_at TEXT NOT NULL
			)`,
			`CREATE TABLE daemon_state (
				singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
				config_revision INTEGER NOT NULL DEFAULT 0 CHECK(config_revision >= 0),
				applied_generation_id INTEGER REFERENCES generations(id) ON DELETE RESTRICT,
				last_known_good_generation_id INTEGER REFERENCES generations(id) ON DELETE RESTRICT,
				recovery_required INTEGER NOT NULL DEFAULT 0 CHECK(recovery_required IN (0, 1))
			)`,
			`INSERT INTO daemon_state(singleton, config_revision, recovery_required) VALUES(1, 0, 0)`,
			`CREATE TABLE apply_journal (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				generation_id INTEGER NOT NULL REFERENCES generations(id) ON DELETE RESTRICT,
				previous_generation_id INTEGER REFERENCES generations(id) ON DELETE RESTRICT,
				base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
				target_revision INTEGER NOT NULL CHECK(target_revision = base_revision + 1),
				phase TEXT NOT NULL CHECK(phase IN ('prepared', 'activating', 'verifying', 'rolling_back', 'committed', 'rolled_back', 'failed', 'interrupted')),
				active_slot INTEGER CHECK(active_slot IS NULL OR active_slot = 1),
				error TEXT NOT NULL DEFAULT '',
				started_at TEXT NOT NULL,
				updated_at TEXT NOT NULL
			)`,
			`CREATE UNIQUE INDEX apply_journal_one_active ON apply_journal(active_slot) WHERE active_slot IS NOT NULL`,
			`CREATE INDEX apply_journal_generation ON apply_journal(generation_id)`,
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply sqlite migration 1: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("record sqlite migration 1: %w", err)
		}
	}

	if !version.Valid || version.Int64 < 2 {
		if _, err := tx.ExecContext(ctx, `
			ALTER TABLE daemon_state
			ADD COLUMN core_desired_state TEXT NOT NULL DEFAULT 'stopped'
			CHECK(core_desired_state IN ('stopped', 'running'))
		`); err != nil {
			return fmt.Errorf("apply sqlite migration 2: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(2, ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("record sqlite migration 2: %w", err)
		}
	}

	if !version.Valid || version.Int64 < 3 {
		statements := []string{
			`ALTER TABLE generations ADD COLUMN manifest_json BLOB`,
			`ALTER TABLE generations ADD COLUMN manifest_sha256 TEXT CHECK(manifest_sha256 IS NULL OR length(manifest_sha256) = 64)`,
			`ALTER TABLE generations ADD COLUMN source_map_json BLOB`,
			`ALTER TABLE generations ADD COLUMN source_map_sha256 TEXT CHECK(source_map_sha256 IS NULL OR length(source_map_sha256) = 64)`,
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply sqlite migration 3: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(3, ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("record sqlite migration 3: %w", err)
		}
	}

	if !version.Valid || version.Int64 < 4 {
		statements := []string{
			`CREATE TABLE declaration_revisions (
				revision INTEGER PRIMARY KEY CHECK(revision > 0),
				parent_revision INTEGER REFERENCES declaration_revisions(revision) ON DELETE RESTRICT,
				document_json BLOB NOT NULL,
				document_sha256 TEXT NOT NULL CHECK(length(document_sha256) = 64),
				source TEXT NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE TABLE declaration_state (
				singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
				current_revision INTEGER REFERENCES declaration_revisions(revision) ON DELETE RESTRICT
			)`,
			`INSERT INTO declaration_state(singleton, current_revision) VALUES(1, NULL)`,
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply sqlite migration 4: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(4, ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("record sqlite migration 4: %w", err)
		}
	}

	if !version.Valid || version.Int64 < 5 {
		statements := []string{
			`CREATE TABLE apply_history (
				id INTEGER PRIMARY KEY,
				generation_id INTEGER NOT NULL,
				previous_generation_id INTEGER,
				base_revision INTEGER NOT NULL CHECK(base_revision >= 0),
				target_revision INTEGER NOT NULL CHECK(target_revision = base_revision + 1),
				phase TEXT NOT NULL CHECK(phase IN ('committed', 'rolled_back', 'failed', 'interrupted')),
				config_sha256 TEXT NOT NULL CHECK(length(config_sha256) = 64),
				manifest_sha256 TEXT CHECK(manifest_sha256 IS NULL OR length(manifest_sha256) = 64),
				source_map_sha256 TEXT CHECK(source_map_sha256 IS NULL OR length(source_map_sha256) = 64),
				error TEXT NOT NULL DEFAULT '',
				started_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				generation_created_at TEXT NOT NULL,
				archived_at TEXT NOT NULL
			)`,
			`CREATE INDEX apply_history_generation ON apply_history(generation_id)`,
			`CREATE INDEX apply_history_phase_revision ON apply_history(phase, target_revision DESC, id DESC)`,
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply sqlite migration 5: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations(version, applied_at) VALUES(5, ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("record sqlite migration 5: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit sqlite migration: %w", err)
	}
	return nil
}

func (s *Store) quickCheck(ctx context.Context) error {
	var result string
	if err := s.db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&result); err != nil {
		return fmt.Errorf("run sqlite quick_check: %w", err)
	}
	if result != "ok" {
		return fmt.Errorf("sqlite quick_check failed: %s", result)
	}
	return nil
}

func prepareDatabaseFile(path string) error {
	if path == "" {
		return errors.New("state database path is empty")
	}
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create state database directory: %w", err)
	}
	parentInfo, err := os.Stat(parent)
	if err != nil {
		return fmt.Errorf("inspect state database directory: %w", err)
	}
	parentStat, ok := parentInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify ownership of state database directory %s", parent)
	}
	if int(parentStat.Uid) != os.Getuid() {
		return fmt.Errorf("state database directory %s is owned by uid %d, expected uid %d", parent, parentStat.Uid, os.Getuid())
	}
	if parentInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state database directory %s is accessible by group or others (mode %04o)", parent, parentInfo.Mode().Perm())
	}

	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return fmt.Errorf("create state database: %w", createErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return fmt.Errorf("close new state database: %w", closeErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect state database: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink state database %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("state database %s is not a regular file", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot verify ownership of state database %s", path)
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("state database %s is owned by uid %d, expected uid %d", path, stat.Uid, os.Getuid())
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("state database %s is accessible by group or others (mode %04o)", path, info.Mode().Perm())
	}
	return nil
}

func nullInt64Ptr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	v := value.Int64
	return &v
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func nullableValue(value sql.NullInt64) any {
	if !value.Valid {
		return nil
	}
	return value.Int64
}

func phaseAllowed(current Phase, allowed []Phase) bool {
	for _, candidate := range allowed {
		if current == candidate {
			return true
		}
	}
	return false
}

func isTerminal(phase Phase) bool {
	switch phase {
	case PhaseCommitted, PhaseRolledBack, PhaseFailed, PhaseInterrupted:
		return true
	default:
		return false
	}
}
