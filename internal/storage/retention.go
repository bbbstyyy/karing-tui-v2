package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	DefaultConfirmedGenerationRetention = 5
	DefaultGenerationPayloadQuotaBytes   = int64(640 << 20)
)

type RetentionPolicy struct {
	ConfirmedGenerations int   `json:"confirmed_generations"`
	MaxGenerationBytes   int64 `json:"max_generation_bytes"`
}

func DefaultRetentionPolicy() RetentionPolicy {
	return RetentionPolicy{
		ConfirmedGenerations: DefaultConfirmedGenerationRetention,
		MaxGenerationBytes:   DefaultGenerationPayloadQuotaBytes,
	}
}

func (p RetentionPolicy) Validate() error {
	if p.ConfirmedGenerations < 2 {
		return errors.New("retention policy must keep at least two confirmed generations")
	}
	if p.MaxGenerationBytes <= 0 {
		return errors.New("generation payload quota must be positive")
	}
	return nil
}

type RetentionReport struct {
	Policy                   RetentionPolicy `json:"policy"`
	LiveGenerationCount      int             `json:"live_generation_count"`
	LiveGenerationBytes      int64           `json:"live_generation_bytes"`
	ProtectedGenerationCount int             `json:"protected_generation_count"`
	ActiveAttemptCount       int             `json:"active_attempt_count"`
	ArchivedAttemptCount     int             `json:"archived_attempt_count"`
	ArchivedThisRun          int64           `json:"archived_this_run,omitempty"`
	PrunedGenerationCount    int64           `json:"pruned_generation_count,omitempty"`
	ReclaimedGenerationBytes int64           `json:"reclaimed_generation_bytes,omitempty"`
	OverBudget               bool            `json:"over_budget"`
}

func (s *Store) RetentionPolicy() RetentionPolicy {
	return s.retention
}

func (s *Store) RetentionStatus(ctx context.Context) (RetentionReport, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RetentionReport{}, fmt.Errorf("begin retention status transaction: %w", err)
	}
	defer tx.Rollback()

	protected, err := protectedGenerationIDsTx(ctx, tx, s.retention.ConfirmedGenerations)
	if err != nil {
		return RetentionReport{}, err
	}
	return retentionReportTx(ctx, tx, s.retention, protected)
}

func (s *Store) PruneRetention(ctx context.Context) (RetentionReport, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RetentionReport{}, fmt.Errorf("begin retention prune transaction: %w", err)
	}
	defer tx.Rollback()

	beforeBytes, err := generationBytesTx(ctx, tx)
	if err != nil {
		return RetentionReport{}, err
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	archiveResult, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO apply_history(
			id,
			generation_id,
			previous_generation_id,
			base_revision,
			target_revision,
			phase,
			config_sha256,
			manifest_sha256,
			source_map_sha256,
			error,
			started_at,
			updated_at,
			generation_created_at,
			archived_at
		)
		SELECT
			j.id,
			j.generation_id,
			j.previous_generation_id,
			j.base_revision,
			j.target_revision,
			j.phase,
			g.config_sha256,
			g.manifest_sha256,
			g.source_map_sha256,
			j.error,
			j.started_at,
			j.updated_at,
			g.created_at,
			?
		FROM apply_journal j
		JOIN generations g ON g.id = j.generation_id
		WHERE j.active_slot IS NULL
			AND j.phase IN (?, ?, ?, ?)
	`, now, PhaseCommitted, PhaseRolledBack, PhaseFailed, PhaseInterrupted)
	if err != nil {
		return RetentionReport{}, fmt.Errorf("archive terminal apply attempts: %w", err)
	}
	archivedThisRun, err := archiveResult.RowsAffected()
	if err != nil {
		return RetentionReport{}, fmt.Errorf("read archived apply attempt count: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		DELETE FROM apply_journal
		WHERE active_slot IS NULL
			AND id IN (SELECT id FROM apply_history)
	`); err != nil {
		return RetentionReport{}, fmt.Errorf("compact terminal apply journal: %w", err)
	}

	protected, err := protectedGenerationIDsTx(ctx, tx, s.retention.ConfirmedGenerations)
	if err != nil {
		return RetentionReport{}, err
	}
	pruned, err := deletePrunableGenerationsTx(ctx, tx, protected)
	if err != nil {
		return RetentionReport{}, err
	}

	report, err := retentionReportTx(ctx, tx, s.retention, protected)
	if err != nil {
		return RetentionReport{}, err
	}
	report.ArchivedThisRun = archivedThisRun
	report.PrunedGenerationCount = pruned
	if beforeBytes > report.LiveGenerationBytes {
		report.ReclaimedGenerationBytes = beforeBytes - report.LiveGenerationBytes
	}

	if err := tx.Commit(); err != nil {
		return RetentionReport{}, fmt.Errorf("commit retention prune: %w", err)
	}
	return report, nil
}

func (s *Store) ensureGenerationBudget(ctx context.Context, incomingBytes int64) error {
	if incomingBytes < 0 {
		return errors.New("incoming generation size is negative")
	}
	report, err := s.PruneRetention(ctx)
	if err != nil {
		return fmt.Errorf("prune generation history before apply: %w", err)
	}
	if incomingBytes > s.retention.MaxGenerationBytes ||
		report.LiveGenerationBytes > s.retention.MaxGenerationBytes-incomingBytes {
		return fmt.Errorf(
			"%w: retained=%d incoming=%d quota=%d",
			ErrGenerationStorageBudget,
			report.LiveGenerationBytes,
			incomingBytes,
			s.retention.MaxGenerationBytes,
		)
	}
	return nil
}

func protectedGenerationIDsTx(ctx context.Context, tx *sql.Tx, keepConfirmed int) (map[int64]struct{}, error) {
	protected := make(map[int64]struct{}, keepConfirmed+4)
	add := func(value sql.NullInt64) {
		if value.Valid && value.Int64 > 0 {
			protected[value.Int64] = struct{}{}
		}
	}

	var applied, lastKnownGood sql.NullInt64
	if err := tx.QueryRowContext(ctx, `
		SELECT applied_generation_id, last_known_good_generation_id
		FROM daemon_state
		WHERE singleton = 1
	`).Scan(&applied, &lastKnownGood); err != nil {
		return nil, fmt.Errorf("read protected daemon generations: %w", err)
	}
	add(applied)
	add(lastKnownGood)

	rows, err := tx.QueryContext(ctx, `
		SELECT generation_id, previous_generation_id
		FROM apply_journal
		WHERE active_slot = 1
	`)
	if err != nil {
		return nil, fmt.Errorf("read active generation references: %w", err)
	}
	for rows.Next() {
		var generation int64
		var previous sql.NullInt64
		if err := rows.Scan(&generation, &previous); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan active generation references: %w", err)
		}
		if generation > 0 {
			protected[generation] = struct{}{}
		}
		add(previous)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate active generation references: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close active generation references: %w", err)
	}

	rows, err = tx.QueryContext(ctx, `
		SELECT generation_id
		FROM apply_history
		WHERE phase = ?
		ORDER BY target_revision DESC, id DESC
		LIMIT ?
	`, PhaseCommitted, keepConfirmed)
	if err != nil {
		return nil, fmt.Errorf("read retained confirmed generations: %w", err)
	}
	for rows.Next() {
		var generation int64
		if err := rows.Scan(&generation); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan retained confirmed generation: %w", err)
		}
		if generation > 0 {
			protected[generation] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate retained confirmed generations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close retained confirmed generations: %w", err)
	}
	return protected, nil
}

func deletePrunableGenerationsTx(ctx context.Context, tx *sql.Tx, protected map[int64]struct{}) (int64, error) {
	query := `
		DELETE FROM generations
		WHERE NOT EXISTS (
			SELECT 1
			FROM apply_journal j
			WHERE j.generation_id = generations.id
				OR j.previous_generation_id = generations.id
		)
	`
	args := make([]any, 0, len(protected))
	if len(protected) != 0 {
		ids := make([]int64, 0, len(protected))
		for id := range protected {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		placeholders := make([]string, 0, len(ids))
		for _, id := range ids {
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		query += " AND id NOT IN (" + strings.Join(placeholders, ",") + ")"
	}
	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("prune unreferenced generations: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("read pruned generation count: %w", err)
	}
	return count, nil
}

func retentionReportTx(
	ctx context.Context,
	tx *sql.Tx,
	policy RetentionPolicy,
	protected map[int64]struct{},
) (RetentionReport, error) {
	var report RetentionReport
	report.Policy = policy

	if err := tx.QueryRowContext(ctx, `
		SELECT
			COUNT(*),
			COALESCE(SUM(
				length(config_json) +
				COALESCE(length(manifest_json), 0) +
				COALESCE(length(source_map_json), 0)
			), 0)
		FROM generations
	`).Scan(&report.LiveGenerationCount, &report.LiveGenerationBytes); err != nil {
		return RetentionReport{}, fmt.Errorf("measure retained generation payloads: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM apply_journal
		WHERE active_slot = 1
	`).Scan(&report.ActiveAttemptCount); err != nil {
		return RetentionReport{}, fmt.Errorf("count active apply attempts for retention: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM apply_history`).Scan(&report.ArchivedAttemptCount); err != nil {
		return RetentionReport{}, fmt.Errorf("count archived apply attempts: %w", err)
	}

	if len(protected) != 0 {
		ids := make([]int64, 0, len(protected))
		for id := range protected {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		placeholders := make([]string, 0, len(ids))
		args := make([]any, 0, len(ids))
		for _, id := range ids {
			placeholders = append(placeholders, "?")
			args = append(args, id)
		}
		query := "SELECT COUNT(*) FROM generations WHERE id IN (" + strings.Join(placeholders, ",") + ")"
		if err := tx.QueryRowContext(ctx, query, args...).Scan(&report.ProtectedGenerationCount); err != nil {
			return RetentionReport{}, fmt.Errorf("count protected generations: %w", err)
		}
	}
	report.OverBudget = report.LiveGenerationBytes > policy.MaxGenerationBytes
	return report, nil
}

func generationBytesTx(ctx context.Context, tx *sql.Tx) (int64, error) {
	var value int64
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(
			length(config_json) +
			COALESCE(length(manifest_json), 0) +
			COALESCE(length(source_map_json), 0)
		), 0)
		FROM generations
	`).Scan(&value); err != nil {
		return 0, fmt.Errorf("measure generation bytes before prune: %w", err)
	}
	return value, nil
}
