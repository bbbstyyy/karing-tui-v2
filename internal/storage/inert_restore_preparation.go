package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxInertRestorePreparations = 32
	maxInertRestoreArchiveBytes = int64(2 << 30)
	inertRestoreScopePrefix = ".ktui-restore-v1-"
)

var (
	ErrInertRestorePreparationRefused = errors.New("inert restore preparation refused")
	ErrInertRestorePreparationBusy = errors.New("inert restore preparation already pending")
)

type InertRestorePreparationPhase string

const (
	InertRestorePrepared InertRestorePreparationPhase = "prepared"
	InertRestoreAbandoned InertRestorePreparationPhase = "abandoned"
)

// InertRestorePreparation is NOT a prepared apply, an activation reservation,
// a restorable snapshot or permission to import any database. A prepared row
// merely records that a ciphertext-only candidate passed the transient CAS.
// In particular it is NEVER consumed by apply_journal or RecoverInterrupted.
type InertRestorePreparation struct {
	ID int64
	CandidateScope string
	ArchiveSHA256 string
	InventorySHA256 string
	ArchiveBytes int64
	Baseline InertRestoreFence
	Phase InertRestorePreparationPhase
	CreatedAt time.Time
	UpdatedAt time.Time
	RequiresRevalidation bool
	RestoreSupported bool
	RestoreReady bool
}

// The input does not contain a candidate path, plaintext, encryption key,
// SQL payload, or arbitrary DDL. Scope is a checked single path component.
type InertRestorePreparationInput struct {
	CandidateScope string
	ArchiveSHA256 string
	InventorySHA256 string
	ArchiveBytes int64
	Baseline InertRestoreFence
}

func validInertRestoreScope(value string) bool {
	if filepath.Base(value) != value ||
		!strings.HasPrefix(value, inertRestoreScopePrefix) {
		return false
	}
	suffix := strings.TrimPrefix(value, inertRestoreScopePrefix)
	if len(suffix) < 6 || len(suffix) > 32 {
		return false
	}
	for _, ch := range suffix {
		if ch >= 'a' && ch <= 'z' ||
			ch >= 'A' && ch <= 'Z' ||
			ch >= '0' && ch <= '9' {
			continue
		}
		return false
	}
	return true
}

func validInertRestorePreparationInput(in InertRestorePreparationInput) bool {
	return validInertRestoreScope(in.CandidateScope) &&
		validHistoricalSHA(in.ArchiveSHA256) &&
		validHistoricalSHA(in.InventorySHA256) &&
		in.ArchiveBytes > 0 && in.ArchiveBytes <= maxInertRestoreArchiveBytes &&
		validInertRestoreFence(in.Baseline)
}

// PrepareInertRestoreRecord atomically binds the complete checked live fence
// to a non-activating durable row. The same transaction both obtains SQLite's
// single-writer CAS and INSERTs the inert record. It never alters the applied
// generation or starts/blocks an ordinary apply (except for the short writer
// lock while this transaction commits).
//
// The caller MUST have just authenticated a still-flock-held encrypted
// candidate. That is a prerequisite, NOT persistent authorization: all
// subsequent use, particularly after process restart, requires a new key,
// candidate lease and full verification.
func (s *Store) PrepareInertRestoreRecord(
	ctx context.Context, in InertRestorePreparationInput,
) (InertRestorePreparation, error) {
	return s.prepareInertRestoreRecord(ctx, in, nil)
}

// afterInsert is an unexported fault-injection hook for rollback/crash tests.
// It runs inside the SQLite transaction and must not call into the Store.
func (s *Store) prepareInertRestoreRecord(
	ctx context.Context, in InertRestorePreparationInput,
	afterInsert func() error,
) (InertRestorePreparation, error) {
	var empty InertRestorePreparation
	if s == nil || s.db == nil || ctx == nil || !validInertRestorePreparationInput(in) {
		return empty, ErrInertRestorePreparationRefused
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	bounded, cancel := context.WithTimeout(ctx, inertRestoreWriteCASDeadline)
	defer cancel()
	fenceJSON, err := json.Marshal(in.Baseline)
	if err != nil || len(fenceJSON) > 4096 {
		return empty, ErrInertRestorePreparationRefused
	}
	fenceDigest := sha256.Sum256(fenceJSON)
	fenceSHA := hex.EncodeToString(fenceDigest[:])
	tx, err := s.db.BeginTx(bounded, nil)
	if err != nil {
		return empty, ErrInertRestorePreparationRefused
	}
	defer tx.Rollback()
	if err := checkInertRestoreWriteCASTx(bounded, tx, in.Baseline); err != nil {
		if errors.Is(err, ErrInertRestoreFenceChanged) {
			return empty, err
		}
		return empty, ErrInertRestorePreparationRefused
	}
	// Exactly one pending record is permitted. A pending record's lifetime
	// is NOT tied to a process PID; on restart it must be reviewed explicitly.
	var count, pending int
	if err := tx.QueryRowContext(bounded, `
		SELECT COUNT(*), COALESCE(SUM(CASE WHEN phase = 'prepared' THEN 1 ELSE 0 END), 0)
		FROM inert_restore_preparations
	`).Scan(&count, &pending); err != nil ||
		count < 0 || count >= maxInertRestorePreparations ||
		pending < 0 || pending > 1 {
		return empty, ErrInertRestorePreparationRefused
	}
	if pending != 0 {
		return empty, ErrInertRestorePreparationBusy
	}
	now := time.Now().UTC()
	encodedTime := now.Format(time.RFC3339Nano)
	res, err := tx.ExecContext(bounded, `
		INSERT INTO inert_restore_preparations
			(candidate_scope, archive_sha256, inventory_sha256,
			 archive_bytes, baseline_json, baseline_sha256,
			 phase, active_slot, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 'prepared', 1, ?, ?)
	`, in.CandidateScope, in.ArchiveSHA256, in.InventorySHA256,
		in.ArchiveBytes, fenceJSON, fenceSHA, encodedTime, encodedTime)
	if err != nil {
		return empty, ErrInertRestorePreparationRefused
	}
	id, err := res.LastInsertId()
	if err != nil || id <= 0 {
		return empty, ErrInertRestorePreparationRefused
	}
	if afterInsert != nil {
		if err := afterInsert(); err != nil {
			return empty, ErrInertRestorePreparationRefused
		}
	}
	if err := bounded.Err(); err != nil {
		return empty, err
	}
	if err := tx.Commit(); err != nil {
		return empty, ErrInertRestorePreparationRefused
	}
	return InertRestorePreparation{
		ID: id, CandidateScope: in.CandidateScope,
		ArchiveSHA256: in.ArchiveSHA256,
		InventorySHA256: in.InventorySHA256,
		ArchiveBytes: in.ArchiveBytes,
		Baseline: in.Baseline, Phase: InertRestorePrepared,
		CreatedAt: now, UpdatedAt: now, RequiresRevalidation: true,
		RestoreSupported: false, RestoreReady: false,
	}, nil
}

const inertRestoreJournalSelect = `
	SELECT id, candidate_scope, archive_sha256, inventory_sha256,
	       archive_bytes, baseline_json, baseline_sha256,
	       phase, active_slot, created_at, updated_at
	FROM inert_restore_preparations
`

// scanInertRestorePreparation is used by BOTH live inspection and sealed
// archive validation. It never returns SQL text, paths or private payloads.
func scanInertRestorePreparation(row scanner) (InertRestorePreparation, bool) {
	var result InertRestorePreparation
	var encoded []byte
	var digest, created, updated string
	var active sql.NullInt64
	if row.Scan(&result.ID, &result.CandidateScope,
		&result.ArchiveSHA256, &result.InventorySHA256, &result.ArchiveBytes,
		&encoded, &digest, &result.Phase, &active, &created, &updated) != nil ||
		result.ID <= 0 || len(encoded) == 0 || len(encoded) > 4096 ||
		!validHistoricalSHA(digest) {
		return InertRestorePreparation{}, false
	}
	var fence InertRestoreFence
	if json.Unmarshal(encoded, &fence) != nil || !validInertRestoreFence(fence) {
		return InertRestorePreparation{}, false
	}
	canonical, err := json.Marshal(fence)
	d := sha256.Sum256(encoded)
	if err != nil || !bytes.Equal(encoded, canonical) ||
		hex.EncodeToString(d[:]) != digest {
		return InertRestorePreparation{}, false
	}
	result.Baseline = fence
	if !validInertRestorePreparationInput(InertRestorePreparationInput{
		CandidateScope: result.CandidateScope,
		ArchiveSHA256: result.ArchiveSHA256,
		InventorySHA256: result.InventorySHA256,
		ArchiveBytes: result.ArchiveBytes, Baseline: fence,
	}) ||
		(result.Phase != InertRestorePrepared &&
			result.Phase != InertRestoreAbandoned) ||
		(result.Phase == InertRestorePrepared && (!active.Valid || active.Int64 != 1)) ||
		(result.Phase == InertRestoreAbandoned && active.Valid) {
		return InertRestorePreparation{}, false
	}
	result.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return InertRestorePreparation{}, false
	}
	result.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil || result.UpdatedAt.Before(result.CreatedAt) {
		return InertRestorePreparation{}, false
	}
	result.RequiresRevalidation = true
	return result, true
}

// InspectInertRestoreRecords is a bounded read-only inventory. A "prepared"
// row after restart is ONLY a pending administrative record. It is not safe
// to assume the old candidate lease remains held or that the resource exists.
func (s *Store) InspectInertRestoreRecords(
	ctx context.Context,
) ([]InertRestorePreparation, error) {
	if s == nil || s.db == nil || ctx == nil {
		return nil, ErrInertRestorePreparationRefused
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, inertRestoreJournalSelect+
		" ORDER BY id LIMIT ?", maxInertRestorePreparations+1)
	if err != nil {
		return nil, ErrInertRestorePreparationRefused
	}
	defer rows.Close()
	out := make([]InertRestorePreparation, 0)
	active := 0
	for rows.Next() {
		if ctx.Err() != nil || len(out) >= maxInertRestorePreparations {
			return nil, ErrInertRestorePreparationRefused
		}
		row, ok := scanInertRestorePreparation(rows)
		if !ok {
			return nil, ErrInertRestorePreparationRefused
		}
		if row.Phase == InertRestorePrepared {
			active++
		}
		out = append(out, row)
	}
	if rows.Err() != nil || active > 1 {
		return nil, ErrInertRestorePreparationRefused
	}
	return out, nil
}

// AbandonInertRestoreRecord is the only supported phase transition. It
// never deletes the encrypted candidate nor modifies applied/LKG config.
// It can be invoked after a crash without trusting a stale process lease.
func (s *Store) AbandonInertRestoreRecord(
	ctx context.Context, id int64, scope, archiveSHA string,
) error {
	if s == nil || s.db == nil || ctx == nil || id <= 0 ||
		!validInertRestoreScope(scope) || !validHistoricalSHA(archiveSHA) {
		return ErrInertRestorePreparationRefused
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrInertRestorePreparationRefused
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `
		UPDATE inert_restore_preparations
		SET phase = 'abandoned', active_slot = NULL, updated_at = ?
		WHERE id = ? AND candidate_scope = ? AND archive_sha256 = ?
			AND phase = 'prepared' AND active_slot = 1
	`, time.Now().UTC().Format(time.RFC3339Nano), id, scope, archiveSHA)
	if err != nil {
		return ErrInertRestorePreparationRefused
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return ErrInertRestorePreparationRefused
	}
	if err := tx.Commit(); err != nil {
		return ErrInertRestorePreparationRefused
	}
	return nil
}
