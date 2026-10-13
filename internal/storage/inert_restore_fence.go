package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"
)

var (
	ErrInertRestoreFenceUnavailable = errors.New("read-only restore fence unavailable")
	ErrInertRestoreFenceChanged     = errors.New("read-only restore fence changed")
)

// InertRestoreFence is a comparable, nonsecret snapshot of committed live
// bindings. It is NOT a write CAS, recovery authorization, or a durable lease.
// Only a future writer's atomic SQL CAS + operation gate could close the race
// between this read and any later mutation.
type InertRestoreFence struct {
	ConfigRevision               uint64
	AppliedGenerationID          int64
	LastKnownGoodGenerationID    int64
	DeclarationRevision          uint64
	DeclarationSHA256            string
	SelectionRevision            uint64
	SelectionSHA256              string
	RoutingMode                  RoutingMode
	PrivateDirect                bool
	CoreDesiredState             CoreDesiredState
	AppliedConfigSHA256          string
	AppliedManifestSHA256        string
	AppliedSourceMapSHA256       string
	LastKnownGoodConfigSHA256    string
	LastKnownGoodManifestSHA256  string
	LastKnownGoodSourceMapSHA256 string
}

// ReadInertRestoreFence reads all relevant CAS bindings within ONE SQLite
// read transaction and rehashes the committed generation/declaration payloads.
// A concurrent apply, selection update or declaration commit cannot produce
// a torn read. Active apply or recovery-required states are always refused.
// No SQL INSERT/UPDATE/DELETE, core action, or staging file is performed.
func (s *Store) ReadInertRestoreFence(ctx context.Context) (InertRestoreFence, error) {
	var none InertRestoreFence
	if s == nil || s.db == nil || ctx == nil {
		return none, ErrInertRestoreFenceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return none, ErrInertRestoreFenceUnavailable
	}
	defer tx.Rollback()
	return readInertRestoreFenceTx(ctx, tx)
}

// readInertRestoreFenceTx is intentionally shared by the optimistic read
// fence and the write-intent CAS. It must validate exactly the same live
// SQL rows and content hashes while the caller holds its transaction.
func readInertRestoreFenceTx(ctx context.Context, tx *sql.Tx) (InertRestoreFence, error) {
	var none InertRestoreFence
	if ctx == nil || tx == nil {
		return none, ErrInertRestoreFenceUnavailable
	}
	var configRev, declarationRev, selectionRev int64
	var applied, lastGood, recoveryRequired, privateDirect int64
	var coreDesired, routingMode string
	var declarationBytes, selectionBytes []byte
	var updatedAt sql.NullString
	var appliedConfig, appliedManifest, appliedSource []byte
	var lastConfig, lastManifest, lastSource []byte
	var fence InertRestoreFence
	err = tx.QueryRowContext(ctx, `
		SELECT d.config_revision, d.applied_generation_id,
			d.last_known_good_generation_id, d.recovery_required,
			d.core_desired_state, d.routing_mode, d.private_direct,
			ds.current_revision, dr.document_json, dr.document_sha256,
			ss.revision, ss.current_target_json, ss.updated_at,
			a.config_json, a.config_sha256, a.manifest_json,
			a.manifest_sha256, a.source_map_json, a.source_map_sha256,
			l.config_json, l.config_sha256, l.manifest_json,
			l.manifest_sha256, l.source_map_json, l.source_map_sha256
		FROM daemon_state d
		CROSS JOIN declaration_state ds
		JOIN declaration_revisions dr ON dr.revision = ds.current_revision
		CROSS JOIN selection_state ss
		JOIN generations a ON a.id = d.applied_generation_id
		JOIN generations l ON l.id = d.last_known_good_generation_id
		WHERE d.singleton = 1 AND ds.singleton = 1 AND ss.singleton = 1
	`).Scan(
		&configRev, &applied, &lastGood, &recoveryRequired,
		&coreDesired, &routingMode, &privateDirect,
		&declarationRev, &declarationBytes, &fence.DeclarationSHA256,
		&selectionRev, &selectionBytes, &updatedAt,
		&appliedConfig, &fence.AppliedConfigSHA256,
		&appliedManifest, &fence.AppliedManifestSHA256,
		&appliedSource, &fence.AppliedSourceMapSHA256,
		&lastConfig, &fence.LastKnownGoodConfigSHA256,
		&lastManifest, &fence.LastKnownGoodManifestSHA256,
		&lastSource, &fence.LastKnownGoodSourceMapSHA256,
	)
	if err != nil || configRev <= 0 || configRev >= math.MaxInt64 ||
		applied <= 0 || lastGood <= 0 || declarationRev <= 0 ||
		selectionRev < 0 || recoveryRequired != 0 ||
		(privateDirect != 0 && privateDirect != 1) ||
		(coreDesired != string(CoreDesiredRunning) &&
			coreDesired != string(CoreDesiredStopped)) ||
		RoutingMode(routingMode).Validate() != nil {
		return none, ErrInertRestoreFenceUnavailable
	}
	if !validHistoricalBlob(declarationBytes, fence.DeclarationSHA256, MaxDeclarationBytes) ||
		!validHistoricalBlob(appliedConfig, fence.AppliedConfigSHA256, MaxGenerationConfigBytes) ||
		!validHistoricalBlob(appliedManifest, fence.AppliedManifestSHA256, MaxGenerationMetadataBytes) ||
		!validHistoricalBlob(appliedSource, fence.AppliedSourceMapSHA256, MaxGenerationMetadataBytes) ||
		!validHistoricalBlob(lastConfig, fence.LastKnownGoodConfigSHA256, MaxGenerationConfigBytes) ||
		!validHistoricalBlob(lastManifest, fence.LastKnownGoodManifestSHA256, MaxGenerationMetadataBytes) ||
		!validHistoricalBlob(lastSource, fence.LastKnownGoodSourceMapSHA256, MaxGenerationMetadataBytes) {
		return none, ErrInertRestoreFenceUnavailable
	}
	if len(selectionBytes) > MaxSelectionTargetBytes ||
		(len(selectionBytes) > 0 && (!json.Valid(selectionBytes) ||
			!updatedAt.Valid || !validInertSelectionTime(updatedAt.String))) ||
		(len(selectionBytes) == 0 && updatedAt.Valid && updatedAt.String != "") {
		return none, ErrInertRestoreFenceUnavailable
	}
	var activeCount int
	if err := tx.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM apply_journal WHERE active_slot = 1",
	).Scan(&activeCount); err != nil || activeCount != 0 {
		return none, ErrInertRestoreFenceUnavailable
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	fence.ConfigRevision = uint64(configRev)
	fence.AppliedGenerationID = applied
	fence.LastKnownGoodGenerationID = lastGood
	fence.DeclarationRevision = uint64(declarationRev)
	fence.SelectionRevision = uint64(selectionRev)
	fence.RoutingMode = RoutingMode(routingMode)
	fence.CoreDesiredState = CoreDesiredState(coreDesired)
	fence.PrivateDirect = privateDirect == 1
	selectionSHA := sha256.Sum256(selectionBytes)
	fence.SelectionSHA256 = hex.EncodeToString(selectionSHA[:])
	return fence, nil
}

func validInertSelectionTime(value string) bool {
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

// RecheckInertRestoreFence provides only a read-only optimistic conflict
// check. A future restore writer must use a NEW transaction-local SQL CAS.
func (s *Store) RecheckInertRestoreFence(ctx context.Context, expected InertRestoreFence) error {
	if !validInertRestoreFence(expected) {
		return ErrInertRestoreFenceUnavailable
	}
	found, err := s.ReadInertRestoreFence(ctx)
	if err != nil {
		return err
	}
	if found != expected {
		return ErrInertRestoreFenceChanged
	}
	return nil
}

// validInertRestoreFence rejects forged and overflowed caller-supplied
// baselines before either an optimistic read or a write-intent probe.
func validInertRestoreFence(expected InertRestoreFence) bool {
	if expected.ConfigRevision == 0 || expected.ConfigRevision >= uint64(1<<63-1) ||
		expected.AppliedGenerationID <= 0 ||
		expected.LastKnownGoodGenerationID <= 0 ||
		expected.DeclarationRevision == 0 || expected.DeclarationRevision > uint64(1<<63-1) ||
		expected.SelectionRevision > uint64(1<<63-1) ||
		!validHistoricalSHA(expected.DeclarationSHA256) ||
		!validHistoricalSHA(expected.SelectionSHA256) ||
		!validHistoricalSHA(expected.AppliedConfigSHA256) ||
		!validHistoricalSHA(expected.AppliedManifestSHA256) ||
		!validHistoricalSHA(expected.AppliedSourceMapSHA256) ||
		!validHistoricalSHA(expected.LastKnownGoodConfigSHA256) ||
		!validHistoricalSHA(expected.LastKnownGoodManifestSHA256) ||
		!validHistoricalSHA(expected.LastKnownGoodSourceMapSHA256) ||
		expected.RoutingMode.Validate() != nil ||
		(expected.CoreDesiredState != CoreDesiredStopped && expected.CoreDesiredState != CoreDesiredRunning) {
		return false
	}
	return true
}
