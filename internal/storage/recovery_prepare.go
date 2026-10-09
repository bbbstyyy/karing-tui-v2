package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

var (
	ErrHistoricalRestoreRejected    = errors.New("historical restore precondition invalid")
	ErrHistoricalRestoreChanged     = errors.New("historical restore state changed")
	ErrHistoricalRestoreUnavailable = errors.New("historical committed generation unavailable or unverified")
)

// HistoricalRestorePrecondition binds an audited, retained generation to the
// precise state observed by a future gated coordinator. It is not a public
// restore token, and does not authorize core activation.
type HistoricalRestorePrecondition struct {
	SourceGenerationID                 int64
	SourceConfigSHA256                  string
	SourceManifestSHA256                string
	SourceMapSHA256                     string
	ExpectedConfigRevision             uint64
	ExpectedAppliedGenerationID        int64
	ExpectedLastKnownGoodGenerationID  int64
	ExpectedDeclarationRevision        uint64
	ExpectedDeclarationSHA256          string
	ExpectedSelectionRevision          uint64
	ExpectedRoutingMode                RoutingMode
	ExpectedPrivateDirect              bool
	ExpectedCoreDesiredState           CoreDesiredState
}

func validHistoricalSHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	data, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(data) == value
}

func (p HistoricalRestorePrecondition) validate() error {
	if p.SourceGenerationID <= 0 ||
		p.ExpectedConfigRevision == 0 || p.ExpectedConfigRevision >= math.MaxInt64 ||
		p.ExpectedAppliedGenerationID <= 0 || p.ExpectedLastKnownGoodGenerationID <= 0 ||
		p.ExpectedDeclarationRevision == 0 || p.ExpectedDeclarationRevision > math.MaxInt64 ||
		p.ExpectedSelectionRevision > math.MaxInt64 ||
		p.SourceGenerationID == p.ExpectedAppliedGenerationID ||
		!validHistoricalSHA(p.SourceConfigSHA256) ||
		!validHistoricalSHA(p.SourceManifestSHA256) ||
		!validHistoricalSHA(p.SourceMapSHA256) ||
		!validHistoricalSHA(p.ExpectedDeclarationSHA256) {
		return ErrHistoricalRestoreRejected
	}
	if p.ExpectedRoutingMode.Validate() != nil {
		return ErrHistoricalRestoreRejected
	}
	if p.ExpectedCoreDesiredState != CoreDesiredRunning &&
		p.ExpectedCoreDesiredState != CoreDesiredStopped {
		return ErrHistoricalRestoreRejected
	}
	return nil
}

// PrepareHistoricalRestore copies an already COMMITTED, retained generation
// into a distinct, immutable candidate, with its historical origin recorded.
// The original generation is never re-activated by ID. The normal active
// apply journal slot protects the candidate and previous applied generation
// from retention pruning and supplies existing crash-recovery semantics.
//
// It does not do network I/O, core checks, activation or applied-state writes.
// Before exposing a user operation, daemon must guard this call with full
// immutable rule-resource, selector, binary and live-policy verification.
func (s *Store) PrepareHistoricalRestore(
	ctx context.Context, p HistoricalRestorePrecondition,
) (Attempt, GenerationArtifacts, error) {
	if s == nil {
		return Attempt{}, GenerationArtifacts{}, ErrHistoricalRestoreRejected
	}
	if err := p.validate(); err != nil {
		return Attempt{}, GenerationArtifacts{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Attempt{}, GenerationArtifacts{}, fmt.Errorf("begin historical restore transaction: %w", err)
	}
	defer tx.Rollback()

	var (
		configRevision, selectionRevision int64
		applied, lastKnownGood, declarationRevision sql.NullInt64
		declarationSHA sql.NullString
		recoveryRequired, privateDirect int
		coreDesired, routingMode string
	)
	if err := tx.QueryRowContext(ctx, `SELECT
		d.config_revision, d.applied_generation_id, d.last_known_good_generation_id,
		d.recovery_required, d.core_desired_state, d.routing_mode, d.private_direct,
		ds.current_revision, dr.document_sha256, ss.revision
		FROM daemon_state d
		CROSS JOIN declaration_state ds
		LEFT JOIN declaration_revisions dr ON dr.revision = ds.current_revision
		CROSS JOIN selection_state ss
		WHERE d.singleton = 1 AND ds.singleton = 1 AND ss.singleton = 1
	`).Scan(
		&configRevision, &applied, &lastKnownGood, &recoveryRequired,
		&coreDesired, &routingMode, &privateDirect, &declarationRevision,
		&declarationSHA, &selectionRevision,
	); err != nil {
		return Attempt{}, GenerationArtifacts{}, fmt.Errorf("read historical restore bindings: %w", err)
	}
	if recoveryRequired != 0 {
		return Attempt{}, GenerationArtifacts{}, ErrRecoveryRequired
	}
	if configRevision < 0 || uint64(configRevision) != p.ExpectedConfigRevision ||
		!applied.Valid || applied.Int64 != p.ExpectedAppliedGenerationID ||
		!lastKnownGood.Valid || lastKnownGood.Int64 != p.ExpectedLastKnownGoodGenerationID ||
		!declarationRevision.Valid || declarationRevision.Int64 != int64(p.ExpectedDeclarationRevision) ||
		!declarationSHA.Valid || declarationSHA.String != p.ExpectedDeclarationSHA256 ||
		selectionRevision < 0 || uint64(selectionRevision) != p.ExpectedSelectionRevision ||
		routingMode != string(p.ExpectedRoutingMode) ||
		(privateDirect == 1) != p.ExpectedPrivateDirect ||
		coreDesired != string(p.ExpectedCoreDesiredState) {
		return Attempt{}, GenerationArtifacts{}, ErrHistoricalRestoreChanged
	}

	var activeCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM apply_journal WHERE active_slot = 1`).Scan(&activeCount); err != nil {
		return Attempt{}, GenerationArtifacts{}, fmt.Errorf("read active apply before historical restore: %w", err)
	}
	if activeCount != 0 {
		return Attempt{}, GenerationArtifacts{}, ErrApplyInProgress
	}

	var source GenerationArtifacts
	err = tx.QueryRowContext(ctx, `SELECT
		config_json, config_sha256, manifest_json, manifest_sha256,
		source_map_json, source_map_sha256
		FROM generations WHERE id = ?
	`, p.SourceGenerationID).Scan(
		&source.ConfigJSON, &source.ConfigSHA256,
		&source.ManifestJSON, &source.ManifestSHA256,
		&source.SourceMapJSON, &source.SourceMapSHA256,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Attempt{}, GenerationArtifacts{}, ErrHistoricalRestoreUnavailable
	}
	if err != nil {
		return Attempt{}, GenerationArtifacts{}, fmt.Errorf("read historical restore source: %w", err)
	}
	if source.ConfigSHA256 != p.SourceConfigSHA256 ||
		source.ManifestSHA256 != p.SourceManifestSHA256 ||
		source.SourceMapSHA256 != p.SourceMapSHA256 ||
		!validHistoricalBlob(source.ConfigJSON, source.ConfigSHA256, MaxGenerationConfigBytes) ||
		!validHistoricalBlob(source.ManifestJSON, source.ManifestSHA256, MaxGenerationMetadataBytes) ||
		!validHistoricalBlob(source.SourceMapJSON, source.SourceMapSHA256, MaxGenerationMetadataBytes) {
		return Attempt{}, GenerationArtifacts{}, ErrHistoricalRestoreUnavailable
	}

	// The archived manifest must still bind an existing immutable declaration.
	// Full compiler-schema and external rule-resource checks belong in daemon.
	var binding struct {
		ConfigSHA256        string `json:"config_sha256"`
		DeclarationRevision uint64 `json:"declaration_revision"`
		DeclarationSHA256   string `json:"declaration_sha256"`
	}
	if json.Unmarshal(source.ManifestJSON, &binding) != nil ||
		binding.ConfigSHA256 != source.ConfigSHA256 ||
		binding.DeclarationRevision == 0 || binding.DeclarationRevision > math.MaxInt64 ||
		!validHistoricalSHA(binding.DeclarationSHA256) {
		return Attempt{}, GenerationArtifacts{}, ErrHistoricalRestoreUnavailable
	}
	var oldDeclaration []byte
	var oldDeclarationSHA string
	err = tx.QueryRowContext(ctx, `SELECT document_json, document_sha256
		FROM declaration_revisions WHERE revision = ?`, binding.DeclarationRevision).
		Scan(&oldDeclaration, &oldDeclarationSHA)
	if err != nil || oldDeclarationSHA != binding.DeclarationSHA256 ||
		!validHistoricalBlob(oldDeclaration, oldDeclarationSHA, MaxDeclarationBytes) {
		return Attempt{}, GenerationArtifacts{}, ErrHistoricalRestoreUnavailable
	}

	// Never mistake a prepared, failed or rolled-back attempt for history.
	// Archived records must match ALL three immutable payload fingerprints.
	var confirmed int
	err = tx.QueryRowContext(ctx, `SELECT
		EXISTS(SELECT 1 FROM apply_journal
			WHERE generation_id = ? AND phase = 'committed')
		OR EXISTS(SELECT 1 FROM apply_history
			WHERE generation_id = ? AND phase = 'committed'
				AND config_sha256 = ? AND manifest_sha256 = ? AND source_map_sha256 = ?)
	`, p.SourceGenerationID, p.SourceGenerationID,
		source.ConfigSHA256, source.ManifestSHA256, source.SourceMapSHA256).Scan(&confirmed)
	if err != nil {
		return Attempt{}, GenerationArtifacts{}, fmt.Errorf("verify committed historical source: %w", err)
	}
	if confirmed != 1 {
		return Attempt{}, GenerationArtifacts{}, ErrHistoricalRestoreUnavailable
	}

	// Do not prune before pinning the historical payload. Reject quota
	// pressure without touching any existing immutable generation.
	incoming := int64(len(source.ConfigJSON) + len(source.ManifestJSON) + len(source.SourceMapJSON))
	retained, err := generationBytesTx(ctx, tx)
	if err != nil {
		return Attempt{}, GenerationArtifacts{}, err
	}
	if incoming > s.retention.MaxGenerationBytes ||
		retained > s.retention.MaxGenerationBytes-incoming {
		return Attempt{}, GenerationArtifacts{}, ErrGenerationStorageBudget
	}

	now := time.Now().UTC()
	timestamp := now.Format(time.RFC3339Nano)
	generation, err := tx.ExecContext(ctx, `INSERT INTO generations (
		base_revision, target_revision, config_json, config_sha256,
		manifest_json, manifest_sha256, source_map_json, source_map_sha256,
		created_at, restore_origin_generation_id
	) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ExpectedConfigRevision, p.ExpectedConfigRevision+1,
		source.ConfigJSON, source.ConfigSHA256, source.ManifestJSON, source.ManifestSHA256,
		source.SourceMapJSON, source.SourceMapSHA256, timestamp, p.SourceGenerationID)
	if err != nil {
		return Attempt{}, GenerationArtifacts{}, fmt.Errorf("insert historical restore candidate: %w", err)
	}
	generationID, err := generation.LastInsertId()
	if err != nil {
		return Attempt{}, GenerationArtifacts{}, fmt.Errorf("read historical restore generation ID: %w", err)
	}
	journal, err := tx.ExecContext(ctx, `INSERT INTO apply_journal (
		generation_id, previous_generation_id, base_revision, target_revision,
		phase, active_slot, error, started_at, updated_at
	) VALUES (?, ?, ?, ?, ?, 1, '', ?, ?)`,
		generationID, p.ExpectedAppliedGenerationID, p.ExpectedConfigRevision,
		p.ExpectedConfigRevision+1, PhasePrepared, timestamp, timestamp)
	if err != nil {
		return Attempt{}, GenerationArtifacts{}, fmt.Errorf("insert historical restore journal: %w", err)
	}
	attemptID, err := journal.LastInsertId()
	if err != nil {
		return Attempt{}, GenerationArtifacts{}, fmt.Errorf("read historical restore attempt ID: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Attempt{}, GenerationArtifacts{}, fmt.Errorf("commit historical restore prepare: %w", err)
	}
	return Attempt{
		ID: attemptID, GenerationID: generationID,
		PreviousGenerationID: &p.ExpectedAppliedGenerationID,
		BaseRevision: p.ExpectedConfigRevision, TargetRevision: p.ExpectedConfigRevision+1,
		Phase: PhasePrepared, ConfigSHA256: source.ConfigSHA256,
		StartedAt: now, UpdatedAt: now,
	}, source, nil
}

func validHistoricalBlob(data []byte, expectedSHA string, maxBytes int) bool {
	if len(data) == 0 || len(data) > maxBytes || !json.Valid(data) || !validHistoricalSHA(expectedSHA) {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == expectedSHA
}
