package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

const (
	MaxProfileNodePayloadBytes     = 1 << 20
	MaxProfileSnapshotPayloadBytes = 64 << 20
)

var (
	ErrInvalidProfileSnapshot = errors.New("invalid profile snapshot")
	ErrEmptyProfileSnapshot   = errors.New("empty profile snapshot requires explicit confirmation")
	ErrProfileSnapshotMissing = errors.New("profile snapshot not found")
)

type ProfileSnapshotCandidate struct {
	ProfileID      string
	SourceKind     string
	SourceRevision string
	SourceSHA256   string
	Nodes          []profile.SourceNode
}

type ProfileSnapshotCommitOptions struct {
	AllowEmpty bool
}

type ProfileSnapshotNode struct {
	Identity      profile.NodeIdentity
	PayloadJSON   []byte
	PayloadSHA256 string
}

type ProfileSnapshot struct {
	ID             int64
	ProfileID      string
	SourceKind     string
	SourceRevision string
	SourceSHA256   string
	CreatedAt      time.Time
	Nodes          []ProfileSnapshotNode
}

type ProfileSnapshotCommit struct {
	Snapshot ProfileSnapshot
	Added    []profile.NodeIdentity
	Removed  []profile.NodeIdentity
	Renamed  []profile.NodeRename
}

func (s *Store) CommitProfileSnapshot(
	ctx context.Context,
	candidate ProfileSnapshotCandidate,
	options ProfileSnapshotCommitOptions,
) (ProfileSnapshotCommit, error) {
	if err := validateProfileSnapshotCandidate(candidate); err != nil {
		return ProfileSnapshotCommit{}, err
	}
	if len(candidate.Nodes) == 0 && !options.AllowEmpty {
		return ProfileSnapshotCommit{}, ErrEmptyProfileSnapshot
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProfileSnapshotCommit{}, fmt.Errorf("begin profile snapshot transaction: %w", err)
	}
	defer tx.Rollback()

	var currentID, previousID sql.NullInt64
	err = tx.QueryRowContext(ctx, `
		SELECT current_snapshot_id, previous_snapshot_id
		FROM profile_state
		WHERE profile_id = ?
	`, candidate.ProfileID).Scan(&currentID, &previousID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ProfileSnapshotCommit{}, fmt.Errorf("read profile state: %w", err)
	}

	var previous []profile.NodeIdentity
	if currentID.Valid {
		previous, err = readProfileSnapshotNodesTx(ctx, tx, currentID.Int64, candidate.ProfileID)
		if err != nil {
			return ProfileSnapshotCommit{}, err
		}
	}
	reconciled, err := profile.ReconcileNodeIdentities(candidate.ProfileID, previous, candidate.Nodes)
	if err != nil {
		return ProfileSnapshotCommit{}, fmt.Errorf("%w: reconcile profile nodes: %v", ErrInvalidProfileSnapshot, err)
	}

	payloadByKey := make(map[string][]byte, len(candidate.Nodes))
	for _, node := range candidate.Nodes {
		payloadByKey[node.SourceKey] = node.PayloadJSON
	}

	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `
		INSERT INTO profile_snapshots(
			profile_id,
			source_kind,
			source_revision,
			source_sha256,
			created_at
		)
		VALUES(?, ?, ?, ?, ?)
	`,
		candidate.ProfileID,
		candidate.SourceKind,
		candidate.SourceRevision,
		strings.ToLower(candidate.SourceSHA256),
		now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return ProfileSnapshotCommit{}, fmt.Errorf("insert profile snapshot: %w", err)
	}
	snapshotID, err := result.LastInsertId()
	if err != nil {
		return ProfileSnapshotCommit{}, fmt.Errorf("read profile snapshot id: %w", err)
	}

	snapshotNodes := make([]ProfileSnapshotNode, 0, len(reconciled.Current))
	for ordinal, node := range reconciled.Current {
		payload, exists := payloadByKey[node.SourceKey]
		if !exists {
			return ProfileSnapshotCommit{}, fmt.Errorf("%w: reconciled node %q has no payload", ErrInvalidProfileSnapshot, node.SourceKey)
		}
		sum := sha256.Sum256(payload)
		payloadHash := hex.EncodeToString(sum[:])
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO profile_snapshot_nodes(
				snapshot_id,
				ordinal,
				node_id,
				source_key,
				source_name,
				payload_json,
				payload_sha256
			)
			VALUES(?, ?, ?, ?, ?, ?, ?)
		`, snapshotID, ordinal, node.NodeID, node.SourceKey, node.SourceName, payload, payloadHash); err != nil {
			return ProfileSnapshotCommit{}, fmt.Errorf("insert profile snapshot node %d: %w", ordinal, err)
		}
		snapshotNodes = append(snapshotNodes, ProfileSnapshotNode{
			Identity:      node,
			PayloadJSON:   append([]byte(nil), payload...),
			PayloadSHA256: payloadHash,
		})
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO profile_state(profile_id, current_snapshot_id, previous_snapshot_id, updated_at)
		VALUES(?, ?, NULL, ?)
		ON CONFLICT(profile_id) DO UPDATE SET
			previous_snapshot_id = profile_state.current_snapshot_id,
			current_snapshot_id = excluded.current_snapshot_id,
			updated_at = excluded.updated_at
	`, candidate.ProfileID, snapshotID, now.Format(time.RFC3339Nano)); err != nil {
		return ProfileSnapshotCommit{}, fmt.Errorf("advance profile snapshot pointer: %w", err)
	}

	var keepPrevious any
	if currentID.Valid {
		keepPrevious = currentID.Int64
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM profile_snapshots
		WHERE profile_id = ?
		  AND id <> ?
		  AND (? IS NULL OR id <> ?)
	`, candidate.ProfileID, snapshotID, keepPrevious, keepPrevious); err != nil {
		return ProfileSnapshotCommit{}, fmt.Errorf("prune old profile snapshots: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return ProfileSnapshotCommit{}, fmt.Errorf("commit profile snapshot: %w", err)
	}

	return ProfileSnapshotCommit{
		Snapshot: ProfileSnapshot{
			ID:             snapshotID,
			ProfileID:      candidate.ProfileID,
			SourceKind:     candidate.SourceKind,
			SourceRevision: candidate.SourceRevision,
			SourceSHA256:   strings.ToLower(candidate.SourceSHA256),
			CreatedAt:      now,
			Nodes:          snapshotNodes,
		},
		Added:   append([]profile.NodeIdentity(nil), reconciled.Added...),
		Removed: append([]profile.NodeIdentity(nil), reconciled.Removed...),
		Renamed: append([]profile.NodeRename(nil), reconciled.Renamed...),
	}, nil
}

func (s *Store) CurrentProfileSnapshot(ctx context.Context, profileID string) (ProfileSnapshot, bool, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return ProfileSnapshot{}, false, err
	}
	var snapshotID sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `
		SELECT current_snapshot_id
		FROM profile_state
		WHERE profile_id = ?
	`, profileID).Scan(&snapshotID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProfileSnapshot{}, false, nil
		}
		return ProfileSnapshot{}, false, fmt.Errorf("read current profile snapshot pointer: %w", err)
	}
	if !snapshotID.Valid {
		return ProfileSnapshot{}, false, nil
	}
	snapshot, err := readProfileSnapshot(ctx, s.db, snapshotID.Int64, profileID)
	if err != nil {
		return ProfileSnapshot{}, false, err
	}
	return snapshot, true, nil
}

func (s *Store) PreviousProfileSnapshot(ctx context.Context, profileID string) (ProfileSnapshot, bool, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return ProfileSnapshot{}, false, err
	}
	var snapshotID sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `
		SELECT previous_snapshot_id
		FROM profile_state
		WHERE profile_id = ?
	`, profileID).Scan(&snapshotID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProfileSnapshot{}, false, nil
		}
		return ProfileSnapshot{}, false, fmt.Errorf("read previous profile snapshot pointer: %w", err)
	}
	if !snapshotID.Valid {
		return ProfileSnapshot{}, false, nil
	}
	snapshot, err := readProfileSnapshot(ctx, s.db, snapshotID.Int64, profileID)
	if err != nil {
		return ProfileSnapshot{}, false, err
	}
	return snapshot, true, nil
}

type queryRower interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func readProfileSnapshot(ctx context.Context, db queryRower, snapshotID int64, profileID string) (ProfileSnapshot, error) {
	var snapshot ProfileSnapshot
	var createdAt string
	if err := db.QueryRowContext(ctx, `
		SELECT id, profile_id, source_kind, source_revision, source_sha256, created_at
		FROM profile_snapshots
		WHERE id = ? AND profile_id = ?
	`, snapshotID, profileID).Scan(
		&snapshot.ID,
		&snapshot.ProfileID,
		&snapshot.SourceKind,
		&snapshot.SourceRevision,
		&snapshot.SourceSHA256,
		&createdAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProfileSnapshot{}, ErrProfileSnapshotMissing
		}
		return ProfileSnapshot{}, fmt.Errorf("read profile snapshot %d: %w", snapshotID, err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return ProfileSnapshot{}, fmt.Errorf("parse profile snapshot created_at: %w", err)
	}
	snapshot.CreatedAt = parsed

	rows, err := db.QueryContext(ctx, `
		SELECT node_id, source_key, source_name, payload_json, payload_sha256
		FROM profile_snapshot_nodes
		WHERE snapshot_id = ?
		ORDER BY ordinal
	`, snapshotID)
	if err != nil {
		return ProfileSnapshot{}, fmt.Errorf("list profile snapshot nodes: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		node := ProfileSnapshotNode{
			Identity: profile.NodeIdentity{ProfileID: profileID},
		}
		if err := rows.Scan(
			&node.Identity.NodeID,
			&node.Identity.SourceKey,
			&node.Identity.SourceName,
			&node.PayloadJSON,
			&node.PayloadSHA256,
		); err != nil {
			return ProfileSnapshot{}, fmt.Errorf("scan profile snapshot node: %w", err)
		}
		sum := sha256.Sum256(node.PayloadJSON)
		if hex.EncodeToString(sum[:]) != node.PayloadSHA256 {
			return ProfileSnapshot{}, fmt.Errorf("%w: node %q payload SHA-256 mismatch", ErrInvalidProfileSnapshot, node.Identity.SourceKey)
		}
		node.PayloadJSON = append([]byte(nil), node.PayloadJSON...)
		snapshot.Nodes = append(snapshot.Nodes, node)
	}
	if err := rows.Err(); err != nil {
		return ProfileSnapshot{}, fmt.Errorf("iterate profile snapshot nodes: %w", err)
	}
	return snapshot, nil
}

func readProfileSnapshotNodesTx(ctx context.Context, tx *sql.Tx, snapshotID int64, profileID string) ([]profile.NodeIdentity, error) {
	snapshot, err := readProfileSnapshot(ctx, tx, snapshotID, profileID)
	if err != nil {
		return nil, err
	}
	result := make([]profile.NodeIdentity, 0, len(snapshot.Nodes))
	for _, node := range snapshot.Nodes {
		result = append(result, node.Identity)
	}
	return result, nil
}

func validateProfileSnapshotCandidate(candidate ProfileSnapshotCandidate) error {
	if err := profile.ValidateProfileID(candidate.ProfileID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProfileSnapshot, err)
	}
	if err := validateProfileSnapshotText("source kind", candidate.SourceKind, true, 128); err != nil {
		return err
	}
	if err := validateProfileSnapshotText("source revision", candidate.SourceRevision, false, 4096); err != nil {
		return err
	}
	decoded, err := hex.DecodeString(candidate.SourceSHA256)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("%w: source SHA-256 must be 64 hexadecimal characters", ErrInvalidProfileSnapshot)
	}
	totalPayload := 0
	for i, node := range candidate.Nodes {
		if len(node.PayloadJSON) == 0 || !json.Valid(node.PayloadJSON) {
			return fmt.Errorf("%w: node %d payload must be non-empty valid JSON", ErrInvalidProfileSnapshot, i)
		}
		if len(node.PayloadJSON) > MaxProfileNodePayloadBytes {
			return fmt.Errorf(
				"%w: node %d payload %d bytes exceeds %d bytes",
				ErrInvalidProfileSnapshot,
				i,
				len(node.PayloadJSON),
				MaxProfileNodePayloadBytes,
			)
		}
		totalPayload += len(node.PayloadJSON)
		if totalPayload > MaxProfileSnapshotPayloadBytes {
			return fmt.Errorf(
				"%w: profile node payload total exceeds %d bytes",
				ErrInvalidProfileSnapshot,
				MaxProfileSnapshotPayloadBytes,
			)
		}
	}
	return nil
}

func validateProfileSnapshotText(label, value string, required bool, limit int) error {
	if required && value == "" {
		return fmt.Errorf("%w: %s must not be empty", ErrInvalidProfileSnapshot, label)
	}
	if len(value) > limit {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidProfileSnapshot, label, limit)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: %s must not have leading or trailing whitespace", ErrInvalidProfileSnapshot, label)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidProfileSnapshot, label)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalidProfileSnapshot, label)
		}
	}
	return nil
}
