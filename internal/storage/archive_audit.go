package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

// ErrArchiveDomainInvalid is intentionally opaque: source locations, node
// payloads and SQL strings must never escape in a backup preflight error.
var ErrArchiveDomainInvalid = errors.New("archive schema or domain state is inconsistent")

const (
	maxArchiveSchemaObjects    = 128
	maxArchiveSchemaTextBytes  = 1 << 20
	maxArchiveProfileSnapshots = 4096
	maxArchiveProfileNodes     = 65536
	maxArchiveProfileSources   = 2048
	maxArchiveProfileOverlays  = 65536
)

// ArchiveDomainCounts is an allowlisted, non-secret summary. It is neither
// a restore receipt nor evidence that a backup can be activated.
type ArchiveDomainCounts struct {
	ProfileSnapshots int
	ProfileNodes     int
	ProfileSources   int
	ProfileOverlays  int
}

type archiveSchemaObject struct {
	Kind      string
	Name      string
	TableName string
	SQL       sql.NullString
}

// VerifyArchivedSchemaAndDomains is READ-ONLY on the caller's independently
// deserialized, already authenticated SQLite connection. A separate scratch
// in-memory database executes the application's actual migrations, then the
// complete sqlite_schema catalog is compared exactly (including indexes,
// autoindexes and triggers). No user-controlled SQL is ever executed.
func VerifyArchivedSchemaAndDomains(
	ctx context.Context, candidate *sql.Conn,
) (ArchiveDomainCounts, error) {
	var empty ArchiveDomainCounts
	if ctx == nil || candidate == nil || ctx.Err() != nil {
		return empty, ErrArchiveDomainInvalid
	}
	referenceDB, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return empty, ErrArchiveDomainInvalid
	}
	defer referenceDB.Close()
	referenceDB.SetMaxOpenConns(1)
	if (&Store{db: referenceDB}).migrate(ctx) != nil {
		return empty, ErrArchiveDomainInvalid
	}
	reference, err := referenceDB.Conn(ctx)
	if err != nil {
		return empty, ErrArchiveDomainInvalid
	}
	defer reference.Close()
	known, err := archiveSchemaCatalog(ctx, reference)
	if err != nil {
		return empty, ErrArchiveDomainInvalid
	}
	actual, err := archiveSchemaCatalog(ctx, candidate)
	if err != nil || !reflect.DeepEqual(known, actual) {
		return empty, ErrArchiveDomainInvalid
	}
	counts, err := verifyArchiveProfileSnapshots(ctx, candidate)
	if err != nil {
		return empty, ErrArchiveDomainInvalid
	}
	counts.ProfileSources, err = verifyArchiveProfileSources(ctx, candidate)
	if err != nil {
		return empty, ErrArchiveDomainInvalid
	}
	counts.ProfileOverlays, err = verifyArchiveProfileOverlays(ctx, candidate)
	if err != nil || verifyArchiveSelection(ctx, candidate) != nil {
		return empty, ErrArchiveDomainInvalid
	}
	return counts, nil
}

func archiveSchemaCatalog(ctx context.Context, conn *sql.Conn) ([]archiveSchemaObject, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT type, name, tbl_name, sql
		FROM sqlite_schema
		ORDER BY type, name, tbl_name
		LIMIT ?`, maxArchiveSchemaObjects+1)
	if err != nil {
		return nil, ErrArchiveDomainInvalid
	}
	defer rows.Close()
	objects := make([]archiveSchemaObject, 0, 48)
	textBudget := maxArchiveSchemaTextBytes
	for rows.Next() {
		if ctx.Err() != nil || len(objects) >= maxArchiveSchemaObjects {
			return nil, ErrArchiveDomainInvalid
		}
		var item archiveSchemaObject
		if rows.Scan(&item.Kind, &item.Name, &item.TableName, &item.SQL) != nil {
			return nil, ErrArchiveDomainInvalid
		}
		textBudget -= len(item.Kind) + len(item.Name) + len(item.TableName) + len(item.SQL.String)
		if textBudget < 0 {
			return nil, ErrArchiveDomainInvalid
		}
		objects = append(objects, item)
	}
	if rows.Err() != nil {
		return nil, ErrArchiveDomainInvalid
	}
	return objects, nil
}

type archiveSnapshotHeader struct {
	id             int64
	profileID      string
	sourceKind     string
	sourceRevision string
	sourceSHA      string
	createdAt      string
}

func verifyArchiveProfileSnapshots(ctx context.Context, conn *sql.Conn) (ArchiveDomainCounts, error) {
	var counts ArchiveDomainCounts
	rows, err := conn.QueryContext(ctx, `
		SELECT id, profile_id, source_kind, source_revision, source_sha256, created_at
		FROM profile_snapshots ORDER BY id LIMIT ?`, maxArchiveProfileSnapshots+1)
	if err != nil {
		return counts, ErrArchiveDomainInvalid
	}
	headers := make([]archiveSnapshotHeader, 0)
	for rows.Next() {
		if ctx.Err() != nil || len(headers) >= maxArchiveProfileSnapshots {
			_ = rows.Close()
			return counts, ErrArchiveDomainInvalid
		}
		var h archiveSnapshotHeader
		if rows.Scan(&h.id, &h.profileID, &h.sourceKind, &h.sourceRevision, &h.sourceSHA, &h.createdAt) != nil ||
			h.id <= 0 || profile.ValidateProfileID(h.profileID) != nil ||
			validateProfileSnapshotText("kind", h.sourceKind, true, 128) != nil ||
			validateProfileSnapshotText("revision", h.sourceRevision, false, 4096) != nil ||
			!archiveLowerSHA(h.sourceSHA) || !archiveTimestamp(h.createdAt) {
			_ = rows.Close()
			return counts, ErrArchiveDomainInvalid
		}
		headers = append(headers, h)
	}
	err = rows.Err()
	closeErr := rows.Close()
	if err != nil || closeErr != nil {
		return counts, ErrArchiveDomainInvalid
	}
	byID := make(map[int64]string, len(headers))
	for _, header := range headers {
		byID[header.id] = header.profileID
		nodes, err := verifyArchivedSnapshotNodes(ctx, conn, header.id)
		if err != nil || nodes > maxArchiveProfileNodes-counts.ProfileNodes {
			return ArchiveDomainCounts{}, ErrArchiveDomainInvalid
		}
		counts.ProfileSnapshots++
		counts.ProfileNodes += nodes
	}
	state, err := conn.QueryContext(ctx, `
		SELECT profile_id, current_snapshot_id, previous_snapshot_id
		FROM profile_state ORDER BY profile_id LIMIT ?`, maxArchiveProfileSnapshots+1)
	if err != nil {
		return ArchiveDomainCounts{}, ErrArchiveDomainInvalid
	}
	defer state.Close()
	matches := 0
	for state.Next() {
		if ctx.Err() != nil || matches >= maxArchiveProfileSnapshots {
			return ArchiveDomainCounts{}, ErrArchiveDomainInvalid
		}
		var profileID string
		var current int64
		var previous sql.NullInt64
		if state.Scan(&profileID, &current, &previous) != nil ||
			profile.ValidateProfileID(profileID) != nil ||
			byID[current] != profileID ||
			(previous.Valid && (previous.Int64 == current || byID[previous.Int64] != profileID)) {
			return ArchiveDomainCounts{}, ErrArchiveDomainInvalid
		}
		matches++
	}
	if state.Err() != nil {
		return ArchiveDomainCounts{}, ErrArchiveDomainInvalid
	}
	return counts, nil
}

func verifyArchivedSnapshotNodes(ctx context.Context, conn *sql.Conn, id int64) (int, error) {
	rows, err := conn.QueryContext(ctx, `
		SELECT ordinal, node_id, source_key, source_name, payload_json, payload_sha256
		FROM profile_snapshot_nodes WHERE snapshot_id = ?
		ORDER BY ordinal LIMIT ?`, id, maxArchiveProfileNodes+1)
	if err != nil {
		return 0, ErrArchiveDomainInvalid
	}
	defer rows.Close()
	count, bytesTotal := 0, 0
	for rows.Next() {
		if ctx.Err() != nil || count >= maxArchiveProfileNodes {
			return 0, ErrArchiveDomainInvalid
		}
		var ordinal int
		var nodeID, sourceKey, sourceName, payloadSHA string
		var payload []byte
		if rows.Scan(&ordinal, &nodeID, &sourceKey, &sourceName, &payload, &payloadSHA) != nil ||
			ordinal != count || profile.ValidateNodeID(nodeID) != nil ||
			!archiveNodeSourceKey(sourceKey) ||
			!archiveNodeName(sourceName) ||
			len(payload) == 0 || len(payload) > MaxProfileNodePayloadBytes ||
			!json.Valid(payload) || !archiveLowerSHA(payloadSHA) ||
			archiveSHA(payload) != payloadSHA {
			return 0, ErrArchiveDomainInvalid
		}
		bytesTotal += len(payload)
		if bytesTotal > MaxProfileSnapshotPayloadBytes {
			return 0, ErrArchiveDomainInvalid
		}
		count++
	}
	if rows.Err() != nil {
		return 0, ErrArchiveDomainInvalid
	}
	return count, nil
}

func verifyArchiveProfileSources(ctx context.Context, conn *sql.Conn) (int, error) {
	rows, err := conn.QueryContext(ctx, profileSourceSelect+
		" ORDER BY s.profile_id LIMIT ?", maxArchiveProfileSources+1)
	if err != nil {
		return 0, ErrArchiveDomainInvalid
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		if ctx.Err() != nil || count >= maxArchiveProfileSources {
			return 0, ErrArchiveDomainInvalid
		}
		state, err := scanProfileSource(rows)
		if err != nil || state.Revision == 0 ||
			(state.ActiveUpdateID != "" && validateProfileUpdateID(state.ActiveUpdateID) != nil) {
			return 0, ErrArchiveDomainInvalid
		}
		count++
	}
	if rows.Err() != nil {
		return 0, ErrArchiveDomainInvalid
	}
	return count, nil
}

func verifyArchiveProfileOverlays(ctx context.Context, conn *sql.Conn) (int, error) {
	rows, err := conn.QueryContext(ctx, profileNodeOverlaySelect+
		" ORDER BY profile_id, node_id LIMIT ?", maxArchiveProfileOverlays+1)
	if err != nil {
		return 0, ErrArchiveDomainInvalid
	}
	defer rows.Close()
	count := 0
	byProfile := map[string]int{}
	for rows.Next() {
		if ctx.Err() != nil || count >= maxArchiveProfileOverlays {
			return 0, ErrArchiveDomainInvalid
		}
		state, err := scanProfileNodeOverlay(rows)
		if err != nil || state.Revision == 0 {
			return 0, ErrArchiveDomainInvalid
		}
		byProfile[state.Overlay.ProfileID]++
		if byProfile[state.Overlay.ProfileID] > MaxProfileNodeOverlaysPerProfile {
			return 0, ErrArchiveDomainInvalid
		}
		count++
	}
	if rows.Err() != nil {
		return 0, ErrArchiveDomainInvalid
	}
	return count, nil
}

func verifyArchiveSelection(ctx context.Context, conn *sql.Conn) error {
	var target []byte
	var when sql.NullString
	var revision int64
	if conn.QueryRowContext(ctx, `
		SELECT current_target_json, updated_at, revision
		FROM selection_state WHERE singleton=1`).Scan(&target, &when, &revision) != nil ||
		revision < 0 || len(target) > MaxSelectionTargetBytes {
		return ErrArchiveDomainInvalid
	}
	if len(target) > 0 &&
		(!json.Valid(target) || !when.Valid || !archiveTimestamp(when.String)) {
		return ErrArchiveDomainInvalid
	}
	return nil
}

func archiveTimestamp(value string) bool {
	_, err := time.Parse(time.RFC3339Nano, value)
	return err == nil
}

func archiveLowerSHA(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && strings.ToLower(value) == value
}

func archiveSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func archiveNodeSourceKey(value string) bool {
	if len(value) == 0 || len(value) > 4096 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func archiveNodeName(value string) bool {
	if len(value) == 0 || len(value) > 4096 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
