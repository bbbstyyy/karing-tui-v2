package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

var (
	ErrProfileSourceNotFound         = errors.New("profile source not found")
	ErrProfileSourceRevisionConflict = errors.New("profile source revision conflict")
	ErrProfileSourceDisabled         = errors.New("profile source is disabled")
	ErrProfileUpdateInProgress       = errors.New("profile update already in progress")
	ErrProfileUpdateLeaseMismatch    = errors.New("profile update lease does not match active update")
	ErrInvalidProfileUpdateID        = errors.New("invalid profile update ID")
	ErrInvalidProfileUpdateStatus    = errors.New("invalid profile update status")
)

type ProfileSourceState struct {
	Revision                   uint64
	Spec                       profile.SourceSpec
	CreatedAt                  time.Time
	UpdatedAt                  time.Time
	LastAttemptAt              *time.Time
	LastSuccessAt              *time.Time
	LastError                  string
	LastSourceRevision         string
	ETag                       string
	LastModified               string
	SubscriptionUsage             *profile.SubscriptionUsage
	SubscriptionUsageUpdatedAt    *time.Time
	SubscriptionMetadataObservedAt *time.Time
	LastMetadataError             string
	ConsecutiveFailures        uint32
	RetryAfterAt               *time.Time
	ActiveUpdateID             string
	ActiveUpdateStarted        *time.Time
	CurrentSnapshotID          *int64
}

type ProfileUpdateSuccess struct {
	SourceRevision        string
	ETag                  string
	LastModified          string
	UsageMetadataObserved bool
	SubscriptionUsage     *profile.SubscriptionUsage
	UsageMetadataError    string
}

type ProfileUpdateLease struct {
	ID             string
	ProfileID      string
	SourceRevision uint64
	StartedAt      time.Time
}

type InterruptedProfileUpdate struct {
	ProfileID string
	UpdateID  string
	StartedAt time.Time
}

func (s *Store) CommitProfileSource(
	ctx context.Context,
	expectedRevision uint64,
	spec profile.SourceSpec,
) (ProfileSourceState, error) {
	if err := spec.Validate(); err != nil {
		return ProfileSourceState{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProfileSourceState{}, fmt.Errorf("begin profile source transaction: %w", err)
	}
	defer tx.Rollback()

	var (
		currentRevision       int64
		activeUpdate          sql.NullString
		currentSpec           profile.SourceSpec
		currentEnabled        int
		currentUpdateInterval int64
	)
	err = tx.QueryRowContext(ctx, `
		SELECT
			revision,
			active_update_id,
			source_format,
			location_kind,
			location,
			user_agent,
			fetch_mode,
			fetch_profile_id,
			fetch_node_id,
			enabled,
			update_interval_seconds
		FROM profile_sources
		WHERE profile_id = ?
	`, spec.ProfileID).Scan(
		&currentRevision,
		&activeUpdate,
		&currentSpec.Format,
		&currentSpec.LocationKind,
		&currentSpec.Location,
		&currentSpec.UserAgent,
		&currentSpec.Fetch.Mode,
		&currentSpec.Fetch.ProfileID,
		&currentSpec.Fetch.NodeID,
		&currentEnabled,
		&currentUpdateInterval,
	)
	currentSpec.Enabled = currentEnabled != 0
	currentSpec.UpdateInterval = time.Duration(currentUpdateInterval) * time.Second
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if expectedRevision != 0 {
			return ProfileSourceState{}, fmt.Errorf(
				"%w: expected %d, current 0",
				ErrProfileSourceRevisionConflict,
				expectedRevision,
			)
		}
		now := time.Now().UTC()
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO profile_sources(
				profile_id,
				revision,
				source_format,
				location_kind,
				location,
				user_agent,
				fetch_mode,
				fetch_profile_id,
				fetch_node_id,
				filter_method,
				filter_expression,
				filter_match_attribute,
				enabled,
				update_interval_seconds,
				created_at,
				updated_at
			)
			VALUES(?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			spec.ProfileID,
			spec.Format,
			spec.LocationKind,
			spec.Location,
			spec.UserAgent,
			spec.Fetch.Mode,
			spec.Fetch.ProfileID,
			spec.Fetch.NodeID,
			spec.Filter.Method,
			spec.Filter.KeywordOrRegex,
			boolInt(spec.Filter.MatchAttribute),
			boolInt(spec.Enabled),
			int64(spec.UpdateInterval/time.Second),
			now.Format(time.RFC3339Nano),
			now.Format(time.RFC3339Nano),
		); err != nil {
			return ProfileSourceState{}, fmt.Errorf("insert profile source: %w", err)
		}
	case err != nil:
		return ProfileSourceState{}, fmt.Errorf("read profile source before commit: %w", err)
	default:
		if uint64(currentRevision) != expectedRevision {
			return ProfileSourceState{}, fmt.Errorf(
				"%w: expected %d, current %d",
				ErrProfileSourceRevisionConflict,
				expectedRevision,
				currentRevision,
			)
		}
		if activeUpdate.Valid {
			return ProfileSourceState{}, fmt.Errorf("%w: %s", ErrProfileUpdateInProgress, activeUpdate.String)
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		result, err := tx.ExecContext(ctx, `
			UPDATE profile_sources
			SET revision = revision + 1,
				source_format = ?,
				location_kind = ?,
				location = ?,
				user_agent = ?,
				fetch_mode = ?,
				fetch_profile_id = ?,
				fetch_node_id = ?,
				filter_method = ?,
				filter_expression = ?,
				filter_match_attribute = ?,
				enabled = ?,
				update_interval_seconds = ?,
				updated_at = ?
			WHERE profile_id = ? AND revision = ?
		`,
			spec.Format,
			spec.LocationKind,
			spec.Location,
			spec.UserAgent,
			spec.Fetch.Mode,
			spec.Fetch.ProfileID,
			spec.Fetch.NodeID,
			spec.Filter.Method,
			spec.Filter.KeywordOrRegex,
			boolInt(spec.Filter.MatchAttribute),
			boolInt(spec.Enabled),
			int64(spec.UpdateInterval/time.Second),
			now,
			spec.ProfileID,
			currentRevision,
		)
		if err != nil {
			return ProfileSourceState{}, fmt.Errorf("update profile source: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return ProfileSourceState{}, fmt.Errorf("read profile source update result: %w", err)
		}
		if affected != 1 {
			return ProfileSourceState{}, ErrProfileSourceRevisionConflict
		}
		if sourceFetchIdentityChanged(currentSpec, spec) {
			if _, err := tx.ExecContext(ctx, `
				UPDATE profile_sources
				SET last_attempt_at = NULL,
					last_success_at = NULL,
					last_error = '',
					last_source_revision = '',
					etag = '',
					last_modified = '',
					subscription_upload_bytes = NULL,
					subscription_download_bytes = NULL,
					subscription_total_bytes = NULL,
					subscription_expires_at = NULL,
					subscription_usage_updated_at = NULL,
					subscription_metadata_observed_at = NULL,
					subscription_metadata_error = '',
					consecutive_failures = 0,
					retry_after_at = NULL
				WHERE profile_id = ? AND revision = ?
			`, spec.ProfileID, currentRevision+1); err != nil {
				return ProfileSourceState{}, fmt.Errorf("reset profile source fetch state: %w", err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return ProfileSourceState{}, fmt.Errorf("commit profile source: %w", err)
	}
	return s.ProfileSource(ctx, spec.ProfileID)
}

func sourceFetchIdentityChanged(before, after profile.SourceSpec) bool {
	return before.Format != after.Format ||
		before.LocationKind != after.LocationKind ||
		before.Location != after.Location ||
		before.UserAgent != after.UserAgent ||
		before.Fetch.Mode != after.Fetch.Mode ||
		before.Fetch.ProfileID != after.Fetch.ProfileID ||
		before.Fetch.NodeID != after.Fetch.NodeID
}

func (s *Store) ProfileSource(ctx context.Context, profileID string) (ProfileSourceState, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return ProfileSourceState{}, err
	}
	row := s.db.QueryRowContext(ctx, profileSourceSelect+` WHERE s.profile_id = ?`, profileID)
	return scanProfileSource(row)
}

func (s *Store) ListProfileSources(ctx context.Context) ([]ProfileSourceState, error) {
	rows, err := s.db.QueryContext(ctx, profileSourceSelect+` ORDER BY s.profile_id`)
	if err != nil {
		return nil, fmt.Errorf("list profile sources: %w", err)
	}
	defer rows.Close()

	var result []ProfileSourceState
	for rows.Next() {
		state, err := scanProfileSource(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, state)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate profile sources: %w", err)
	}
	return result, nil
}

func (s *Store) BeginProfileUpdate(
	ctx context.Context,
	profileID string,
	expectedSourceRevision uint64,
	updateID string,
) (ProfileUpdateLease, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return ProfileUpdateLease{}, err
	}
	if err := validateProfileUpdateID(updateID); err != nil {
		return ProfileUpdateLease{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ProfileUpdateLease{}, fmt.Errorf("begin profile update lease transaction: %w", err)
	}
	defer tx.Rollback()

	var (
		revision     int64
		enabled      int
		activeUpdate sql.NullString
	)
	err = tx.QueryRowContext(ctx, `
		SELECT revision, enabled, active_update_id
		FROM profile_sources
		WHERE profile_id = ?
	`, profileID).Scan(&revision, &enabled, &activeUpdate)
	if errors.Is(err, sql.ErrNoRows) {
		return ProfileUpdateLease{}, ErrProfileSourceNotFound
	}
	if err != nil {
		return ProfileUpdateLease{}, fmt.Errorf("read profile source before update: %w", err)
	}
	if uint64(revision) != expectedSourceRevision {
		return ProfileUpdateLease{}, fmt.Errorf(
			"%w: expected %d, current %d",
			ErrProfileSourceRevisionConflict,
			expectedSourceRevision,
			revision,
		)
	}
	if enabled == 0 {
		return ProfileUpdateLease{}, ErrProfileSourceDisabled
	}
	if activeUpdate.Valid {
		return ProfileUpdateLease{}, fmt.Errorf("%w: %s", ErrProfileUpdateInProgress, activeUpdate.String)
	}

	now := time.Now().UTC()
	result, err := tx.ExecContext(ctx, `
		UPDATE profile_sources
		SET active_update_id = ?,
			active_update_started_at = ?,
			last_attempt_at = ?
		WHERE profile_id = ?
		  AND revision = ?
		  AND active_update_id IS NULL
	`,
		updateID,
		now.Format(time.RFC3339Nano),
		now.Format(time.RFC3339Nano),
		profileID,
		revision,
	)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "unique") {
			return ProfileUpdateLease{}, ErrProfileUpdateInProgress
		}
		return ProfileUpdateLease{}, fmt.Errorf("acquire profile update lease: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return ProfileUpdateLease{}, fmt.Errorf("read profile update lease result: %w", err)
	}
	if affected != 1 {
		return ProfileUpdateLease{}, ErrProfileUpdateInProgress
	}

	if err := tx.Commit(); err != nil {
		return ProfileUpdateLease{}, fmt.Errorf("commit profile update lease: %w", err)
	}
	return ProfileUpdateLease{
		ID:             updateID,
		ProfileID:      profileID,
		SourceRevision: uint64(revision),
		StartedAt:      now,
	}, nil
}

func (s *Store) FinishProfileUpdateSuccess(
	ctx context.Context,
	lease ProfileUpdateLease,
	success ProfileUpdateSuccess,
) error {
	if err := validateProfileUpdateLease(lease); err != nil {
		return err
	}
	if err := validateProfileUpdateSuccess(success); err != nil {
		return err
	}
	return finishProfileUpdateSuccessWith(ctx, s.db, lease, success)
}

type profileUpdateExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func finishProfileUpdateSuccessWith(
	ctx context.Context,
	execer profileUpdateExecer,
	lease ProfileUpdateLease,
	success ProfileUpdateSuccess,
) error {
	now := time.Now().UTC()
	observed := boolInt(success.UsageMetadataObserved)
	usagePresent := 0
	var (
		uploadBytes   any
		downloadBytes any
		totalBytes    any
		expiresAt     any
		usageUpdated  any
	)
	if success.SubscriptionUsage != nil {
		usagePresent = 1
		uploadBytes = nullableInt64Pointer(success.SubscriptionUsage.UploadBytes)
		downloadBytes = nullableInt64Pointer(success.SubscriptionUsage.DownloadBytes)
		totalBytes = nullableInt64Pointer(success.SubscriptionUsage.TotalBytes)
		if success.SubscriptionUsage.ExpiresAt != nil {
			expiresAt = success.SubscriptionUsage.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		usageUpdated = now.Format(time.RFC3339Nano)
	}
	result, err := execer.ExecContext(ctx, `
		UPDATE profile_sources
		SET active_update_id = NULL,
			active_update_started_at = NULL,
			last_success_at = ?,
			last_error = '',
			last_source_revision = ?,
			etag = ?,
			last_modified = ?,
			subscription_metadata_error = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_metadata_error
			END,
			subscription_upload_bytes = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_upload_bytes
			END,
			subscription_download_bytes = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_download_bytes
			END,
			subscription_total_bytes = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_total_bytes
			END,
			subscription_expires_at = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_expires_at
			END,
			subscription_usage_updated_at = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_usage_updated_at
			END,
			subscription_metadata_observed_at = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_metadata_observed_at
			END,
			consecutive_failures = 0,
			retry_after_at = NULL
		WHERE profile_id = ?
		  AND revision = ?
		  AND active_update_id = ?
	`,
		now.Format(time.RFC3339Nano),
		success.SourceRevision,
		success.ETag,
		success.LastModified,
		observed,
		success.UsageMetadataError,
		usagePresent,
		uploadBytes,
		usagePresent,
		downloadBytes,
		usagePresent,
		totalBytes,
		usagePresent,
		expiresAt,
		usagePresent,
		usageUpdated,
		observed,
		now.Format(time.RFC3339Nano),
		lease.ProfileID,
		lease.SourceRevision,
		lease.ID,
	)
	if err != nil {
		return fmt.Errorf("finish successful profile update: %w", err)
	}
	return requireProfileUpdateLeaseResult(result)
}

func validateProfileUpdateSuccess(success ProfileUpdateSuccess) error {
	if err := validateProfileUpdateStatusText("source revision", success.SourceRevision, 4096, false); err != nil {
		return err
	}
	if err := validateProfileUpdateStatusText("ETag", success.ETag, 4096, false); err != nil {
		return err
	}
	if err := validateProfileUpdateStatusText("Last-Modified", success.LastModified, 4096, false); err != nil {
		return err
	}
	if err := validateProfileUpdateStatusText("subscription metadata error", success.UsageMetadataError, 2048, false); err != nil {
		return err
	}
	if success.SubscriptionUsage != nil {
		if err := success.SubscriptionUsage.Validate(); err != nil {
			return err
		}
		if !success.UsageMetadataObserved || success.UsageMetadataError != "" {
			return ErrInvalidProfileUpdateStatus
		}
	}
	if success.UsageMetadataError != "" && !success.UsageMetadataObserved {
		return ErrInvalidProfileUpdateStatus
	}
	if success.UsageMetadataObserved && success.SubscriptionUsage == nil && success.UsageMetadataError == "" {
		return ErrInvalidProfileUpdateStatus
	}
	return nil
}

func (s *Store) CommitProfileSubscriptionMetadata(
	ctx context.Context,
	profileID string,
	expectedRevision uint64,
	observedAt time.Time,
	observed bool,
	usage *profile.SubscriptionUsage,
	metadataError string,
) (bool, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return false, err
	}
	if expectedRevision == 0 || observedAt.IsZero() {
		return false, ErrInvalidProfileUpdateStatus
	}
	observedAt = observedAt.UTC()
	if err := validateProfileUpdateStatusText(
		"subscription metadata error",
		metadataError,
		2048,
		false,
	); err != nil {
		return false, err
	}
	if usage != nil {
		if err := usage.Validate(); err != nil {
			return false, err
		}
		if !observed || metadataError != "" {
			return false, ErrInvalidProfileUpdateStatus
		}
	}
	if metadataError != "" && !observed {
		return false, ErrInvalidProfileUpdateStatus
	}
	if observed && usage == nil && metadataError == "" {
		return false, ErrInvalidProfileUpdateStatus
	}
	if !observed && (usage != nil || metadataError != "") {
		return false, ErrInvalidProfileUpdateStatus
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin profile metadata transaction: %w", err)
	}
	defer tx.Rollback()

	var (
		revision        int64
		activeUpdate    sql.NullString
		currentObserved sql.NullString
	)
	err = tx.QueryRowContext(ctx, `
		SELECT revision, active_update_id, subscription_metadata_observed_at
		FROM profile_sources
		WHERE profile_id = ?
	`, profileID).Scan(&revision, &activeUpdate, &currentObserved)
	if errors.Is(err, sql.ErrNoRows) {
		return false, ErrProfileSourceNotFound
	}
	if err != nil {
		return false, fmt.Errorf("read profile source before metadata update: %w", err)
	}
	if uint64(revision) != expectedRevision {
		return false, fmt.Errorf(
			"%w: expected %d, current %d",
			ErrProfileSourceRevisionConflict,
			expectedRevision,
			revision,
		)
	}
	if activeUpdate.Valid {
		return false, fmt.Errorf("%w: %s", ErrProfileUpdateInProgress, activeUpdate.String)
	}
	if currentObserved.Valid {
		current, err := time.Parse(time.RFC3339Nano, currentObserved.String)
		if err != nil {
			return false, fmt.Errorf("parse existing subscription metadata observation: %w", err)
		}
		if !observedAt.After(current) {
			return false, nil
		}
	}
	if !observed {
		return false, nil
	}

	usagePresent := 0
	var (
		uploadBytes   any
		downloadBytes any
		totalBytes    any
		expiresAt     any
		usageUpdated  any
	)
	if usage != nil {
		usagePresent = 1
		uploadBytes = nullableInt64Pointer(usage.UploadBytes)
		downloadBytes = nullableInt64Pointer(usage.DownloadBytes)
		totalBytes = nullableInt64Pointer(usage.TotalBytes)
		if usage.ExpiresAt != nil {
			expiresAt = usage.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		usageUpdated = observedAt.Format(time.RFC3339Nano)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE profile_sources
		SET subscription_metadata_observed_at = ?,
			subscription_metadata_error = ?,
			subscription_upload_bytes = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_upload_bytes
			END,
			subscription_download_bytes = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_download_bytes
			END,
			subscription_total_bytes = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_total_bytes
			END,
			subscription_expires_at = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_expires_at
			END,
			subscription_usage_updated_at = CASE
				WHEN ? = 1 THEN ?
				ELSE subscription_usage_updated_at
			END
		WHERE profile_id = ?
		  AND revision = ?
		  AND active_update_id IS NULL
	`,
		observedAt.Format(time.RFC3339Nano),
		metadataError,
		usagePresent,
		uploadBytes,
		usagePresent,
		downloadBytes,
		usagePresent,
		totalBytes,
		usagePresent,
		expiresAt,
		usagePresent,
		usageUpdated,
		profileID,
		expectedRevision,
	)
	if err != nil {
		return false, fmt.Errorf("persist profile subscription metadata: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read profile metadata update result: %w", err)
	}
	if affected != 1 {
		return false, ErrProfileUpdateInProgress
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit profile metadata transaction: %w", err)
	}
	return true, nil
}

func (s *Store) FinishProfileUpdateFailure(
	ctx context.Context,
	lease ProfileUpdateLease,
	cause string,
	retryAfter *time.Time,
) error {
	if err := validateProfileUpdateLease(lease); err != nil {
		return err
	}
	if err := validateProfileUpdateStatusText("failure", cause, 8192, true); err != nil {
		return err
	}
	var retryValue any
	if retryAfter != nil {
		retryValue = retryAfter.UTC().Format(time.RFC3339Nano)
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE profile_sources
		SET active_update_id = NULL,
			active_update_started_at = NULL,
			last_error = ?,
			consecutive_failures = consecutive_failures + 1,
			retry_after_at = ?
		WHERE profile_id = ?
		  AND revision = ?
		  AND active_update_id = ?
	`,
		cause,
		retryValue,
		lease.ProfileID,
		lease.SourceRevision,
		lease.ID,
	)
	if err != nil {
		return fmt.Errorf("finish failed profile update: %w", err)
	}
	return requireProfileUpdateLeaseResult(result)
}

func (s *Store) RecoverInterruptedProfileUpdates(ctx context.Context) ([]InterruptedProfileUpdate, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin profile update recovery: %w", err)
	}
	defer tx.Rollback()

	rows, err := tx.QueryContext(ctx, `
		SELECT profile_id, active_update_id, active_update_started_at
		FROM profile_sources
		WHERE active_update_id IS NOT NULL
		ORDER BY profile_id
	`)
	if err != nil {
		return nil, fmt.Errorf("list interrupted profile updates: %w", err)
	}
	var interrupted []InterruptedProfileUpdate
	for rows.Next() {
		var (
			item      InterruptedProfileUpdate
			startedAt string
		)
		if err := rows.Scan(&item.ProfileID, &item.UpdateID, &startedAt); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan interrupted profile update: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339Nano, startedAt)
		if err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("parse interrupted profile update timestamp: %w", err)
		}
		item.StartedAt = parsed
		interrupted = append(interrupted, item)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate interrupted profile updates: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close interrupted profile update rows: %w", err)
	}

	if len(interrupted) != 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE profile_sources
			SET active_update_id = NULL,
				active_update_started_at = NULL,
				last_error = 'daemon restarted during profile update',
				consecutive_failures = consecutive_failures + 1,
				retry_after_at = NULL
			WHERE active_update_id IS NOT NULL
		`); err != nil {
			return nil, fmt.Errorf("clear interrupted profile updates: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit profile update recovery: %w", err)
	}
	return interrupted, nil
}

const profileSourceSelect = `
	SELECT
		s.revision,
		s.profile_id,
		s.source_format,
		s.location_kind,
		s.location,
		s.user_agent,
		s.fetch_mode,
		s.fetch_profile_id,
		s.fetch_node_id,
		s.filter_method,
		s.filter_expression,
		s.filter_match_attribute,
		s.enabled,
		s.update_interval_seconds,
		s.created_at,
		s.updated_at,
		s.last_attempt_at,
		s.last_success_at,
		s.last_error,
		s.last_source_revision,
		s.etag,
		s.last_modified,
		s.subscription_upload_bytes,
		s.subscription_download_bytes,
		s.subscription_total_bytes,
		s.subscription_expires_at,
		s.subscription_usage_updated_at,
		s.subscription_metadata_observed_at,
		s.subscription_metadata_error,
		s.consecutive_failures,
		s.retry_after_at,
		s.active_update_id,
		s.active_update_started_at,
		p.current_snapshot_id
	FROM profile_sources s
	LEFT JOIN profile_state p ON p.profile_id = s.profile_id
`

func scanProfileSource(row scanner) (ProfileSourceState, error) {
	var (
		state              ProfileSourceState
		revision           int64
		enabled            int
		updateInterval     int64
		filterMatchAttr    int
		createdAt          string
		updatedAt          string
		lastAttempt        sql.NullString
		lastSuccess        sql.NullString
		retryAfter         sql.NullString
		activeUpdate       sql.NullString
		activeStarted      sql.NullString
		currentSnapshot    sql.NullInt64
		usageUpload        sql.NullInt64
		usageDownload      sql.NullInt64
		usageTotal         sql.NullInt64
		usageExpires       sql.NullString
		usageUpdated       sql.NullString
		metadataObserved   sql.NullString
		consecutiveFailure int64
	)
	if err := row.Scan(
		&revision,
		&state.Spec.ProfileID,
		&state.Spec.Format,
		&state.Spec.LocationKind,
		&state.Spec.Location,
		&state.Spec.UserAgent,
		&state.Spec.Fetch.Mode,
		&state.Spec.Fetch.ProfileID,
		&state.Spec.Fetch.NodeID,
		&state.Spec.Filter.Method,
		&state.Spec.Filter.KeywordOrRegex,
		&filterMatchAttr,
		&enabled,
		&updateInterval,
		&createdAt,
		&updatedAt,
		&lastAttempt,
		&lastSuccess,
		&state.LastError,
		&state.LastSourceRevision,
		&state.ETag,
		&state.LastModified,
		&usageUpload,
		&usageDownload,
		&usageTotal,
		&usageExpires,
		&usageUpdated,
		&metadataObserved,
		&state.LastMetadataError,
		&consecutiveFailure,
		&retryAfter,
		&activeUpdate,
		&activeStarted,
		&currentSnapshot,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProfileSourceState{}, ErrProfileSourceNotFound
		}
		return ProfileSourceState{}, fmt.Errorf("read profile source: %w", err)
	}
	if revision <= 0 || consecutiveFailure < 0 || updateInterval < 0 {
		return ProfileSourceState{}, errors.New("profile source contains invalid persisted counters")
	}
	state.Revision = uint64(revision)
	state.Spec.Filter.MatchAttribute = filterMatchAttr != 0
	state.Spec.Enabled = enabled != 0
	state.Spec.UpdateInterval = time.Duration(updateInterval) * time.Second
	state.ConsecutiveFailures = uint32(consecutiveFailure)
	state.ActiveUpdateID = activeUpdate.String
	state.CurrentSnapshotID = nullInt64Ptr(currentSnapshot)

	var err error
	if state.CreatedAt, err = time.Parse(time.RFC3339Nano, createdAt); err != nil {
		return ProfileSourceState{}, fmt.Errorf("parse profile source created_at: %w", err)
	}
	if state.UpdatedAt, err = time.Parse(time.RFC3339Nano, updatedAt); err != nil {
		return ProfileSourceState{}, fmt.Errorf("parse profile source updated_at: %w", err)
	}
	if state.LastAttemptAt, err = parseNullableTime(lastAttempt); err != nil {
		return ProfileSourceState{}, fmt.Errorf("parse profile source last_attempt_at: %w", err)
	}
	if state.LastSuccessAt, err = parseNullableTime(lastSuccess); err != nil {
		return ProfileSourceState{}, fmt.Errorf("parse profile source last_success_at: %w", err)
	}
	if state.RetryAfterAt, err = parseNullableTime(retryAfter); err != nil {
		return ProfileSourceState{}, fmt.Errorf("parse profile source retry_after_at: %w", err)
	}
	if state.ActiveUpdateStarted, err = parseNullableTime(activeStarted); err != nil {
		return ProfileSourceState{}, fmt.Errorf("parse profile source active_update_started_at: %w", err)
	}
	state.SubscriptionUsageUpdatedAt, err = parseNullableTime(usageUpdated)
	if err != nil {
		return ProfileSourceState{}, fmt.Errorf("parse subscription usage updated_at: %w", err)
	}
	state.SubscriptionMetadataObservedAt, err = parseNullableTime(metadataObserved)
	if err != nil {
		return ProfileSourceState{}, fmt.Errorf("parse subscription metadata observed_at: %w", err)
	}
	usageExpiresAt, err := parseNullableTime(usageExpires)
	if err != nil {
		return ProfileSourceState{}, fmt.Errorf("parse subscription expiry: %w", err)
	}
	if usageUpload.Valid || usageDownload.Valid || usageTotal.Valid || usageExpires.Valid || usageUpdated.Valid {
		if !usageUpdated.Valid {
			return ProfileSourceState{}, errors.New("profile source subscription usage timestamp is missing")
		}
		usage := &profile.SubscriptionUsage{
			UploadBytes:   nullInt64ValuePtr(usageUpload),
			DownloadBytes: nullInt64ValuePtr(usageDownload),
			TotalBytes:    nullInt64ValuePtr(usageTotal),
			ExpiresAt:     usageExpiresAt,
		}
		if err := usage.Validate(); err != nil {
			return ProfileSourceState{}, fmt.Errorf("validate persisted subscription usage: %w", err)
		}
		state.SubscriptionUsage = usage
	}
	if err := state.Spec.Validate(); err != nil {
		return ProfileSourceState{}, fmt.Errorf("validate persisted profile source: %w", err)
	}
	if (state.ActiveUpdateID == "") != (state.ActiveUpdateStarted == nil) {
		return ProfileSourceState{}, errors.New("profile source active update state is inconsistent")
	}
	return state, nil
}

func validateProfileUpdateID(value string) error {
	if value == "" || len(value) > 128 {
		return ErrInvalidProfileUpdateID
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') {
			continue
		}
		switch r {
		case '-', '_', '.', ':':
			continue
		default:
			return fmt.Errorf("%w: unsupported character %q", ErrInvalidProfileUpdateID, r)
		}
	}
	return nil
}

func validateProfileUpdateLease(lease ProfileUpdateLease) error {
	if err := validateProfileUpdateID(lease.ID); err != nil {
		return err
	}
	if err := profile.ValidateProfileID(lease.ProfileID); err != nil {
		return err
	}
	if lease.SourceRevision == 0 || lease.StartedAt.IsZero() {
		return ErrProfileUpdateLeaseMismatch
	}
	return nil
}

func validateProfileUpdateStatusText(label, value string, limit int, required bool) error {
	if required && value == "" {
		return fmt.Errorf("%w: %s must not be empty", ErrInvalidProfileUpdateStatus, label)
	}
	if len(value) > limit || !utf8.ValidString(value) {
		return fmt.Errorf("%w: invalid %s length or encoding", ErrInvalidProfileUpdateStatus, label)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalidProfileUpdateStatus, label)
		}
	}
	return nil
}

func requireProfileUpdateLeaseResult(result sql.Result) error {
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read profile update completion result: %w", err)
	}
	if affected != 1 {
		return ErrProfileUpdateLeaseMismatch
	}
	return nil
}

func parseNullableTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

func nullableInt64Pointer(value *int64) any {
	if value == nil {
		return nil
	}
	return *value
}

func nullInt64ValuePtr(value sql.NullInt64) *int64 {
	if !value.Valid {
		return nil
	}
	result := value.Int64
	return &result
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}
