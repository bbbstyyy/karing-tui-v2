package storage

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

func TestSchemaV9AddsProfileSnapshotsToV8Database(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		)
	`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO schema_migrations(version, applied_at)
		VALUES(8, '2026-10-07T00:00:00Z')
	`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	// Schema v8 already included migration 6's singleton selection_state.
	// Omitting it would fabricate a corrupted database, not a v8 fixture.
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE selection_state (
			singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
			current_target_json BLOB,
			updated_at TEXT
		)
	`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO selection_state(singleton, current_target_json, updated_at)
		VALUES(1, '{"kind":"direct"}', '2026-10-07T00:00:00Z')
	`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var version int
	if err := store.db.QueryRowContext(ctx, `SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 16 {
		t.Fatalf("schema version = %d, want 16", version)
	}
	intent, persisted, err := store.CurrentSelectionIntent(ctx)
	if err != nil || !persisted || intent.Revision != 0 || string(intent.TargetJSON) != `{"kind":"direct"}` {
		t.Fatalf("v8 persisted selection changed by migration: %+v persisted=%t err=%v", intent, persisted, err)
	}

	var metadataObservedColumn string
	if err := store.db.QueryRowContext(ctx, `
		SELECT name
		FROM pragma_table_info('profile_sources')
		WHERE name = 'subscription_metadata_observed_at'
	`).Scan(&metadataObservedColumn); err != nil {
		t.Fatal(err)
	}
	if metadataObservedColumn != "subscription_metadata_observed_at" {
		t.Fatalf("metadata observed column = %q", metadataObservedColumn)
	}

	committed, err := store.CommitProfileSnapshot(ctx, ProfileSnapshotCandidate{
		ProfileID:    "profile-v8",
		SourceKind:   "sing-box",
		SourceSHA256: strings.Repeat("e", 64),
		Nodes: []profile.SourceNode{{
			SourceKey:   "tag-a",
			SourceName:  "Alpha",
			PayloadJSON: []byte(`{"type":"http","tag":"tag-a","server":"127.0.0.1","server_port":8080}`),
		}},
	}, ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	current, ok, err := store.CurrentProfileSnapshot(ctx, "profile-v8")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current.ID != committed.Snapshot.ID || len(current.Nodes) != 1 {
		t.Fatalf("migrated profile snapshot = %+v ok=%v", current, ok)
	}
}
