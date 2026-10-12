package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDatabaseSnapshotCapturesCommittedWALAndStaysIndependent(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()
	if _, err := store.db.ExecContext(ctx, "CREATE TABLE backup_probe(id INTEGER PRIMARY KEY, secret TEXT NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "INSERT INTO backup_probe(id,secret) VALUES(1,'sensitive-original')"); err != nil {
		t.Fatal(err)
	}
	var wal string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&wal); err != nil || wal != "wal" {
		t.Fatalf("WAL mode unexpectedly disabled: %q %v", wal, err)
	}
	parent := t.TempDir()
	snap, err := store.CreateDatabaseSnapshot(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	if snap.Size <= 0 || len(snap.SHA256) != 64 {
		t.Fatalf("invalid snapshot metadata: %+v", snap)
	}
	dirInfo, err := os.Stat(filepath.Dir(snap.Path))
	if err != nil || dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("snapshot scope not private: %v %v", dirInfo, err)
	}
	info, err := os.Lstat(snap.Path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot file not private: %v %v", info, err)
	}
	bytes, err := os.ReadFile(snap.Path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	if hex.EncodeToString(sum[:]) != snap.SHA256 || int64(len(bytes)) != snap.Size {
		t.Fatal("snapshot digest/size not bound to actual file")
	}
	if _, err := store.db.ExecContext(ctx, "INSERT INTO backup_probe(id,secret) VALUES(2,'later-change')"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, "UPDATE backup_probe SET secret='changed' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	copiedURL := url.URL{Scheme: "file", Path: snap.Path, RawQuery: "immutable=1&mode=ro"}
	copied, err := sql.Open("sqlite", copiedURL.String())
	if err != nil {
		t.Fatal(err)
	}
	defer copied.Close()
	var original string
	if err := copied.QueryRowContext(ctx, "SELECT secret FROM backup_probe WHERE id=1").Scan(&original); err != nil || original != "sensitive-original" {
		t.Fatalf("snapshot did not preserve pre-change row: %q %v", original, err)
	}
	var count int
	if err := copied.QueryRowContext(ctx, "SELECT count(*) FROM backup_probe").Scan(&count); err != nil || count != 1 {
		t.Fatalf("snapshot got WAL-inconsistent rows: %d %v", count, err)
	}
	if err := store.db.QueryRowContext(ctx, "SELECT count(*) FROM backup_probe").Scan(&count); err != nil || count != 2 {
		t.Fatal("live database was modified by snapshot read")
	}
	if err := snap.Close(); err != nil {
		t.Fatalf("private snapshot cleanup failed: %v", err)
	}
	if err := snap.Close(); err != nil {
		t.Fatalf("repeat cleanup must be idempotent: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary snapshot scope leaked: %v %v", entries, err)
	}
}

func TestDatabaseSnapshotRejectsUnsafeParentsBudgetAndCancellation(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()
	parent := t.TempDir()
	symlink := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(parent, symlink); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, path string
		limit      int64
		ctx        context.Context
	}{
		{"relative", "relative", MaxDatabaseSnapshotBytes, ctx},
		{"symlink", symlink, MaxDatabaseSnapshotBytes, ctx},
		{"world-readable", loose, MaxDatabaseSnapshotBytes, ctx},
		{"tiny quota", parent, 1, ctx},
		{"invalid quota", parent, MaxDatabaseSnapshotBytes + 1, ctx},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := store.createDatabaseSnapshot(tc.ctx, tc.path, tc.limit)
			if got != nil || !errors.Is(err, ErrUnsafeDatabaseSnapshot) {
				t.Fatalf("unsafe input accepted: %+v %v", got, err)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := store.CreateDatabaseSnapshot(canceled, parent); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation accepted: %+v %v", got, err)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("failed snapshot left scope: %v %v", entries, err)
	}
	var version int
	if err := store.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		t.Fatalf("refused backup broke source DB: %v", err)
	}
}

func TestDatabaseSnapshotCloseRefusesUnknownEntriesAndHardlinks(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()
	parent := t.TempDir()
	snap, err := store.CreateDatabaseSnapshot(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	injected := filepath.Join(filepath.Dir(snap.Path), "unknown")
	if err := os.WriteFile(injected, []byte("must-not-delete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snap.Close(); !errors.Is(err, ErrUnsafeDatabaseSnapshot) {
		t.Fatalf("unexpected file did not block cleanup: %v", err)
	}
	body, err := os.ReadFile(injected)
	if err != nil || string(body) != "must-not-delete" {
		t.Fatal("cleanup erased unrecognized file")
	}
	if err := os.Remove(injected); err != nil {
		t.Fatal(err)
	}
	extraLink := filepath.Join(parent, "additional-link")
	if err := os.Link(snap.Path, extraLink); err != nil {
		t.Fatal(err)
	}
	if err := snap.Close(); !errors.Is(err, ErrUnsafeDatabaseSnapshot) {
		t.Fatalf("hardlink did not block cleanup: %v", err)
	}
	if _, err := os.Lstat(snap.Path); err != nil {
		t.Fatal("cleanup removed linked file")
	}
	if err := os.Remove(extraLink); err != nil {
		t.Fatal(err)
	}
	if err := snap.Close(); err != nil {
		t.Fatalf("safe cleanup after removal failed: %v", err)
	}
}

func TestDatabaseSnapshotCloseRefusesPathReplacement(t *testing.T) {
	ctx := context.Background()
	store, _ := newTestStore(t, ctx)
	defer store.Close()
	parent := t.TempDir()
	snap, err := store.CreateDatabaseSnapshot(ctx, parent)
	if err != nil {
		t.Fatal(err)
	}
	displaced := filepath.Join(parent, "displaced-original")
	if err := os.Rename(snap.Path, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(snap.Path, []byte("replacement-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := snap.Close(); !errors.Is(err, ErrUnsafeDatabaseSnapshot) {
		t.Fatalf("inode replacement passed cleanup: %v", err)
	}
	content, err := os.ReadFile(snap.Path)
	if err != nil || !strings.Contains(string(content), "replacement-secret") {
		t.Fatal("cleanup damaged replaced file")
	}
	if err := os.Remove(snap.Path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(displaced, snap.Path); err != nil {
		t.Fatal(err)
	}
	if err := snap.Close(); err != nil {
		t.Fatal(err)
	}
}
