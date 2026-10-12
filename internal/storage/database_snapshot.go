package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	MaxDatabaseSnapshotBytes = int64(768 << 20)
	databaseSnapshotTimeout  = 30 * time.Second
)

var ErrUnsafeDatabaseSnapshot = errors.New("private database snapshot refused")

// DatabaseSnapshot is an ephemeral, self-contained WAL-consistent SQLite copy.
// It does NOT contain external rule-set resources or constitute a restorable
// product backup. The caller owns it and must Close it on every path.
type DatabaseSnapshot struct {
	Path              string
	SHA256            string
	Size              int64
	directory         string
	directoryIdentity os.FileInfo
	fileIdentity      os.FileInfo
	closed            bool
}

// CreateDatabaseSnapshot makes an isolated read-only-to-other-users copy of
// the SQLite main database in a caller-owned, existing private directory.
// It neither modifies live generations nor reads/copies a standalone WAL file.
// No HTTP/CLI/TUI endpoint exports this sensitive artifact.
func (s *Store) CreateDatabaseSnapshot(ctx context.Context, parent string) (*DatabaseSnapshot, error) {
	return s.createDatabaseSnapshot(ctx, parent, MaxDatabaseSnapshotBytes)
}

func (s *Store) createDatabaseSnapshot(ctx context.Context, parent string, limit int64) (snapshot *DatabaseSnapshot, err error) {
	if s == nil || s.db == nil || ctx == nil || limit <= 0 || limit > MaxDatabaseSnapshotBytes {
		return nil, ErrUnsafeDatabaseSnapshot
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := verifyPrivateSnapshotParent(parent); err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, databaseSnapshotTimeout)
	defer cancel()

	// Best-effort byte budget before SQLite starts writing. SQLite is the
	// authority for final size; the output is checked again after VACUUM.
	var pages, pageSize int64
	if err := s.db.QueryRowContext(bounded, "PRAGMA main.page_count").Scan(&pages); err != nil {
		return nil, ErrUnsafeDatabaseSnapshot
	}
	if err := s.db.QueryRowContext(bounded, "PRAGMA main.page_size").Scan(&pageSize); err != nil {
		return nil, ErrUnsafeDatabaseSnapshot
	}
	if pages <= 0 || pageSize <= 0 || pages > limit/pageSize {
		return nil, ErrUnsafeDatabaseSnapshot
	}

	dir, err := os.MkdirTemp(parent, ".sqlite-snapshot-")
	if err != nil {
		return nil, ErrUnsafeDatabaseSnapshot
	}
	snapshot = &DatabaseSnapshot{Path: filepath.Join(dir, "state.db"), directory: dir}
	defer func() {
		if err != nil {
			closeErr := snapshot.Close()
			err = errors.Join(err, closeErr)
			snapshot = nil
		}
	}()
	snapshot.directoryIdentity, err = os.Lstat(dir)
	if err != nil || !snapshot.directoryIdentity.IsDir() || snapshot.directoryIdentity.Mode().Perm() != 0o700 {
		return snapshot, ErrUnsafeDatabaseSnapshot
	}
	// SQLite explicitly permits an already-existing zero-byte INTO file.
	// Pre-creation avoids inheriting the daemon's umask as a confidentiality
	// boundary and makes symlink/hardlink substitution more difficult.
	f, createErr := os.OpenFile(snapshot.Path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if createErr != nil {
		return snapshot, ErrUnsafeDatabaseSnapshot
	}
	snapshot.fileIdentity, err = f.Stat()
	err = errors.Join(err, f.Close())
	if err != nil {
		return snapshot, ErrUnsafeDatabaseSnapshot
	}
	if err = syncDatabaseSnapshotDir(dir); err != nil {
		return snapshot, err
	}

	// INTO runs on the store's single database connection and creates a
	// transactional snapshot including committed WAL pages, without blocking
	// out the live core or altering the source main.db file.
	if _, err = s.db.ExecContext(bounded, "VACUUM main INTO ?", snapshot.Path); err != nil {
		return snapshot, fmt.Errorf("%w: sqlite consistent copy unavailable", ErrUnsafeDatabaseSnapshot)
	}
	if err = snapshot.verifyFile(); err != nil {
		return snapshot, err
	}
	if snapshot.Size, snapshot.SHA256, err = digestDatabaseSnapshot(bounded, snapshot.Path, limit); err != nil {
		return snapshot, err
	}
	if err = checkDatabaseSnapshot(bounded, snapshot.Path); err != nil {
		return snapshot, err
	}
	if err = syncDatabaseSnapshotDir(dir); err != nil {
		return snapshot, err
	}
	if err = syncDatabaseSnapshotDir(parent); err != nil {
		return snapshot, err
	}
	if err = bounded.Err(); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func verifyPrivateSnapshotParent(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrUnsafeDatabaseSnapshot
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUnsafeDatabaseSnapshot
		}
		if current == path {
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || int(st.Uid) != os.Getuid() || info.Mode().Perm()&0o077 != 0 {
				return ErrUnsafeDatabaseSnapshot
			}
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return nil
}

func (s *DatabaseSnapshot) verifyFile() error {
	if s == nil || s.closed || s.fileIdentity == nil || s.directoryIdentity == nil {
		return ErrUnsafeDatabaseSnapshot
	}
	dirInfo, dirErr := os.Lstat(s.directory)
	if dirErr != nil || !os.SameFile(dirInfo, s.directoryIdentity) || !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0o700 {
		return ErrUnsafeDatabaseSnapshot
	}
	info, err := os.Lstat(s.Path)
	if err != nil || !info.Mode().IsRegular() || !os.SameFile(info, s.fileIdentity) || info.Mode().Perm() != 0o600 {
		return ErrUnsafeDatabaseSnapshot
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != os.Getuid() || st.Nlink != 1 {
		return ErrUnsafeDatabaseSnapshot
	}
	return nil
}

func digestDatabaseSnapshot(ctx context.Context, path string, limit int64) (int64, string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return 0, "", ErrUnsafeDatabaseSnapshot
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var size int64
	var prefix [16]byte
	if _, err := f.ReadAt(prefix[:], 0); err != nil || string(prefix[:]) != "SQLite format 3\x00" {
		return 0, "", ErrUnsafeDatabaseSnapshot
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, "", ErrUnsafeDatabaseSnapshot
	}
	for {
		if err := ctx.Err(); err != nil {
			return 0, "", err
		}
		n, readErr := f.Read(buf)
		size += int64(n)
		if size > limit {
			return 0, "", ErrUnsafeDatabaseSnapshot
		}
		if n > 0 {
			if _, err := h.Write(buf[:n]); err != nil {
				return 0, "", ErrUnsafeDatabaseSnapshot
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return 0, "", ErrUnsafeDatabaseSnapshot
		}
	}
	if size == 0 {
		return 0, "", ErrUnsafeDatabaseSnapshot
	}
	if err := f.Sync(); err != nil {
		return 0, "", ErrUnsafeDatabaseSnapshot
	}
	return size, hex.EncodeToString(h.Sum(nil)), nil
}

func checkDatabaseSnapshot(ctx context.Context, path string) error {
	uri := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro&immutable=1"}
	reader, err := sql.Open("sqlite", uri.String())
	if err != nil {
		return ErrUnsafeDatabaseSnapshot
	}
	defer reader.Close()
	reader.SetMaxOpenConns(1)
	var result string
	if err := reader.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&result); err != nil || result != "ok" {
		return ErrUnsafeDatabaseSnapshot
	}
	return nil
}

func syncDatabaseSnapshotDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return ErrUnsafeDatabaseSnapshot
	}
	return errors.Join(f.Sync(), f.Close())
}

// Close deletes only the exact private file and directory created by this
// snapshot. Unexpected entries, inode replacement or unsafe permissions stop
// cleanup rather than recursively removing caller-owned data.
func (s *DatabaseSnapshot) Close() error {
	if s == nil || s.closed {
		return nil
	}
	if s.directoryIdentity == nil {
		return ErrUnsafeDatabaseSnapshot
	}
	d, err := os.Lstat(s.directory)
	if err != nil || !os.SameFile(d, s.directoryIdentity) || !d.IsDir() || d.Mode().Perm() != 0o700 {
		return ErrUnsafeDatabaseSnapshot
	}
	entries, err := os.ReadDir(s.directory)
	if err != nil {
		return ErrUnsafeDatabaseSnapshot
	}
	if len(entries) > 1 || (len(entries) == 1 && entries[0].Name() != "state.db") {
		return ErrUnsafeDatabaseSnapshot
	}
	if len(entries) == 1 {
		if err := s.verifyFile(); err != nil {
			return err
		}
		if err := os.Remove(s.Path); err != nil {
			return ErrUnsafeDatabaseSnapshot
		}
	}
	if err := os.Remove(s.directory); err != nil {
		return ErrUnsafeDatabaseSnapshot
	}
	if err := syncDatabaseSnapshotDir(filepath.Dir(s.directory)); err != nil {
		return err
	}
	s.closed = true
	return nil
}
