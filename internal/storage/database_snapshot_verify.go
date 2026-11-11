package storage

import "context"

// Verify independently checks the inode, permissions, exact bytes and SQLite
// integrity of this still-flock-held snapshot. This provides an internal
// consistency barrier before and after assembling external rule-set closures;
// it is not a backup authorization or a durable restoration lease.
func (s *DatabaseSnapshot) Verify(ctx context.Context) error {
	if s == nil || ctx == nil || s.closed || s.Size <= 0 ||
		!validHistoricalSHA(s.SHA256) {
		return ErrUnsafeDatabaseSnapshot
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.verifyFile(); err != nil {
		return ErrUnsafeDatabaseSnapshot
	}
	size, digest, err := digestDatabaseSnapshot(ctx, s.Path, MaxDatabaseSnapshotBytes)
	if err != nil || size != s.Size || digest != s.SHA256 {
		return ErrUnsafeDatabaseSnapshot
	}
	if err := checkDatabaseSnapshot(ctx, s.Path); err != nil {
		return ErrUnsafeDatabaseSnapshot
	}
	if err := s.verifyFile(); err != nil {
		return ErrUnsafeDatabaseSnapshot
	}
	return nil
}
