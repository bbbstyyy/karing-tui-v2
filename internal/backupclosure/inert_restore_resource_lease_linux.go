//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrInertRestoreResourceLeaseRefused = errors.New("inert restore ciphertext resource lease refused")

// InertRestoreResourceLease owns a LIVE cross-process directory flock and a
// freshly authenticated, journal-bound ciphertext file inode. The SQLite
// record persists but the lease NEVER survives Close, SIGKILL, or restart.
// Neither this object nor its revalidation may be passed to the core or to
// an actual backup import operation.
type InertRestoreResourceLease struct {
	mu           sync.Mutex
	live         *storage.Store
	candidate    *InertRestoreCandidate
	record       storage.InertRestorePreparation
	fileIdentity os.FileInfo
}

// AcquireInertRestoreResourceLease reacquires a known, pending v18 record's
// candidate after a restart. It does not scan directories to select a
// candidate: the caller explicitly names the record ID and a pre-existing
// owned private parent. It requires the caller-resupplied 32-byte key.
//
// The encrypted candidate directory is locked exclusively until Close; an
// open, still-locked candidate from an earlier process is never inherited.
// Only hashes and a generation-like journal row ID survive a crash.
func AcquireInertRestoreResourceLease(
	ctx context.Context, live *storage.Store,
	candidateParent string, recordID int64, key [32]byte,
) (*InertRestoreResourceLease, error) {
	if ctx == nil || live == nil || recordID <= 0 ||
		key == ([32]byte{}) ||
		verifySealedArchiveParent(candidateParent) != nil {
		return nil, ErrInertRestoreResourceLeaseRefused
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	records, err := live.InspectInertRestoreRecords(ctx)
	if err != nil {
		return nil, ErrInertRestoreResourceLeaseRefused
	}
	var record *storage.InertRestorePreparation
	pending := 0
	for i := range records {
		if records[i].Phase == storage.InertRestorePrepared {
			pending++
		}
		if records[i].ID == recordID {
			record = &records[i]
		}
	}
	if record == nil || pending != 1 ||
		record.Phase != storage.InertRestorePrepared ||
		!record.RequiresRevalidation || record.RestoreReady ||
		record.RestoreSupported {
		return nil, ErrInertRestoreResourceLeaseRefused
	}
	directory := filepath.Join(candidateParent, record.CandidateScope)
	if !validInertRestoreCandidateDir(directory) ||
		filepath.Dir(directory) != candidateParent {
		return nil, ErrInertRestoreResourceLeaseRefused
	}
	candidate, err := ReopenInertRestoreCandidate(ctx, directory, key)
	if err != nil {
		if errors.Is(err, ErrInertRestoreCandidateBusy) {
			return nil, err
		}
		return nil, ErrInertRestoreResourceLeaseRefused
	}
	lease := &InertRestoreResourceLease{
		live: live, candidate: candidate, record: *record,
	}
	// A failed acquisition MUST drop the newly acquired child lock; the
	// persistent ciphertext and journal remain untouched for manual review.
	if lease.fileIdentity, err = candidateFileIdentity(candidate); err != nil {
		_ = lease.Close()
		return nil, ErrInertRestoreResourceLeaseRefused
	}
	if err := lease.Revalidate(ctx, key); err != nil {
		_ = lease.Close()
		return nil, err
	}
	return lease, nil
}

func candidateFileIdentity(candidate *InertRestoreCandidate) (os.FileInfo, error) {
	if candidate == nil {
		return nil, ErrInertRestoreResourceLeaseRefused
	}
	candidate.mu.Lock()
	defer candidate.mu.Unlock()
	if candidate.dir == nil {
		return nil, ErrInertRestoreResourceLeaseRefused
	}
	info, err := inspectInertCandidateFile(candidate, false)
	if err != nil {
		return nil, ErrInertRestoreResourceLeaseRefused
	}
	return info, nil
}

// Revalidate holds the directory flock across full ciphertext authentication,
// a short atomic (ROLLBACK-only) SQLite check of the complete journal and
// committed live CAS, and a final file/dir identity check.
//
// Only THIS process lifetime's immutable inode identity is pinned: a
// cross-restart inode comparison is NOT claimed. If the same ciphertext is
// atomically replaced under the lease, it fails even when the bytes match.
// This check is not a combined cross-filesystem transaction and expires as
// soon as it returns; a future restore writer must repeat its own full CAS.
func (l *InertRestoreResourceLease) Revalidate(ctx context.Context, key [32]byte) error {
	if l == nil || ctx == nil || key == ([32]byte{}) {
		return ErrInertRestoreResourceLeaseRefused
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.revalidateLocked(ctx, key)
}

// revalidateLocked is shared with anonymous, ephemeral resource probing. The
// caller holds l.mu throughout the complete probe so Close cannot release the
// ciphertext directory flock between authentication and the final CAS.
func (l *InertRestoreResourceLease) revalidateLocked(ctx context.Context, key [32]byte) error {
	if ctx == nil || key == ([32]byte{}) ||
		l.candidate == nil || l.live == nil || l.fileIdentity == nil {
		return ErrInertRestoreResourceLeaseRefused
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	before, err := candidateFileIdentity(l.candidate)
	if err != nil || !sameLeasedFile(l.fileIdentity, before) {
		return ErrInertRestoreResourceLeaseRefused
	}
	receipt, err := l.candidate.Verify(ctx, key)
	if err != nil || receipt.RestoreReady || receipt.RestoreSupported ||
		!receipt.ResourceDigestsVerified ||
		!receipt.SchemaCatalogVerified || !receipt.SQLiteLogicalVerified ||
		receipt.ArchiveSHA256 != l.record.ArchiveSHA256 ||
		receipt.InventorySHA256 != l.record.InventorySHA256 ||
		receipt.ArchiveBytes != l.record.ArchiveBytes {
		return ErrInertRestoreResourceLeaseRefused
	}
	if err := l.live.CheckInertRestoreRecordCAS(ctx, l.record); err != nil {
		return ErrInertRestoreResourceLeaseRefused
	}
	after, err := candidateFileIdentity(l.candidate)
	if err != nil || !sameLeasedFile(l.fileIdentity, after) ||
		!sameLeasedFile(before, after) {
		return ErrInertRestoreResourceLeaseRefused
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func sameLeasedFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) &&
		a.Mode() == b.Mode() && a.Size() == b.Size() &&
		a.ModTime().Equal(b.ModTime())
}

// Record returns only journal metadata, never the key or ciphertext. The
// returned value is inherently non-authorizing and always needs revalidation.
func (l *InertRestoreResourceLease) Record() storage.InertRestorePreparation {
	if l == nil {
		return storage.InertRestorePreparation{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.candidate == nil {
		return storage.InertRestorePreparation{}
	}
	return l.record
}

// Close releases the LIVE lock without touching SQLite, private ciphertext,
// current configuration, apply history or the running sing-box process.
// It is safe to Close more than once; no time- or PID-driven GC is run.
func (l *InertRestoreResourceLease) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.candidate == nil {
		return nil
	}
	err := l.candidate.Close()
	l.candidate = nil
	l.fileIdentity = nil
	return err
}
