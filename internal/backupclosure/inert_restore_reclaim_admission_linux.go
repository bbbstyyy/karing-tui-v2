//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrRetainedEvidenceAdmission is fail-closed: the private state parent may
// be busy, outside its bounded review budget, or have unauthenticated files.
var ErrRetainedEvidenceAdmission = errors.New("private retained proof publication budget refused")

// retainedEvidenceAdmission is a process-local handle to an advisory,
// cross-process Linux flock ON THE EXISTING STATE DIRECTORY. It creates no
// lockfile, token or extra SQLite state. Both known off-scope writers must
// hold this lock throughout O_EXCL publication, file fsync, parent fsync
// and post-publication proof revalidation.
//
// Advisory flock does not police an external writer that ignores this lock.
// These are admission bounds for cooperating writers, not a filesystem
// quota, expiration policy, or permission to remove any historical evidence.
type retainedEvidenceAdmission struct {
	dir    *os.File
	before retainedEvidenceSnapshot
	name   string
	sha    string
	size   int64
}

func beginRetainedEvidenceAdmission(
	ctx context.Context, dir *os.File, name string, payload []byte,
) (_ *retainedEvidenceAdmission, err error) {
	if ctx == nil || ctx.Err() != nil || dir == nil ||
		len(payload) == 0 || !validRetainedEvidenceName(name) {
		return nil, ErrRetainedEvidenceAdmission
	}
	max := maxReclaimAttestationBytes
	if strings.HasPrefix(name, reclaimMirrorPrefix) {
		max = maxReclaimMirrorBytes
	}
	if len(payload) > max {
		return nil, ErrRetainedEvidenceAdmission
	}
	// Never wait for an unbounded external process, which may be stuck while
	// holding its original ciphertext flock or blocked inside SQLite.
	if unix.Flock(int(dir.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return nil, ErrRetainedEvidenceAdmission
	}
	defer func() {
		if err != nil {
			_ = unix.Flock(int(dir.Fd()), unix.LOCK_UN)
		}
	}()
	first, err := scanReclaimEvidenceFootprint(ctx, dir)
	if err != nil {
		return nil, ErrRetainedEvidenceAdmission
	}
	second, err := scanReclaimEvidenceFootprint(ctx, dir)
	if err != nil || !sameReclaimEvidenceFootprint(first, second) ||
		!admitRetainedEvidenceSize(second, name, int64(len(payload))) {
		return nil, ErrRetainedEvidenceAdmission
	}
	return &retainedEvidenceAdmission{
		dir: dir, before: second, name: name,
		sha: shaHex(payload), size: int64(len(payload)),
	}, nil
}

func validRetainedEvidenceName(name string) bool {
	var suffix string
	switch {
	case strings.HasPrefix(name, reclaimAttestationPrefix):
		suffix = strings.TrimPrefix(name, reclaimAttestationPrefix)
	case strings.HasPrefix(name, reclaimMirrorPrefix):
		suffix = strings.TrimPrefix(name, reclaimMirrorPrefix)
	default:
		return false
	}
	return validLowerSHA(suffix)
}

func admitRetainedEvidenceSize(before retainedEvidenceSnapshot, name string, size int64) bool {
	if size <= 0 || !validRetainedEvidenceName(name) ||
		before.directoryEntries < 0 ||
		before.directoryEntries >= maxReclaimEvidenceDirectoryEntries ||
		len(before.proofs) >= maxReclaimEvidenceProofFiles ||
		before.bytes < 0 || before.bytes > maxReclaimEvidenceProofBytes-size {
		return false
	}
	_, found := before.proofs[name]
	return !found
}

// Check immediately before O_EXCL to refuse a late addition/replacement
// even when an unexpected out-of-band writer ignores directory flock.
func (g *retainedEvidenceAdmission) checkBefore(ctx context.Context) error {
	if g == nil || ctx == nil || ctx.Err() != nil {
		return ErrRetainedEvidenceAdmission
	}
	again, err := scanReclaimEvidenceFootprint(ctx, g.dir)
	if err != nil || !sameReclaimEvidenceFootprint(g.before, again) ||
		!admitRetainedEvidenceSize(again, g.name, g.size) {
		return ErrRetainedEvidenceAdmission
	}
	return nil
}

// After publication and directory fsync, verify that exactly the expected
// O_EXCL private proof appeared; no preexisting private proof changed inode,
// bytes, permission, or SHA, and no extra directory entry was added.
func (g *retainedEvidenceAdmission) checkAfter(ctx context.Context) error {
	if g == nil || ctx == nil || ctx.Err() != nil {
		return ErrRetainedEvidenceAdmission
	}
	first, err := scanReclaimEvidenceFootprint(ctx, g.dir)
	if err != nil || !g.matchesPublished(first) {
		return ErrRetainedEvidenceAdmission
	}
	second, err := scanReclaimEvidenceFootprint(ctx, g.dir)
	if err != nil || !sameReclaimEvidenceFootprint(first, second) ||
		!g.matchesPublished(second) {
		return ErrRetainedEvidenceAdmission
	}
	return nil
}

func (g *retainedEvidenceAdmission) matchesPublished(after retainedEvidenceSnapshot) bool {
	if g == nil || after.directoryEntries != g.before.directoryEntries+1 ||
		len(after.proofs) != len(g.before.proofs)+1 ||
		after.bytes != g.before.bytes+g.size {
		return false
	}
	for name, previous := range g.before.proofs {
		now, exists := after.proofs[name]
		if !exists || now.size != previous.size || now.sha != previous.sha ||
			!sameLeasedFile(previous.info, now.info) {
			return false
		}
	}
	published, exists := after.proofs[g.name]
	return exists && published.size == g.size && published.sha == g.sha
}

func (g *retainedEvidenceAdmission) close() {
	if g != nil && g.dir != nil {
		_ = unix.Flock(int(g.dir.Fd()), unix.LOCK_UN)
		g.dir = nil
	}
}
