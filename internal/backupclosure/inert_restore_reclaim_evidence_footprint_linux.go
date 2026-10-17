//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxReclaimEvidenceDirectoryEntries = 4096
	maxReclaimEvidenceProofFiles = 256
	maxReclaimEvidenceProofBytes int64 = 40 << 20
)

var ErrReclaimEvidenceFootprint = errors.New("private retained reclaim evidence footprint refused")

// ReclaimEvidenceFootprint counts private off-scope audit files by *name*
// and verified filesystem identity, not by keyed historical authenticity.
// In particular, a matched filename pair does not prove an HMAC or authorise
// disposal of the original source or either retained proof.
type ReclaimEvidenceFootprint struct {
	ArchiveSHA256 string
	DirectoryEntriesSeen int
	AttestationFiles int
	MirrorFiles int
	NamedPairs int
	UnpairedFiles int
	RetainedBytes int64
	ReviewEntryLimit int
	ReviewFileLimit int
	ReviewByteLimit int64
	NamesOnly bool
	CryptographicProofsVerified bool
	QuotaEnforced bool
	PhysicalCleanupAuthorized bool
	RequiresManualReview bool
	RequiresRevalidation bool
	RestoreSupported bool
	RestoreReady bool
}

type retainedProofObservation struct {
	info os.FileInfo
	sha string
	size int64
}

type retainedEvidenceSnapshot struct {
	proofs map[string]retainedProofObservation
	directoryEntries int
	attestations int
	mirrors int
	pairs int
	unpaired int
	bytes int64
}

// InspectReclaimEvidenceFootprint is a bounded, read-only capacity review of
// the EXISTING current-UID private SQLite state parent. It does not open the
// inactive source reclaim directory or trust other archives' signatures.
// Other candidate archives may have no available key/journal, so names and
// bytes of their evidence are deliberately NOT called authenticated.
func (l *InertRestoreResourceLease) InspectReclaimEvidenceFootprint(
	ctx context.Context, key [32]byte,
) (ReclaimEvidenceFootprint, error) {
	return l.inspectReclaimEvidenceFootprint(ctx, key, nil)
}

// A fault seam models a directory-entry replacement between complete scans.
// Production never retries or mutates a file after detecting a change.
func (l *InertRestoreResourceLease) inspectReclaimEvidenceFootprint(
	ctx context.Context, key [32]byte, betweenScans func() error,
) (ReclaimEvidenceFootprint, error) {
	var zero ReclaimEvidenceFootprint
	if l == nil || ctx == nil || key == ([32]byte{}) {
		return zero, ErrReclaimEvidenceFootprint
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	bounded, cancel := context.WithTimeout(ctx, 4*sealedArchiveTimeout)
	defer cancel()
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.revalidateLocked(bounded, key) != nil ||
		!validLowerSHA(l.record.ArchiveSHA256) {
		return zero, ErrReclaimEvidenceFootprint
	}
	parent, dir, err := openReclaimAttestationParent(l)
	if err != nil {
		return zero, ErrReclaimEvidenceFootprint
	}
	defer parent.Close()
	first, err := scanReclaimEvidenceFootprint(bounded, dir)
	if err != nil || parent.verify() != nil ||
		l.revalidateLocked(bounded, key) != nil {
		return zero, ErrReclaimEvidenceFootprint
	}
	if betweenScans != nil && betweenScans() != nil {
		return zero, ErrReclaimEvidenceFootprint
	}
	second, err := scanReclaimEvidenceFootprint(bounded, dir)
	if err != nil || !sameReclaimEvidenceFootprint(first, second) ||
		parent.verify() != nil || l.revalidateLocked(bounded, key) != nil ||
		bounded.Err() != nil {
		return zero, ErrReclaimEvidenceFootprint
	}
	return ReclaimEvidenceFootprint{
		ArchiveSHA256: l.record.ArchiveSHA256,
		DirectoryEntriesSeen: second.directoryEntries,
		AttestationFiles: second.attestations,
		MirrorFiles: second.mirrors,
		NamedPairs: second.pairs,
		UnpairedFiles: second.unpaired,
		RetainedBytes: second.bytes,
		ReviewEntryLimit: maxReclaimEvidenceDirectoryEntries,
		ReviewFileLimit: maxReclaimEvidenceProofFiles,
		ReviewByteLimit: maxReclaimEvidenceProofBytes,
		NamesOnly: true,
		CryptographicProofsVerified: false,
		QuotaEnforced: false,
		PhysicalCleanupAuthorized: false,
		RequiresManualReview: true,
		RequiresRevalidation: true,
		RestoreSupported: false,
		RestoreReady: false,
	}, nil
}

func scanReclaimEvidenceFootprint(ctx context.Context, dir *os.File) (
	retainedEvidenceSnapshot, error,
) {
	var zero retainedEvidenceSnapshot
	if ctx == nil || ctx.Err() != nil || dir == nil {
		return zero, ErrReclaimEvidenceFootprint
	}
	fd, err := unix.Openat(int(dir.Fd()), ".",
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return zero, ErrReclaimEvidenceFootprint
	}
	reader := os.NewFile(uintptr(fd), "retained-evidence-directory")
	if reader == nil {
		_ = unix.Close(fd)
		return zero, ErrReclaimEvidenceFootprint
	}
	defer reader.Close()
	current, err := dir.Stat()
	if err != nil || !privatePortableDirectory(current) {
		return zero, ErrReclaimEvidenceFootprint
	}
	reopened, err := reader.Stat()
	if err != nil || !os.SameFile(current, reopened) ||
		!privatePortableDirectory(reopened) {
		return zero, ErrReclaimEvidenceFootprint
	}
	entries, err := reader.ReadDir(maxReclaimEvidenceDirectoryEntries + 1)
	if (err != nil && !errors.Is(err, io.EOF)) ||
		len(entries) > maxReclaimEvidenceDirectoryEntries {
		return zero, ErrReclaimEvidenceFootprint
	}

	snapshot := retainedEvidenceSnapshot{
		proofs: make(map[string]retainedProofObservation),
		directoryEntries: len(entries),
	}
	bindings := make(map[string]uint8)
	for _, entry := range entries {
		if ctx.Err() != nil {
			return zero, ErrReclaimEvidenceFootprint
		}
		name := entry.Name()
		var kind uint8
		var max int
		var suffix string
		switch {
		case strings.HasPrefix(name, reclaimAttestationPrefix):
			kind, max = 1, maxReclaimAttestationBytes
			suffix = strings.TrimPrefix(name, reclaimAttestationPrefix)
		case strings.HasPrefix(name, reclaimMirrorPrefix):
			kind, max = 2, maxReclaimMirrorBytes
			suffix = strings.TrimPrefix(name, reclaimMirrorPrefix)
		default:
			continue
		}
		if !validLowerSHA(suffix) ||
			len(snapshot.proofs) >= maxReclaimEvidenceProofFiles {
			return zero, ErrReclaimEvidenceFootprint
		}
		raw, info, err := readPrivateReclaimFile(ctx, dir, name, max)
		if err != nil || info == nil || info.Size() != int64(len(raw)) ||
			snapshot.bytes > maxReclaimEvidenceProofBytes-info.Size() {
			return zero, ErrReclaimEvidenceFootprint
		}
		snapshot.bytes += info.Size()
		snapshot.proofs[name] = retainedProofObservation{
			info: info, sha: shaHex(raw), size: info.Size(),
		}
		bindings[suffix] |= kind
		if kind == 1 {
			snapshot.attestations++
		} else {
			snapshot.mirrors++
		}
	}
	for _, bits := range bindings {
		if bits == 3 {
			snapshot.pairs++
		}
	}
	snapshot.unpaired = len(snapshot.proofs) - 2*snapshot.pairs
	after, err := reader.Stat()
	if err != nil || !os.SameFile(reopened, after) ||
		!privatePortableDirectory(after) || ctx.Err() != nil {
		return zero, ErrReclaimEvidenceFootprint
	}
	return snapshot, nil
}

func sameReclaimEvidenceFootprint(a, b retainedEvidenceSnapshot) bool {
	if a.directoryEntries != b.directoryEntries ||
		a.attestations != b.attestations ||
		a.mirrors != b.mirrors || a.pairs != b.pairs ||
		a.unpaired != b.unpaired || a.bytes != b.bytes ||
		len(a.proofs) != len(b.proofs) {
		return false
	}
	for name, original := range a.proofs {
		later, ok := b.proofs[name]
		if !ok || original.size != later.size ||
			original.sha != later.sha ||
			!sameLeasedFile(original.info, later.info) {
			return false
		}
	}
	return true
}
