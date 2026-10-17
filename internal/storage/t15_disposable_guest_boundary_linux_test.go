//go:build linux

package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	t15GuestCase        = "T15-prepared-journal"
	t15GuestReadyHeader = "KTUI_T15T23_LAB_READY_V1"
)

var (
	t15GuestNonce  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	t15GuestDomain = regexp.MustCompile(`^ktui-t15t23-disposable-[A-Za-z0-9-]{1,24}$`)
	t15GuestUUID   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// guestPrivateDir is a deliberately strict, test-only path check. This
// utility is NOT a production backup/restore or journal entrypoint.
func guestPrivateDir(path string) (*os.File, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("invalid isolated guest directory")
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || canonical != path {
		return nil, errors.New("symlinked guest path refused")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|
		syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), path)
	if dir == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("private guest directory FD missing")
	}
	info, err := dir.Stat()
	named, nameErr := os.Lstat(path)
	if err != nil || nameErr != nil || !info.IsDir() ||
		!os.SameFile(info, named) || info.Mode().Perm() != 0o700 {
		_ = dir.Close()
		return nil, errors.New("guest directory must be stable and private 0700")
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != uint32(os.Geteuid()) {
		_ = dir.Close()
		return nil, errors.New("guest directory owner mismatched")
	}
	return dir, nil
}

// createGuestT15PreparedJournal is only used in an explicitly disposable
// test SQLite directory. It proves a REAL v18 Store committed one baseline
// Applied/LKG and then one prepared-but-unactivated second generation.
// No live Core is ever called, and no existing state.db is overwritten.
func createGuestT15PreparedJournal(ctx context.Context, dbPath string) (int64, error) {
	if ctx == nil || filepath.Base(dbPath) != "state.db" || ctx.Err() != nil {
		return 0, errors.New("invalid T15 guest state DB")
	}
	for _, name := range []string{dbPath, dbPath + "-wal", dbPath + "-shm", dbPath + "-journal"} {
		if _, err := os.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return 0, errors.New("T15 lab refuses existing guest DB or journal files")
		}
	}
	parent, err := guestPrivateDir(filepath.Dir(dbPath))
	if err != nil {
		return 0, err
	}
	defer parent.Close()
	if err := unix.Flock(int(parent.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return 0, errors.New("private T15 state directory is already leased")
	}
	defer unix.Flock(int(parent.Fd()), unix.LOCK_UN)
	store, err := Open(ctx, dbPath)
	if err != nil {
		return 0, err
	}
	// Preserve the DB if any later operation fails. The operator must
	// review the isolated disk; no automatic unlink/repair/retry occurs.
	defer store.Close()
	base, err := store.PrepareApply(ctx, 0, []byte(`{"inbounds":[],"lab":"t15-baseline"}`))
	if err != nil {
		return 0, err
	}
	if err := store.BeginActivation(ctx, base.ID); err != nil {
		return 0, err
	}
	if err := store.BeginVerification(ctx, base.ID); err != nil {
		return 0, err
	}
	if err := store.CommitApplied(ctx, base.ID, true); err != nil {
		return 0, err
	}
	pending, err := store.PrepareApply(ctx, 1,
		[]byte(`{"inbounds":[],"lab":"t15-prepared-unactivated"}`))
	if err != nil {
		return 0, err
	}
	observed, err := store.Snapshot(ctx)
	if err != nil || observed.Revision != 1 ||
		observed.AppliedGenerationID == nil ||
		observed.LastKnownGoodGenerationID == nil ||
		*observed.AppliedGenerationID != base.GenerationID ||
		*observed.LastKnownGoodGenerationID != base.GenerationID ||
		observed.ActiveAttemptID == nil || *observed.ActiveAttemptID != pending.ID ||
		observed.RecoveryRequired || observed.CoreDesiredState != CoreDesiredStopped {
		return 0, errors.New("T15 state did not reach prepared-only boundary")
	}
	if err := store.Close(); err != nil {
		return 0, err
	}
	if err := parent.Sync(); err != nil {
		return 0, err
	}
	return pending.ID, nil
}

// createGuestT15ReadyMarker intentionally does not open any proxy socket,
// checkpoint another filesystem or request a VM shutdown. The *host-side*
// ADR 0128 guard may decide to stop only the disposable VM after this file
// and a separately pinned before-cut baseline have been observed.
func createGuestT15ReadyMarker(witness string, nonce string) error {
	if !t15GuestNonce.MatchString(nonce) {
		return errors.New("invalid test nonce")
	}
	dir, err := guestPrivateDir(witness)
	if err != nil {
		return err
	}
	defer dir.Close()
	filename := "ready-" + nonce + ".txt"
	contents := []byte(t15GuestReadyHeader + "\ncase=" + t15GuestCase +
		"\nnonce=" + nonce + "\n")
	fd, err := unix.Openat(int(dir.Fd()), filename,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), filename)
	if file == nil {
		_ = unix.Close(fd)
		return errors.New("failed to create guest ready marker descriptor")
	}
	n, err := file.Write(contents)
	if err != nil || n != len(contents) {
		_ = file.Close()
		return errors.New("incomplete guest phase marker")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return err
	}
	check, err := unix.Openat(int(dir.Fd()), filename,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	verified := os.NewFile(uintptr(check), filename)
	if verified == nil {
		_ = unix.Close(check)
		return errors.New("guest marker reread descriptor refused")
	}
	defer verified.Close()
	final, err := io.ReadAll(io.LimitReader(verified, 256))
	if err != nil || string(final) != string(contents) {
		return errors.New("guest marker changed after durable publication")
	}
	info, err := verified.Stat()
	if err != nil || info.Mode().Perm() != 0o600 ||
		!info.Mode().IsRegular() || info.Size() != int64(len(contents)) {
		return errors.New("guest ready marker identity not private")
	}
	named, err := os.Lstat(filepath.Join(witness, filename))
	if err != nil || !os.SameFile(info, named) {
		return errors.New("guest ready marker path was replaced")
	}
	return nil
}

// TestT15DisposableGuestPreparedBoundary is an OPT-IN, long-lived lab
// checkpoint. Ordinary Go CI ALWAYS skips it. Only an operator inside
// an empty disposable VM state scope with an exact acknowledgment may run
// it. The intended next action is the separately guarded ADR 0128 HOST VM
// forced-stop, NEVER an automatic process/core/host shutdown.
func TestT15DisposableGuestPreparedBoundary(t *testing.T) {
	ack := os.Getenv("KTUI_T15_GUEST_ACK")
	if ack == "" {
		t.Skip("explicit disposable guest T15 operator acknowledgment missing")
	}
	if os.Getenv("CI") != "" || os.Geteuid() == 0 {
		t.Fatal("T15 guest checkpoint cannot run inside CI or as root")
	}
	nonce := os.Getenv("KTUI_LAB_NONCE")
	domain := os.Getenv("KTUI_LAB_DOMAIN")
	uuid := os.Getenv("KTUI_LAB_UUID")
	if !t15GuestNonce.MatchString(nonce) ||
		!t15GuestDomain.MatchString(domain) || !t15GuestUUID.MatchString(uuid) ||
		ack != "PREPARE:"+domain+":"+uuid+":"+t15GuestCase+":"+nonce {
		t.Fatal("T15 guest checkpoint requires exact domain/UUID/case/nonce authorization")
	}
	stateHome := os.Getenv("XDG_STATE_HOME")
	if stateHome == "" || !filepath.IsAbs(stateHome) ||
		filepath.Clean(stateHome) != stateHome || strings.Contains(stateHome, "..") {
		t.Fatal("explicit absolute guest XDG_STATE_HOME required")
	}
	stateParent := filepath.Join(stateHome, "karing-tui-v2")
	witness := filepath.Join(stateParent, "recovery-lab", "ktui-powercut-disposable-"+nonce)
	p, err := guestPrivateDir(stateParent)
	if err != nil {
		t.Fatal(err)
	}
	_ = p.Close()
	w, err := guestPrivateDir(witness)
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	pending, err := createGuestT15PreparedJournal(context.Background(),
		filepath.Join(stateParent, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := createGuestT15ReadyMarker(witness, nonce); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("T15_GUEST_READY case=%s nonce=%s prepared_attempt=%d\n",
		t15GuestCase, nonce, pending)
	for {
		time.Sleep(time.Hour)
	}
}

func TestT15PreparedGuestStoreAndReadyMarkerAreTestOnly(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("strict private test guest must be owned by a normal user")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	guest := filepath.Join(root, "karing-tui-v2")
	witness := filepath.Join(guest, "recovery-lab", "ktui-powercut-disposable-"+strings.Repeat("a", 32))
	for _, path := range []string{guest, filepath.Dir(witness), witness} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	dbPath := filepath.Join(guest, "state.db")
	ctx := context.Background()
	attemptID, err := createGuestT15PreparedJournal(ctx, dbPath)
	if err != nil || attemptID <= 0 {
		t.Fatalf("isolated real SQLite store did not reach prepared stage: %d %v", attemptID, err)
	}
	if _, err := createGuestT15PreparedJournal(ctx, dbPath); err == nil {
		t.Fatal("second T15 run overwrote an existing test SQLite DB")
	}
	nonce := strings.Repeat("a", 32)
	if err := createGuestT15ReadyMarker(witness, nonce); err != nil {
		t.Fatal(err)
	}
	if err := createGuestT15ReadyMarker(witness, nonce); err == nil {
		t.Fatal("duplicate T15 phase marker was overwritten")
	}
	data, err := os.ReadFile(filepath.Join(witness, "ready-"+nonce+".txt"))
	if err != nil || string(data) != t15GuestReadyHeader+"\ncase="+t15GuestCase+
		"\nnonce="+nonce+"\n" {
		t.Fatalf("host-visible T15 marker is not bound to committed phase: %v", err)
	}
	reopened, err := Open(ctx, dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	before, err := reopened.Snapshot(ctx)
	if err != nil || before.Revision != 1 || before.RecoveryRequired ||
		before.ActiveAttemptID == nil || *before.ActiveAttemptID != attemptID {
		t.Fatalf("T15 prepared journal was not durable: %+v %v", before, err)
	}
	recovery, err := reopened.RecoverInterrupted(ctx)
	if err != nil || recovery.NeedsReconcile ||
		len(recovery.InterruptedAttemptIDs) != 1 ||
		recovery.InterruptedAttemptIDs[0] != attemptID {
		t.Fatalf("prepared journal recovery did not refuse activation: %+v %v", recovery, err)
	}
	after, err := reopened.Snapshot(ctx)
	if err != nil || after.Revision != 1 || after.RecoveryRequired ||
		after.ActiveAttemptID != nil || after.AppliedGenerationID == nil ||
		after.LastKnownGoodGenerationID == nil ||
		*before.AppliedGenerationID != *after.AppliedGenerationID ||
		*before.LastKnownGoodGenerationID != *after.LastKnownGoodGenerationID {
		t.Fatalf("isolated T15 replay lost committed generation: %+v -> %+v %v", before, after, err)
	}
	for _, file := range []string{dbPath, filepath.Join(witness, "ready-"+nonce+".txt")} {
		info, err := os.Lstat(file)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("guest test data unexpectedly public: %s %v %v", file, info, err)
		}
	}
}
