//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func newInertCandidateParent(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, "restore-candidates")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInertRestoreCandidateCiphertextRoundTripAndPersistence(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	sealedDir := testSealedDir(t, f)
	source := filepath.Join(sealedDir, "backed-up.ktbackup")
	key := testSealedKey(t)
	receipt, err := closure.SealInertArchive(context.Background(), source, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoBackupScopes(t, f)
	before, err := f.store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	candidate, err := StageInertRestoreCandidate(context.Background(), source, parent, key)
	if err != nil {
		t.Fatal(err)
	}
	location := candidate.Directory()
	if !validInertRestoreCandidateDir(location) || filepath.Dir(location) != parent {
		t.Fatalf("candidate escaped private parent: %q", location)
	}
	entries, err := os.ReadDir(location)
	if err != nil || len(entries) != 1 || entries[0].Name() != inertRestoreCipherName {
		t.Fatalf("candidate has extra files: %+v %v", entries, err)
	}
	ciphertext, err := os.ReadFile(filepath.Join(location, inertRestoreCipherName))
	if err != nil {
		t.Fatal(err)
	}
	sourceCipher, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(ciphertext, sourceCipher) {
		t.Fatalf("isolated ciphertext differs from authenticated archive: %v", err)
	}
	for _, private := range []string{"token-DO-NOT-EXPOSE", f.stateRoot, "private.example"} {
		if bytes.Contains(ciphertext, []byte(private)) {
			t.Fatal("candidate contains plaintext secret")
		}
	}
	info, err := os.Lstat(filepath.Join(location, inertRestoreCipherName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("candidate file permissions are unsafe: %+v %v", info, err)
	}
	report, err := candidate.Verify(context.Background(), key)
	if err != nil || !report.SQLiteLogicalVerified || !report.SchemaCatalogVerified ||
		report.RestoreSupported || report.RestoreReady ||
		report.ArchiveSHA256 != receipt.ArchiveSHA256 {
		t.Fatalf("candidate generated restore authority or failed verification: %+v %v", report, err)
	}
	if _, err := ReopenInertRestoreCandidate(context.Background(), location, key);
		!errors.Is(err, ErrInertRestoreCandidateBusy) {
		t.Fatalf("active candidate lease was stolen: %v", err)
	}
	if err := candidate.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(location); err != nil {
		t.Fatalf("Close removed durable ciphertext: %v", err)
	}
	reopened, err := ReopenInertRestoreCandidate(context.Background(), location, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Verify(context.Background(), [32]byte{}); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatal("zero encryption key accepted")
	}
	check, err := reopened.Verify(context.Background(), key)
	if err != nil || !sameInertPreflightEvidence(check, report) {
		t.Fatalf("re-opened candidate evidence mismatch: %+v %v", check, err)
	}
	after, err := f.store.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(after, before) {
		t.Fatalf("candidate isolation touched live daemon state: before=%+v after=%+v err=%v", before, after, err)
	}
	if err := reopened.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(location); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("explicit discard retained directory: %v", err)
	}
	if _, err := os.Stat(source); err != nil {
		t.Fatalf("discard removed source archive: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInertRestoreCandidateWrongKeyAndTamperingFailClosed(t *testing.T) {
	f := newFixture(t)
	f.commit(t, false)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	directory := testSealedDir(t, f)
	source := filepath.Join(directory, "origin.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	wrong := testSealedKey(t)
	if _, err := StageInertRestoreCandidate(context.Background(), source, parent, wrong);
		!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("wrong source key accepted: %v", err)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("failed stage wrote candidates: %v %+v", err, entries)
	}
	c, err := StageInertRestoreCandidate(context.Background(), source, parent, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.Directory(), inertRestoreCipherName)
	buf, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	buf[len(buf)/2] ^= 0x80
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		t.Fatal(err)
	}
	if result, err := c.Verify(context.Background(), key);
		!errors.Is(err, ErrUnsafeInertRestoreCandidate) || !reflect.DeepEqual(result, InertArchivePreflight{}) {
		t.Fatalf("corrupted isolated candidate accepted: %+v %v", result, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReopenInertRestoreCandidate(context.Background(), filepath.Dir(path), key);
		!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("corrupted candidate re-adopted: %v", err)
	}
	// Releasing the flock neither hides nor automatically deletes ciphertext.
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("failed adoption auto-deleted candidate: %v", err)
	}
	// Deliberate operator-review cleanup is not automated by this API.
}

func TestInertRestoreCandidateRefusesUnknownAndUnsafeScopes(t *testing.T) {
	f := newFixture(t)
	f.commit(t, false)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sourceDir := testSealedDir(t, f)
	source := filepath.Join(sourceDir, "origin.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	unknown := filepath.Join(parent, "unrelated-file")
	if err := os.WriteFile(unknown, []byte("unrelated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StageInertRestoreCandidate(context.Background(), source, parent, key);
		!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("stage accepted unexpected parent entry: %v", err)
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatal(err)
	}
	c, err := StageInertRestoreCandidate(context.Background(), source, parent, key)
	if err != nil {
		t.Fatal(err)
	}
	scope := c.Directory()
	if err := os.WriteFile(filepath.Join(scope, "unknown.txt"), []byte("untrusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := c.Discard(context.Background()); !errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("discard removed unknown file: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(scope, "unknown.txt")); err != nil {
		t.Fatalf("unknown file was deleted: %v", err)
	}
	if _, err := ReopenInertRestoreCandidate(context.Background(), scope, key);
		!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("candidate with unknown files re-adopted: %v", err)
	}
	if _, err := os.Lstat(scope); err != nil {
		t.Fatalf("unknown scope was removed: %v", err)
	}
}

func TestInertRestoreCandidateDoesNotPruneAtCapacity(t *testing.T) {
	f := newFixture(t)
	f.commit(t, false)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sourceDir := testSealedDir(t, f)
	source := filepath.Join(sourceDir, "origin.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	for i := 0; i < MaxInertRestoreCandidates; i++ {
		scope := filepath.Join(parent, fmt.Sprintf("%s%08d", inertRestoreCandidatePrefix, i))
		if err := os.Mkdir(scope, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := StageInertRestoreCandidate(context.Background(), source, parent, key);
		!errors.Is(err, ErrUnsafeInertRestoreCandidate) {
		t.Fatalf("more than eight candidate scopes accepted: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != MaxInertRestoreCandidates {
		t.Fatalf("capacity denial deleted candidates: %+v %v", entries, err)
	}
}

func TestInertRestoreCandidateCrashHolderHelper(t *testing.T) {
	if os.Getenv("KTUI_INERT_CANDIDATE_TEST_HELPER") != "yes" {
		return
	}
	directory := os.Getenv("KTUI_INERT_CANDIDATE_PATH")
	decoded, err := hex.DecodeString(os.Getenv("KTUI_INERT_CANDIDATE_KEY"))
	if err != nil || len(decoded) != 32 {
		t.Fatal("invalid test key")
	}
	var key [32]byte
	copy(key[:], decoded)
	candidate, err := ReopenInertRestoreCandidate(context.Background(), directory, key)
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.Close()
	if _, err := os.Stdout.Write([]byte("ready\n")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Minute)
}

func TestInertRestoreCandidateLeaseSurvivesProcessCrash(t *testing.T) {
	f := newFixture(t)
	f.commit(t, false)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	sourceDir := testSealedDir(t, f)
	source := filepath.Join(sourceDir, "origin.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), source, key); err != nil {
		t.Fatal(err)
	}
	parent := newInertCandidateParent(t, f.stateRoot)
	c, err := StageInertRestoreCandidate(context.Background(), source, parent, key)
	if err != nil {
		t.Fatal(err)
	}
	location := c.Directory()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInertRestoreCandidateCrashHolderHelper$")
	cmd.Env = append(os.Environ(),
		"KTUI_INERT_CANDIDATE_TEST_HELPER=yes",
		"KTUI_INERT_CANDIDATE_PATH="+location,
		"KTUI_INERT_CANDIDATE_KEY="+hex.EncodeToString(key[:]))
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	killed := false
	t.Cleanup(func() {
		if !killed {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})
	prefix := make([]byte, len("ready\n"))
	if _, err := io.ReadFull(out, prefix); err != nil || string(prefix) != "ready\n" {
		t.Fatalf("child did not acquire candidate flock: %q %v", prefix, err)
	}
	if _, err := ReopenInertRestoreCandidate(context.Background(), location, key);
		!errors.Is(err, ErrInertRestoreCandidateBusy) {
		t.Fatalf("live child lease was stolen: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	killed = true
	reopened, err := ReopenInertRestoreCandidate(context.Background(), location, key)
	if err != nil {
		t.Fatalf("crash recovery could not re-authenticate candidate: %v", err)
	}
	if report, err := reopened.Verify(context.Background(), key);
		err != nil || !report.SQLiteLogicalVerified || report.RestoreReady {
		t.Fatalf("restarted candidate had unsafe report: %+v %v", report, err)
	}
	if err := reopened.Discard(context.Background()); err != nil {
		t.Fatal(err)
	}
}
