//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
)

func TestPreflightInertArchiveOfflineAndNoSensitiveOutput(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	parent := testSealedDir(t, f)
	archivePath := filepath.Join(parent, "preflight.ktbackup")
	key := testSealedKey(t)
	receipt, err := closure.SealInertArchive(context.Background(), archivePath, key)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	report, err := PreflightInertArchive(context.Background(), archivePath, key, closure)
	if err != nil {
		t.Fatal(err)
	}
	if report.ArchiveSHA256 != receipt.ArchiveSHA256 ||
		report.InventorySHA256 != receipt.InventorySHA256 ||
		report.ArchiveBytes != receipt.Bytes || report.Format != ManifestVersion ||
		report.StorageSchema != supportedStorageSchema ||
		report.GenerationCount != 1 || report.RuleSetCount != 1 ||
		report.RuleSetBytes != int64(len(f.ruleData)) ||
		report.CoreIncluded || report.TargetMetadataCompatible ||
		!report.ContainsCredentials || !report.ResourceDigestsVerified ||
		!report.ComparedWithCurrent || report.DatabaseDifferent ||
		report.Generations.Shared != 1 ||
		report.RuleSets.Shared != 1 ||
		report.Generations.OnlyInArchive != 0 ||
		report.Generations.OnlyInCurrent != 0 ||
		report.RestoreReady || report.RestoreSupported {
		t.Fatalf("unexpected offline preflight summary: %+v", report)
	}
	for _, reason := range []string{
		"approved_core_missing_from_archive",
		"transactional_restore_not_implemented",
		"sqlite_logical_restore_validation_not_implemented",
	} {
		if !hasPreflightReason(report.Blockers, reason) {
			t.Fatalf("missing strict restore blocker %q: %+v", reason, report)
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{
		"token-DO-NOT-EXPOSE", "private.example", f.rulePath, f.stateRoot,
	} {
		if bytes.Contains(encoded, []byte(sensitive)) {
			t.Fatalf("preflight leaked sensitive source %q", sensitive)
		}
	}
	after, err := os.ReadDir(parent)
	if err != nil || len(after) != len(before) {
		t.Fatalf("preflight wrote files to archive directory: %+v %v", after, err)
	}
	for index := range before {
		if before[index].Name() != after[index].Name() {
			t.Fatal("preflight changed archive directory entries")
		}
	}
	// The archive may be inspected without any live-state snapshot.
	standalone, err := PreflightInertArchive(context.Background(), archivePath, key, nil)
	if err != nil || standalone.ComparedWithCurrent ||
		standalone.ArchiveSHA256 != report.ArchiveSHA256 {
		t.Fatalf("standalone preflight failed: %+v %v", standalone, err)
	}
}

func hasPreflightReason(reasons []string, expected string) bool {
	for _, reason := range reasons {
		if reason == expected {
			return true
		}
	}
	return false
}

func TestPreflightInertArchiveComparesDigestIdentityNotRowNumber(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	oldClosure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	parent := testSealedDir(t, f)
	path := filepath.Join(parent, "historical.ktbackup")
	key := testSealedKey(t)
	if _, err := oldClosure.SealInertArchive(context.Background(), path, key); err != nil {
		t.Fatal(err)
	}
	if err := oldClosure.Close(); err != nil {
		t.Fatal(err)
	}
	f.commit(t, false)
	current, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	report, err := PreflightInertArchive(context.Background(), path, key, current)
	if err != nil {
		t.Fatal(err)
	}
	if !report.ComparedWithCurrent || !report.DatabaseDifferent ||
		report.GenerationCount != 1 ||
		report.Generations != (InertDigestDifference{OnlyInCurrent: 1, Shared: 1}) ||
		report.RuleSets != (InertDigestDifference{Shared: 1}) ||
		report.RestoreReady {
		t.Fatalf("content digest comparison was incorrect: %+v", report)
	}

	// A separate store can reuse row ID 1 with a different generation.
	other := newFixture(t)
	other.commit(t, false)
	otherClosure, err := Build(context.Background(), other.store, other.stateRoot, other.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer otherClosure.Close()
	report, err = PreflightInertArchive(context.Background(), path, key, otherClosure)
	if err != nil {
		t.Fatal(err)
	}
	if report.Generations != (InertDigestDifference{OnlyInArchive: 1, OnlyInCurrent: 1}) ||
		report.RuleSets != (InertDigestDifference{OnlyInArchive: 1}) {
		t.Fatalf("reused row IDs conflated unrelated generations: %+v", report)
	}
}

func TestPreflightInertArchiveFailsClosedBeforeReturningMetadata(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	parent := testSealedDir(t, f)
	path := filepath.Join(parent, "authentication.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), path, key); err != nil {
		t.Fatal(err)
	}
	wrongKey := testSealedKey(t)
	if report, err := PreflightInertArchive(context.Background(), path, wrongKey, nil);
		!errors.Is(err, ErrUnsafeSealedArchive) || !reflect.DeepEqual(report, InertArchivePreflight{}) {
		t.Fatalf("unauthenticated metadata escaped: %+v %v", report, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if report, err := PreflightInertArchive(ctx, path, key, nil);
		!errors.Is(err, context.Canceled) || !reflect.DeepEqual(report, InertArchivePreflight{}) {
		t.Fatalf("canceled preflight escaped: %+v %v", report, err)
	}
	// After the first fully authenticated read, corrupt the same inode
	// before the metadata replay. The replay's full-file hash must reject it.
	report, err := preflightInertArchive(context.Background(), path, key, nil, func() {
		file, openErr := os.OpenFile(path, os.O_RDWR, 0)
		if openErr != nil {
			t.Error(openErr)
			return
		}
		var previous [1]byte
		if _, openErr = file.ReadAt(previous[:], int64(sealedArchiveHeaderBytes+5)); openErr == nil {
			previous[0] ^= 0x40
			_, openErr = file.WriteAt(previous[:], int64(sealedArchiveHeaderBytes+5))
		}
		if closeErr := file.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		if openErr != nil {
			t.Error(openErr)
		}
	})
	if !errors.Is(err, ErrUnsafeSealedArchive) || !reflect.DeepEqual(report, InertArchivePreflight{}) {
		t.Fatalf("post-authentication inode mutation escaped: %+v %v", report, err)
	}
}

func TestPreflightInertArchiveRejectsTamperedCurrentClosure(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	current, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	parent := testSealedDir(t, f)
	path := filepath.Join(parent, "current.ktbackup")
	key := testSealedKey(t)
	if _, err := current.SealInertArchive(context.Background(), path, key); err != nil {
		t.Fatal(err)
	}
	current.Inventory.RuleSets[0].Size++
	report, err := PreflightInertArchive(context.Background(), path, key, current)
	if !errors.Is(err, ErrUnsafeSealedArchive) || !reflect.DeepEqual(report, InertArchivePreflight{}) {
		t.Fatalf("corrupt local closure was used for comparison: %+v %v", report, err)
	}
}

func TestPreflightCoreArchitectureAndPinnedIdentityAssessment(t *testing.T) {
	v1 := sampleInertInventory()
	var report InertArchivePreflight
	assessArchiveTarget(&report, v1)
	if report.TargetMetadataCompatible || !hasPreflightReason(report.Blockers, "approved_core_missing_from_archive") {
		t.Fatal("v1 inventory was treated as a restore-compatible core bundle")
	}
	v2 := sampleInertInventory()
	v2.Format = CoreManifestVersion
	v2.Core = sampleInertCore(t)
	if err := validateInertInventory(v2); err != nil {
		t.Fatal(err)
	}
	report = InertArchivePreflight{}
	assessArchiveTarget(&report, v2)
	if !report.TargetMetadataCompatible || report.CoreArchitecture != runtime.GOARCH ||
		len(report.Blockers) != 0 {
		t.Fatalf("locked local metadata rejected: %+v", report)
	}
	otherArch := "arm64"
	if runtime.GOARCH == otherArch {
		otherArch = "amd64"
	}
	hash, err := coreartifact.ExpectedSHA256(otherArch)
	if err != nil {
		t.Fatal(err)
	}
	v2.Core.Architecture = otherArch
	v2.Core.SHA256 = hash
	v2.Core.RelativePath = fmt.Sprintf("core/%s.bin", hash)
	if err := validateInertInventory(v2); err != nil {
		t.Fatal(err)
	}
	report = InertArchivePreflight{}
	assessArchiveTarget(&report, v2)
	if report.TargetMetadataCompatible ||
		!hasPreflightReason(report.Blockers, "core_architecture_mismatch") {
		t.Fatalf("cross-architecture core accepted: %+v", report)
	}
}

func TestPreflightInertArchiveRejectsUntrustedPathAndNoFileWrites(t *testing.T) {
	f := newFixture(t)
	parent := testSealedDir(t, f)
	path := filepath.Join(parent, "untrusted.ktbackup")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 128)), 0o600); err != nil {
		t.Fatal(err)
	}
	key := testSealedKey(t)
	report, err := PreflightInertArchive(context.Background(), path, key, nil)
	if !errors.Is(err, ErrUnsafeSealedArchive) || !reflect.DeepEqual(report, InertArchivePreflight{}) {
		t.Fatalf("forged ciphertext was accepted: %+v %v", report, err)
	}
	link := filepath.Join(parent, "symlink.ktbackup")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := PreflightInertArchive(context.Background(), link, key, nil); !errors.Is(err, ErrUnsafeSealedArchive) {
		t.Fatal("symlink archive accepted by preflight")
	}
}
