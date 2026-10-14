//go:build linux

package backupclosure

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestInertPortablePathPreviewDeterministicAndNonMutating(t *testing.T) {
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	before, err := f.store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(f.stateRoot, "hypothetical-new-state")
	first, err := lease.PreviewPortableRulePaths(ctx, target, key)
	if err != nil || first.RestoreSupported || first.RestoreReady ||
		first.ArchiveSHA256 != record.ArchiveSHA256 ||
		first.InventorySHA256 != record.InventorySHA256 ||
		first.GenerationCount != 1 || first.RuleSetCount != 1 ||
		first.RelocatedGenerationCount != 1 ||
		!validLowerSHA(first.RelocatedConfigDigest) {
		t.Fatalf("invalid portable preview or authority escalation: %+v %v", first, err)
	}
	second, err := lease.PreviewPortableRulePaths(ctx, target, key)
	if err != nil || first != second {
		t.Fatalf("relocation preview not deterministic: %+v %+v %v", first, second, err)
	}
	different, err := lease.PreviewPortableRulePaths(ctx, target+"-other", key)
	if err != nil || different.RelocatedConfigDigest == first.RelocatedConfigDigest ||
		different.RestoreReady || different.RestoreSupported {
		t.Fatalf("destination path not bound to relocation hash: %+v %v", different, err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview created target state directory: %v", err)
	}
	if _, err := os.Lstat(target+"-other"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview created second target directory: %v", err)
	}
	if strings.Contains(first.RelocatedConfigDigest, f.stateRoot) ||
		strings.Contains(first.RelocatedConfigDigest, "token-DO-NOT-EXPOSE") {
		t.Fatal("portable preview leaked source path or token")
	}
	after, err := f.store.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("preview changed current configuration: %+v -> %+v %v", before, after, err)
	}
	records, err := f.store.InspectInertRestoreRecords(ctx)
	if err != nil || len(records) != 1 ||
		records[0].ID != record.ID || records[0].Phase != storage.InertRestorePrepared {
		t.Fatalf("preview changed preparation journal: %+v %v", records, err)
	}
	if _, err := os.Lstat(filepath.Join(directory, inertRestoreCipherName)); err != nil {
		t.Fatalf("preview removed encrypted candidate: %v", err)
	}
}

func TestOneNativePortablePathRewriteOnlyTouchesBoundLocalPaths(t *testing.T) {
	f := newFixture(t)
	id := f.commit(t, true)
	artifacts, err := f.store.GenerationArtifacts(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	source := bytes.Clone(artifacts.ConfigJSON)
	allowed := map[string]bool{"rule-sets/sha256/" + f.ruleHash + ".json": true}
	target := filepath.Join(f.stateRoot, "recovered-state")
	hash, changed, err := previewOneNativeRelocation(
		artifacts.ConfigJSON, artifacts.ManifestJSON, target, allowed)
	if err != nil || !changed || !validLowerSHA(hash) ||
		hash == artifacts.ConfigSHA256 {
		t.Fatalf("valid portable mapping rejected: %s %t %v", hash, changed, err)
	}
	// Independently construct the expected JSON object, including the
	// sensitive non-rule field, to prove we did not delete unrelated data.
	var expected map[string]any
	if err := json.Unmarshal(artifacts.ConfigJSON, &expected); err != nil {
		t.Fatal(err)
	}
	route := expected["route"].(map[string]any)
	rules := route["rule_set"].([]any)
	rule := rules[0].(map[string]any)
	if rule["path"] != f.rulePath || expected["private_note"] != "token-DO-NOT-EXPOSE" {
		t.Fatal("fixture does not contain original sensitive and local fields")
	}
	rule["path"] = filepath.Join(target, "core", "rule-sets", "sha256", f.ruleHash+".json")
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	if shaHex(expectedJSON) != hash {
		t.Fatal("path preview changed other fields or failed to bind target path")
	}
	if !bytes.Equal(source, artifacts.ConfigJSON) {
		t.Fatal("preview changed archived native input bytes")
	}
	if _, _, err := previewOneNativeRelocation(
		artifacts.ConfigJSON, artifacts.ManifestJSON, target,
		map[string]bool{}); !errors.Is(err, ErrInertPortablePathPreview) {
		t.Fatalf("missing authenticated resource accepted: %v", err)
	}
	if _, _, err := previewOneNativeRelocation(
		append(bytes.Clone(artifacts.ConfigJSON), ' '), artifacts.ManifestJSON,
		target, allowed); !errors.Is(err, ErrInertPortablePathPreview) {
		t.Fatalf("configuration hash drift accepted: %v", err)
	}
	var metadata compiler.NativeManifest
	if err := json.Unmarshal(artifacts.ManifestJSON, &metadata); err != nil {
		t.Fatal(err)
	}
	metadata.RuleSets[0].Format = compiler.RuleSetFormatBinary
	badManifest, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := previewOneNativeRelocation(
		artifacts.ConfigJSON, badManifest, target, allowed);
		!errors.Is(err, ErrInertPortablePathPreview) {
		t.Fatalf("manifest rule format mismatch accepted: %v", err)
	}
}

func TestOneNativePortablePathPreviewWithoutLocalRules(t *testing.T) {
	f := newFixture(t)
	id := f.commit(t, false)
	artifacts, err := f.store.GenerationArtifacts(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	hash, changed, err := previewOneNativeRelocation(
		artifacts.ConfigJSON, artifacts.ManifestJSON,
		filepath.Join(f.stateRoot, "another-state"), map[string]bool{})
	if err != nil || changed || hash != artifacts.ConfigSHA256 {
		t.Fatalf("rule-free native config changed: %s %t %v", hash, changed, err)
	}
}

func TestInertPortablePathPreviewRejectsUnsafeDestinationsAndKeys(t *testing.T) {
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Close()
	wrongKey := key
	wrongKey[0] ^= 0x33
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	for _, tc := range []struct {
		name   string
		ctx    context.Context
		root   string
		key    [32]byte
	}{
		{"relative", ctx, "relative", key},
		{"filesystem_root", ctx, "/", key},
		{"noncanonical", ctx, f.stateRoot + "/../bad", key},
		{"nul_byte", ctx, f.stateRoot + "/bad\x00name", key},
		{"newline", ctx, f.stateRoot + "/bad\nname", key},
		{"too_long", ctx, f.stateRoot + "/" + strings.Repeat("x", 1100), key},
		{"ciphertext_scope", ctx, directory, key},
		{"candidate_parent", ctx, filepath.Dir(directory), key},
		{"nested_candidate", ctx, filepath.Join(filepath.Dir(directory), "fake"), key},
		{"wrong_key", ctx, filepath.Join(f.stateRoot, "other-state"), wrongKey},
		{"zero_key", ctx, filepath.Join(f.stateRoot, "other-state"), [32]byte{}},
		{"cancelled", cancelled, filepath.Join(f.stateRoot, "other-state"), key},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := lease.PreviewPortableRulePaths(tc.ctx, tc.root, tc.key)
			if err == nil || !reflect.DeepEqual(result, InertPortablePathPreview{}) {
				t.Fatalf("unsafe preview accepted: %+v %v", result, err)
			}
		})
	}
	if _, err := lease.PreviewPortableRulePaths(ctx,
		filepath.Join(f.stateRoot, "good"), key); err != nil {
		t.Fatalf("invalid preview poisoned held journal-bound lease: %v", err)
	}
}

func TestInertPortablePathPreviewFailsAfterLiveStateAndJournalDrift(t *testing.T) {
	for _, mode := range []string{"selection", "abandon", "cipher_inode"} {
		t.Run(mode, func(t *testing.T) {
			f, directory, record, key := makeJournalBoundLeaseFixture(t)
			ctx := context.Background()
			lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
				filepath.Dir(directory), record.ID, key)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Close()
			target := filepath.Join(f.stateRoot, "portable-target")
			report, err := lease.previewPortableRulePaths(ctx, target, key, func() error {
				switch mode {
				case "selection":
					_, err := f.store.SetCurrentSelectionIntent(ctx,
						[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"late-change"}`))
					return err
				case "abandon":
					return f.store.AbandonInertRestoreRecord(ctx,
						record.ID, record.CandidateScope, record.ArchiveSHA256)
				case "cipher_inode":
					path := filepath.Join(directory, inertRestoreCipherName)
					data, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					replacement := filepath.Join(directory, "injected-swap")
					if err := os.WriteFile(replacement, data, 0o600); err != nil {
						return err
					}
					return os.Rename(replacement, path)
				}
				return errors.New("unknown fault")
			})
			if !errors.Is(err, ErrInertPortablePathPreview) ||
				!reflect.DeepEqual(report, InertPortablePathPreview{}) {
				t.Fatalf("changed %s was not rejected: %+v %v", mode, report, err)
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejected preview wrote a destination: %v", err)
			}
			snapshot, err := f.store.Snapshot(ctx)
			if err != nil || snapshot.ActiveAttemptID != nil {
				t.Fatalf("refusal activated an apply transaction: %+v %v", snapshot, err)
			}
		})
	}
}

func TestInertPortablePathPreviewSerializesLeaseClose(t *testing.T) {
	f, directory, record, key := makeJournalBoundLeaseFixture(t)
	ctx := context.Background()
	lease, err := AcquireInertRestoreResourceLease(ctx, f.store,
		filepath.Dir(directory), record.ID, key)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	probed := make(chan error, 1)
	go func() {
		_, err := lease.previewPortableRulePaths(ctx,
			filepath.Join(f.stateRoot, "target-view"), key, func() error {
				close(started)
				<-release
				return nil
			})
		probed <- err
	}()
	select {
	case <-started:
	case <-time.After(12 * time.Second):
		t.Fatal("relocation never reached final CAS boundary")
	}
	closed := make(chan error, 1)
	go func() { closed <- lease.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("lease closed during protected SQLite inspection: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-probed:
		if err != nil {
			t.Fatalf("path relocation preview failed: %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("path preview blocked forever")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("lease Close blocked forever")
	}
}
