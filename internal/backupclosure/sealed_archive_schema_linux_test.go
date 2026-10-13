//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func populateArchiveProfileDomains(t *testing.T, f *fixture) {
	t.Helper()
	ctx := context.Background()
	profileID := "archive-provider"
	_, err := f.store.CommitProfileSource(ctx, 0, profile.SourceSpec{
		ProfileID: profileID,
		Format: profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationURL,
		Location: "https://subscription.example/hidden-token",
		Fetch: profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	commit, err := f.store.CommitProfileSnapshot(ctx, storage.ProfileSnapshotCandidate{
		ProfileID: profileID,
		SourceKind: "subscription",
		SourceRevision: "revision-1",
		SourceSHA256: strings.Repeat("b", 64),
		Nodes: []profile.SourceNode{{
			SourceKey: "provider-key-1",
			SourceName: "Node 1",
			PayloadJSON: []byte(`{"name":"confidential","type":"direct"}`),
		}},
	}, storage.ProfileSnapshotCommitOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(commit.Snapshot.Nodes) != 1 {
		t.Fatal("profile snapshot did not commit a node")
	}
	_, err = f.store.CommitProfileNodeOverlay(ctx, 0, profile.NodeOverlay{
		ProfileID: profileID,
		NodeID: commit.Snapshot.Nodes[0].Identity.NodeID,
		Alias: "Favorite node",
		Favorite: true,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticatedArchiveSchemaAndDomainInspection(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	populateArchiveProfileDomains(t, f)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	parent := testSealedDir(t, f)
	path := filepath.Join(parent, "domain-valid.ktbackup")
	key := testSealedKey(t)
	_, err = closure.SealInertArchive(context.Background(), path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoBackupScopes(t, f)
	report, err := PreflightInertArchive(context.Background(), path, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !report.SchemaCatalogVerified || !report.SQLiteLogicalVerified ||
		report.ProfileSnapshotCount != 1 ||
		report.ProfileNodeCount != 1 ||
		report.ProfileSourceCount != 1 ||
		report.ProfileOverlayCount != 1 ||
		report.RestoreSupported || report.RestoreReady {
		t.Fatalf("valid full domain state rejected or allowed restore: %+v", report)
	}
}

func TestReauthenticatedSchemaAndDomainCorruptionRejected(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	populateArchiveProfileDomains(t, f)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	parent := testSealedDir(t, f)
	original := filepath.Join(parent, "original-domains.ktbackup")
	key := testSealedKey(t)
	if _, err := closure.SealInertArchive(context.Background(), original, key); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		sql  string
	}{
		{"additional_ddl", "CREATE TABLE rogue_state (id INTEGER PRIMARY KEY)"},
		{"dropped_index", "DROP INDEX apply_history_generation"},
		{"unexpected_trigger", "CREATE TRIGGER extra_trigger AFTER INSERT ON profile_sources BEGIN SELECT 1; END"},
		{"missing_profile_column", "ALTER TABLE profile_sources DROP COLUMN filter_match_attribute"},
		{"node_payload_digest", "UPDATE profile_snapshot_nodes SET payload_sha256='" + strings.Repeat("f", 64) + "'"},
		{"node_invalid_json", "UPDATE profile_snapshot_nodes SET payload_json=x'6e6f742d6a736f6e'"},
		{"node_bad_ordinal", "UPDATE profile_snapshot_nodes SET ordinal=42"},
		{"wrong_profile_owner", "UPDATE profile_state SET profile_id='unrelated-profile'"},
		{"source_format", "UPDATE profile_sources SET source_format='unauthorized'"},
		{"source_fetch_policy", "UPDATE profile_sources SET fetch_mode='specific_node'"},
		{"source_usage_no_timestamp", "UPDATE profile_sources SET subscription_upload_bytes=100, subscription_usage_updated_at=NULL"},
		{"overlay_invalid_alias", "UPDATE profile_node_overlays SET alias=' bad alias '"},
		{"selection_invalid_json", "UPDATE selection_state SET current_target_json=x'6e6f742d6a736f6e', updated_at='2026-01-01T00:00:00Z'"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(parent, tc.name+".ktbackup")
			tamperAndResealArchive(t, original, path, key, func(data []byte) []byte {
				return mutateInMemorySQLite(t, data, tc.sql)
			})
			if _, err := VerifyInertArchive(context.Background(), path, key); err != nil {
				t.Fatalf("fixture must have valid crypto and database hash: %v", err)
			}
			report, err := PreflightInertArchive(context.Background(), path, key, nil)
			if !errors.Is(err, ErrUnsafeSealedArchive) ||
				!reflect.DeepEqual(report, InertArchivePreflight{}) {
				t.Fatalf("accepted logically broken authenticated archive: %+v err=%v", report, err)
			}
		})
	}
}

func TestArchivedSchemaCheckLeavesLiveStateUntouched(t *testing.T) {
	f := newFixture(t)
	f.commit(t, true)
	populateArchiveProfileDomains(t, f)
	closure, err := Build(context.Background(), f.store, f.stateRoot, f.parent)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	parent := testSealedDir(t, f)
	path := filepath.Join(parent, "read-only.ktbackup")
	key := testSealedKey(t)
	before, err := f.store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := closure.SealInertArchive(context.Background(), path, key); err != nil {
		t.Fatal(err)
	}
	report, err := PreflightInertArchive(context.Background(), path, key, closure)
	if err != nil || !report.SchemaCatalogVerified {
		t.Fatalf("read-only preflight failed: %+v %v", report, err)
	}
	after, err := f.store.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("preflight changed active state: before=%+v after=%+v err=%v", before, after, err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(path) {
		t.Fatalf("preflight wrote an unexpected archive/temp file: %v %+v", err, entries)
	}
}
