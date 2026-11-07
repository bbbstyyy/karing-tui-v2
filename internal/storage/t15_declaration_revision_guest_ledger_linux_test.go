//go:build linux

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"testing"
)

// Use real v18 Go Store declaration CAS transactions on an isolated
// disposable SQLite file. This does not restart a guest, Core or restore data.
func TestGuestAuditRealV18OlderDeclarationRevisionDrift(t *testing.T) {
	g := newGuestBridge(t)
	g.seedRealV18(t, false)
	ctx := context.Background()
	store, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	older := []byte("{\"route\":{\"mode\":\"rule\"},\"dns\":{\"strategy\":\"first\"}}")
	latest := []byte("{\"route\":{\"mode\":\"rule\"},\"dns\":{\"strategy\":\"latest\"}}")
	first, err := store.CommitDeclaration(ctx, 0, older, "test:t15-declaration-audit")
	if err != nil || first.Revision != 1 {
		t.Fatalf("could not seed first immutable declaration: %+v %v", first, err)
	}
	second, err := store.CommitDeclaration(ctx, 1, latest, "test:t15-declaration-audit")
	if err != nil || second.Revision != 2 {
		t.Fatalf("could not seed latest immutable declaration: %+v %v", second, err)
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil || current.Revision != 2 || !bytes.Equal(current.DocumentJSON, latest) {
		t.Fatalf("wrong declaration head for fixture: %+v %v", current, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	before, err := os.ReadFile(g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	pinned := g.capture(t)
	g.syntheticStopObservation(t)
	report := g.run(t, "verify", pinned, true)
	if report["status"] != "sqlite_subset_consistent_manual_review_only" ||
		report["restore_authorized"] != false ||
		report["archive_hmac_verified"] != false ||
		report["physical_power_loss_verified"] != false ||
		report["guest_reboot_verified"] != false {
		t.Fatalf("declaration audit overstated evidence: %+v", report)
	}
	after, err := os.ReadFile(g.dbPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("read-only declaration audit mutated SQLite: %v", err)
	}

	// Replace only the OLDER declaration and its SHA. The current latest
	// revision, Applied/LKG, selection, and generation ledger do not change.
	forged := []byte("{\"route\":{\"mode\":\"direct\"},\"dns\":{\"strategy\":\"first\"}}")
	db, err := sql.Open("sqlite", g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.ExecContext(ctx,
		"UPDATE declaration_revisions SET document_json=?, document_sha256=? WHERE revision=1",
		forged, sha256String(forged))
	if err != nil {
		t.Fatal(err)
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		t.Fatalf("old declaration mutation did not affect one row: %d %v", changed, err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", pinned, false)
}
