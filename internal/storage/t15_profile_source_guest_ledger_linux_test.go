//go:build linux

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

// ADR 0141 tests a real Go v18 source/lease/usage state against the same
// guest-only Python read-only verifier used after the synthetic VM witness.
// No production database, VM reboot, external HTTP or Core activation occurs.
func TestGuestAuditRealV18ProfileSourceMetadataDrift(t *testing.T) {
	g := newGuestBridge(t)
	g.seedRealV18(t, false)
	ctx := context.Background()
	store, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	spec := testRemoteProfileSource("profile-a", profile.FetchDirect)
	spec.UpdateInterval = profile.DefaultUpdateInterval
	spec.Filter = profile.NodeFilterSpec{
		Method: profile.NodeFilterInclude, KeywordOrRegex: "HK|Hong Kong",
		MatchAttribute: true,
	}
	source, err := store.CommitProfileSource(ctx, 0, spec)
	if err != nil || source.Revision != 1 {
		t.Fatalf("create real Go source state: %+v %v", source, err)
	}
	first, err := store.BeginProfileUpdate(ctx, spec.ProfileID, source.Revision, "guest-source-1")
	if err != nil {
		t.Fatal(err)
	}
	upload, download, total := int64(1024), int64(2048), int64(4096)
	expires := time.Date(2027, time.January, 1, 0, 0, 0, 0, time.UTC)
	if err := store.FinishProfileUpdateSuccess(ctx, first, ProfileUpdateSuccess{
		SourceRevision:        "etag-v1",
		ETag:                  "\"private-etag-v1\"",
		LastModified:          "Wed, 07 Oct 2026 16:00:00 GMT",
		UsageMetadataObserved: true,
		SubscriptionUsage: &profile.SubscriptionUsage{
			UploadBytes: &upload, DownloadBytes: &download,
			TotalBytes: &total, ExpiresAt: &expires,
		},
	}); err != nil {
		t.Fatal(err)
	}
	second, err := store.BeginProfileUpdate(ctx, spec.ProfileID, source.Revision, "guest-source-2")
	if err != nil {
		t.Fatal(err)
	}
	retryAfter := time.Now().UTC().Add(15 * time.Minute).Round(time.Second)
	if err := store.FinishProfileUpdateFailure(ctx, second, "temporary upstream failure", &retryAfter); err != nil {
		t.Fatal(err)
	}
	current, err := store.ProfileSource(ctx, spec.ProfileID)
	if err != nil || current.Revision != 1 || current.ActiveUpdateID != "" ||
		current.SubscriptionUsage == nil || current.SubscriptionUsage.TotalBytes == nil ||
		*current.SubscriptionUsage.TotalBytes != total ||
		current.ConsecutiveFailures != 1 || current.RetryAfterAt == nil ||
		current.Spec.Location != spec.Location {
		t.Fatalf("unexpected committed source/usage state: %+v %v", current, err)
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
		report["metadata_deletion_authorized"] != false ||
		report["archive_hmac_verified"] != false ||
		report["core_health_verified"] != false ||
		report["guest_reboot_verified"] != false ||
		report["physical_power_loss_verified"] != false {
		t.Fatalf("source audit elevated synthetic evidence: %+v", report)
	}
	after, err := os.ReadFile(g.dbPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("guest source audit modified real Go SQLite main bytes: %v", err)
	}

	// A plausible URL change WITHOUT revision/CAS update must invalidate
	// independent pinned evidence, even though no profile snapshot exists.
	db, err := sql.Open("sqlite", g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := db.ExecContext(ctx,
		"UPDATE profile_sources SET location=? WHERE profile_id=?",
		"https://changed.example.invalid/private?token=forged", spec.ProfileID)
	if err != nil {
		t.Fatal(err)
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		t.Fatalf("source tamper affected %d rows: %v", n, e)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", pinned, false)

	// Restore the original text; then modify only persisted subscription
	// usage, without changing its remote URL, revision or applied Core.
	db, err = sql.Open("sqlite", g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE profile_sources SET location=? WHERE profile_id=?",
		spec.Location, spec.ProfileID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", pinned, true)
	db, err = sql.Open("sqlite", g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		"UPDATE profile_sources SET subscription_total_bytes=? WHERE profile_id=?",
		total+1, spec.ProfileID); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	g.run(t, "verify", pinned, false)
}

func TestGuestAuditRealV18ProfileUpdateLeaseRecoveryRequiresSeparateReview(t *testing.T) {
	g := newGuestBridge(t)
	g.seedRealV18(t, false)
	ctx := context.Background()
	store, err := Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	spec := testRemoteProfileSource("profile-a", profile.FetchDirect)
	source, err := store.CommitProfileSource(ctx, 0, spec)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := store.BeginProfileUpdate(ctx, spec.ProfileID, source.Revision, "guest-lease-pending-1")
	if err != nil || lease.ID == "" {
		t.Fatalf("could not commit live-shaped source update lease: %+v %v", lease, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	pinned := g.capture(t)
	g.syntheticStopObservation(t)
	result := g.run(t, "verify", pinned, true)
	if result["restore_authorized"] != false || result["guest_reboot_verified"] != false {
		t.Fatalf("live-shaped lease was falsely promoted to reboot proof: %+v", result)
	}

	store, err = Open(ctx, g.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	interrupted, err := store.RecoverInterruptedProfileUpdates(ctx)
	if err != nil || len(interrupted) != 1 ||
		interrupted[0].ProfileID != spec.ProfileID ||
		interrupted[0].UpdateID != lease.ID {
		t.Fatalf("production source lease recovery did not match test state: %+v %v", interrupted, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	// The narrow prepared-apply reconciliation MUST NOT implicitly permit
	// source-update lease recovery. Manual hold remains mandatory.
	g.run(t, "verify", pinned, false)
}
