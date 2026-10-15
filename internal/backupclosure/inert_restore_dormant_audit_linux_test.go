//go:build linux

package backupclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestDormantRuleAuditPublishedAndPendingRemainUntrusted(t *testing.T) {
	f, _, pins, _, key, parent := makeDormantRuleBundleFixture(t)
	ctx := context.Background()
	initial, err := InspectDormantRuleBundles(ctx, f.store)
	if err != nil || len(initial.Scopes) != 0 || initial.RestoreSupported || initial.RestoreReady {
		t.Fatalf("unexpected initial inventory: %+v %v", initial, err)
	}
	if _, err := pins.StageDormantRuleBundle(ctx, parent, key); err != nil {
		t.Fatal(err)
	}
	report, err := InspectDormantRuleBundles(ctx, f.store)
	if err != nil || report.PublishedCount != 1 || report.PendingCount != 0 ||
		len(report.Scopes) != 1 || report.Scopes[0].Phase != "published_untrusted" ||
		report.Scopes[0].RuleFiles != 1 || report.Scopes[0].RuleBytes != int64(len(f.ruleData)) ||
		report.RuleBytesVerified || !report.RequiresManualReview || report.RestoreReady || report.RestoreSupported ||
		report.PreparedJournalCount != 1 {
		t.Fatalf("published-looking directory must stay untrusted: %+v %v", report, err)
	}
	if err := os.Mkdir(filepath.Join(parent, dormantRulePendingPrefix+"ABCDEF"), 0o700); err != nil {
		t.Fatal(err)
	}
	report, err = InspectDormantRuleBundles(ctx, f.store)
	if err != nil || report.PendingCount != 1 || report.PublishedCount != 1 || len(report.Scopes) != 2 {
		t.Fatalf("pending scope audit failed: %+v %v", report, err)
	}
	if len(dormantStageEntries(t, parent)) != 2 {
		t.Fatal("audit changed directory entries")
	}
}

func TestDormantRuleAuditRejectsTamperingAndDoesNotRemove(t *testing.T) {
	for _, fault := range []string{"unknown", "symlink", "extra", "mode", "replacement", "cancel", "overquota"} {
		t.Run(fault, func(t *testing.T) {
			f, _, pins, _, key, parent := makeDormantRuleBundleFixture(t)
			ctx := context.Background()
			if _, err := pins.StageDormantRuleBundle(ctx, parent, key); err != nil {
				t.Fatal(err)
			}
			published := dormantRuleBundlePrefix + pins.Evidence().ArchiveSHA256
			scope := filepath.Join(parent, published)
			leaf := filepath.Join(scope, f.ruleHash+".json")
			var report DormantRuleBundleAudit
			var err error
			switch fault {
			case "unknown":
				err = os.WriteFile(filepath.Join(parent, "unexpected"), []byte("x"), 0o600)
			case "symlink":
				err = os.Rename(leaf, leaf+".old")
				if err == nil {
					err = os.Symlink(leaf+".old", leaf)
				}
			case "extra":
				err = os.WriteFile(filepath.Join(scope, "extra"), []byte("x"), 0o600)
			case "mode":
				err = os.Chmod(leaf, 0o700)
			case "replacement":
				report, err = inspectDormantRuleBundles(ctx, f.store, func() error {
					return os.Rename(scope, scope+".moved")
				})
			case "cancel":
				cancelled, done := context.WithCancel(ctx)
				done()
				report, err = InspectDormantRuleBundles(cancelled, f.store)
			case "overquota":
				for i := 0; i < MaxDormantRuleAuditScopes; i++ {
					if err = os.Mkdir(filepath.Join(parent, dormantRulePendingPrefix+"ABCDEF"+string(rune('a'+i))), 0o700); err != nil {
						break
					}
				}
			}
			if err != nil && fault != "replacement" && fault != "cancel" {
				t.Fatal(err)
			}
			if fault != "replacement" && fault != "cancel" {
				report, err = InspectDormantRuleBundles(ctx, f.store)
			}
			if err == nil || !reflect.DeepEqual(report, DormantRuleBundleAudit{}) {
				t.Fatalf("unsafe scope accepted: %+v %v", report, err)
			}
			if fault != "cancel" && len(dormantStageEntries(t, parent)) == 0 {
				t.Fatal("audit unexpectedly removed data")
			}
		})
	}
}

func TestDormantRuleAuditRefusesMissingOrPublicRoot(t *testing.T) {
	f, _, _, _, _, parent := makeDormantRuleBundleFixture(t)
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectDormantRuleBundles(context.Background(), f.store); !errors.Is(err, ErrDormantRuleBundleAudit) {
		t.Fatalf("public stage root accepted: %v", err)
	}
	if err := os.Remove(parent); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectDormantRuleBundles(context.Background(), f.store); !errors.Is(err, ErrDormantRuleBundleAudit) {
		t.Fatalf("missing root accepted: %v", err)
	}
}

var _ = storage.InertRestorePrepared
