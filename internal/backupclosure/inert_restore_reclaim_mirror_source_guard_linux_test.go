//go:build linux

package backupclosure

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRetainedFullMirrorNeverAuthorizesMissingOriginalProofs(t *testing.T) {
	for _, fault := range []string{"remove_plan", "remove_completion", "remove_intent", "late_unknown", "late_selection"} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, parent, expected := makeMirroredReclaimFixture(t)
			ctx := context.Background()
			original, err := lease.MirrorSealedReclaimEvidence(ctx, key, expected)
			if err != nil || !original.MirrorRetained || original.RestoreSupported || original.RestoreReady {
				t.Fatalf("mirror preparation failed: %+v %v", original, err)
			}
			before, err := f.store.Snapshot(ctx)
			if err != nil {
				t.Fatal(err)
			}
			sourceDir := filepath.Join(parent, dormantRuleReclaimPrefix+record.ArchiveSHA256)
			altered := ""
			switch fault {
			case "remove_plan":
				altered = reclaimPlanFileName
			case "remove_completion":
				altered = reclaimCompletionName
			case "remove_intent":
				altered = reclaimIntentPrefix + "000"
			case "late_unknown":
				altered = "untrusted"
				err = os.WriteFile(filepath.Join(sourceDir, altered), []byte("bad"), 0600)
			case "late_selection":
				_, err = f.store.SetCurrentSelectionIntent(ctx,
					[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"different"}`))
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(altered) > 0 && fault != "late_unknown" {
				if err := os.Remove(filepath.Join(sourceDir, altered)); err != nil {
					t.Fatal(err)
				}
			}
			result, err := lease.InspectMirroredReclaimEvidence(ctx, key)
			if err == nil || !reflect.DeepEqual(result, ReclaimEvidenceMirrorReceipt{}) {
				t.Fatalf("mirror silently accepted %s after source changed: %+v %v", fault, result, err)
			}
			if fault == "remove_plan" || fault == "remove_completion" || fault == "remove_intent" {
				if _, err := os.Lstat(filepath.Join(sourceDir, altered)); !os.IsNotExist(err) {
					t.Fatalf("inspection silently repaired missing source %s: %v", altered, err)
				}
			}
			proofFile := filepath.Join(filepath.Dir(f.store.Path()), reclaimMirrorPrefix+record.ArchiveSHA256)
			info, err := os.Lstat(proofFile)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 {
				t.Fatalf("refused read tampered external proof: %v %v", info, err)
			}
			if fault != "late_selection" {
				after, err := f.store.Snapshot(ctx)
				if err != nil || !reflect.DeepEqual(before, after) {
					t.Fatalf("source failure altered live state: %v", err)
				}
			}
		})
	}
}
