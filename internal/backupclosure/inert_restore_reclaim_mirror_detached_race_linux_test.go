//go:build linux

package backupclosure

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDetachedMirrorRejectsLateSameByteProofInodeReplacement(t *testing.T) {
	for _, fault := range []string{"mirror_inode", "attestation_inode", "live_selection", "cancel"} {
		t.Run(fault, func(t *testing.T) {
			f, lease, record, key, _, expected := makeMirroredReclaimFixture(t)
			ctx := context.Background()
			if _, err := lease.MirrorSealedReclaimEvidence(ctx, key, expected); err != nil {
				t.Fatal(err)
			}
			scoped, cancel := context.WithCancel(ctx)
			defer cancel()
			receipt, err := lease.inspectDetachedReclaimMirror(scoped, key, func() error {
				switch fault {
				case "mirror_inode", "attestation_inode":
					prefix := reclaimMirrorPrefix
					if fault == "attestation_inode" {
						prefix = reclaimAttestationPrefix
					}
					file := filepath.Join(filepath.Dir(f.store.Path()), prefix+record.ArchiveSHA256)
					raw, err := os.ReadFile(file)
					if err != nil {
						return err
					}
					temp := filepath.Join(filepath.Dir(f.store.Path()), "private-signed-replacement")
					if err := os.WriteFile(temp, raw, 0400); err != nil {
						return err
					}
					return os.Rename(temp, file)
				case "live_selection":
					_, err := f.store.SetCurrentSelectionIntent(ctx,
						[]byte(`{"kind":"specific_node","profile_id":"p","node_id":"late-change"}`))
					return err
				case "cancel":
					cancel()
				}
				return nil
			})
			if err == nil || !reflect.DeepEqual(receipt, DetachedReclaimMirrorAudit{}) {
				t.Fatalf("late %s passed detached double-scan: %+v %v", fault, receipt, err)
			}
			// Signed bytes have not been erased, changed or promoted to a
			// writable/active target by the failed read.
			if fault == "mirror_inode" || fault == "attestation_inode" {
				proof, err := lease.InspectDetachedReclaimMirror(ctx, key)
				if err != nil || !proof.HistoryMACsVerified ||
					proof.SourceScopeVerified || proof.RuleAbsenceVerified ||
					proof.DeletionAuthorized {
					t.Fatalf("fresh independent read failed after safe refusal: %+v %v", proof, err)
				}
			}
		})
	}
}
