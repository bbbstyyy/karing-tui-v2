//go:build linux

package backupclosure

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetainedProofFootprintScannerHardLimits(t *testing.T) {
	for _, fault := range []string{
		"too_many_directory_entries", "too_many_proof_names",
		"noncanonical_archive_suffix", "hardlinked_proof",
	} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir() // MkdirTemp is current-UID private 0700.
			switch fault {
			case "too_many_directory_entries":
				for i := 0; i <= maxReclaimEvidenceDirectoryEntries; i++ {
					name := filepath.Join(root, fmt.Sprintf("unrelated-%05d", i))
					if err := os.WriteFile(name, []byte("x"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "too_many_proof_names":
				for i := 0; i <= maxReclaimEvidenceProofFiles; i++ {
					name := filepath.Join(root,
						reclaimAttestationPrefix+fmt.Sprintf("%064x", i))
					if err := os.WriteFile(name, []byte("x"), 0400); err != nil {
						t.Fatal(err)
					}
				}
			case "noncanonical_archive_suffix":
				if err := os.WriteFile(filepath.Join(root,
					reclaimMirrorPrefix+strings.Repeat("A", 64)), []byte("x"), 0400); err != nil {
					t.Fatal(err)
				}
			case "hardlinked_proof":
				unrelated := filepath.Join(root, "unrelated-private-file")
				if err := os.WriteFile(unrelated, []byte("x"), 0400); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(unrelated, filepath.Join(root,
					reclaimAttestationPrefix+strings.Repeat("b", 64))); err != nil {
					t.Fatal(err)
				}
			}
			pinned, err := os.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer pinned.Close()
			got, err := scanReclaimEvidenceFootprint(context.Background(), pinned)
			if err == nil || got.proofs != nil {
				t.Fatalf("unsafe or over-limit evidence accepted for %s: %+v %v", fault, got, err)
			}
		})
	}
}
