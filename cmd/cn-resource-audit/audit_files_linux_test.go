//go:build linux

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
	"golang.org/x/sys/unix"
)

func completeCNTestAssets(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	snapshot, err := preset.LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	first := ""
	for _, spec := range plan {
		family := filepath.Join(root, filepath.Dir(spec.RelativePath))
		if err := os.MkdirAll(family, 0o700); err != nil {
			t.Fatal(err)
		}
		if spec.Status != preset.CNResourceStatusFile {
			continue
		}
		name := filepath.Join(root, spec.RelativePath)
		if first == "" {
			first = name
		}
		if err := os.WriteFile(name, []byte("safe-"+spec.Ref), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if first == "" {
		t.Fatal("resource plan had no file")
	}
	return root, first
}

func TestCNBoundedAuditStillReportsCompleteKnownBlockingClosure(t *testing.T) {
	root, _ := completeCNTestAssets(t)
	got, err := buildAudit(root)
	if err != nil {
		t.Fatal(err)
	}
	if got.DistributionReady ||
		got.LicenseStatus != "blocked_unresolved_upstream_data_licenses" ||
		got.Summary.LogicalRefs != preset.CNResourceExpectedLogicalRefs ||
		got.Summary.Files != preset.CNResourceExpectedFiles ||
		got.Summary.UpstreamAbsent != 1 || got.Summary.TotalBytes <= 0 ||
		got.Summary.TotalBytes > maxCNTotalBytes {
		t.Fatalf("bounded audit mistakenly claimed distributable data: %+v", got)
	}
}

func TestCNAuditRejectsUnsafeResources(t *testing.T) {
	cases := []struct {
		name   string
		poison func(t *testing.T, root, first string)
	}{
		{"file-symlink", func(t *testing.T, root, first string) {
			t.Helper()
			original, err := os.ReadFile(first)
			if err != nil {
				t.Fatal(err)
			}
			external := filepath.Join(t.TempDir(), "external.srs")
			if err := os.WriteFile(external, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(first); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(external, first); err != nil {
				t.Fatal(err)
			}
		}},
		{"directory-symlink", func(t *testing.T, root, first string) {
			t.Helper()
			family := filepath.Dir(first)
			if err := os.Rename(family, family+"-renamed"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(family)+"-renamed", family); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlinked-file", func(t *testing.T, root, first string) {
			t.Helper()
			target := filepath.Join(t.TempDir(), "external.srs")
			if err := os.WriteFile(target, []byte("foreign-content"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(first); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(target, first); err != nil {
				t.Fatal(err)
			}
		}},
		{"empty-asset", func(t *testing.T, root, first string) {
			t.Helper()
			if err := os.Truncate(first, 0); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized-asset", func(t *testing.T, root, first string) {
			t.Helper()
			if err := os.Truncate(first, maxCNAssetBytes+1); err != nil {
				t.Fatal(err)
			}
		}},
		{"fifo-must-not-hang", func(t *testing.T, root, first string) {
			t.Helper()
			if err := os.Remove(first); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(first, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, first := completeCNTestAssets(t)
			tc.poison(t, root, first)
			if _, err := buildAudit(root); err == nil {
				t.Fatal("unsafe source resource passed a license-blocked audit")
			}
		})
	}
}

func TestCNAssetPathAndRootSymlinkRefusals(t *testing.T) {
	for _, path := range []string{
		"/etc/passwd", "../acl/BanAD.srs", "acl/../bad.srs",
		"acl/nested/child.srs", "other/x.srs", "acl/x",
		"acl\\x.srs", "acl/..", "acl/\x00x.srs",
	} {
		if _, _, err := cnAssetRelativePath(path); err == nil {
			t.Fatalf("unsafe resource path %q was allowed", path)
		}
	}
	root, _ := completeCNTestAssets(t)
	alias := filepath.Join(t.TempDir(), "assets")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := buildAudit(alias); err == nil {
		t.Fatal("symlink asset root was followed")
	}
}

func TestCNAssetAuditRefusesTotalByteBudget(t *testing.T) {
	root, _ := completeCNTestAssets(t)
	snapshot, err := preset.LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range plan {
		if spec.Status == preset.CNResourceStatusFile {
			// Sparse truncation keeps disk/memory small; the auditor still
			// has to read and hash every bounded input before refusing.
			if err := os.Truncate(filepath.Join(root, spec.RelativePath), 1<<20); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := buildAudit(root); err == nil ||
		!strings.Contains(err.Error(), "aggregate byte budget exceeded") {
		t.Fatalf("unbounded total closure was accepted: %v", err)
	}
}
