package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

func TestBuildAuditHashesCompletePinnedResourcePlan(t *testing.T) {
	root := t.TempDir()
	snapshot, err := preset.LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	expected := make(map[string]string)
	for _, spec := range plan {
		if spec.Status != preset.CNResourceStatusFile {
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(spec.RelativePath))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		content := []byte("resource:" + spec.Ref)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(content)
		expected[spec.Ref] = hex.EncodeToString(sum[:])
	}

	document, err := buildAudit(root)
	if err != nil {
		t.Fatal(err)
	}
	if document.DistributionReady {
		t.Fatal("audit unexpectedly marked distribution ready")
	}
	if document.LicenseStatus != "blocked_unresolved_upstream_data_licenses" {
		t.Fatalf("license status = %q", document.LicenseStatus)
	}
	if document.Summary.LogicalRefs != preset.CNResourceExpectedLogicalRefs ||
		document.Summary.Files != preset.CNResourceExpectedFiles ||
		document.Summary.UpstreamAbsent != 1 {
		t.Fatalf("unexpected audit summary: %+v", document.Summary)
	}
	for _, resource := range document.Resources {
		if resource.Status != string(preset.CNResourceStatusFile) {
			if resource.Ref != "geoip:bing" || resource.SHA256 != "" || resource.Bytes != 0 {
				t.Fatalf("unexpected absent audit entry: %+v", resource)
			}
			continue
		}
		if resource.SHA256 != expected[resource.Ref] {
			t.Fatalf("digest for %q = %q, want %q", resource.Ref, resource.SHA256, expected[resource.Ref])
		}
		if resource.Bytes == 0 {
			t.Fatalf("resource %q has zero audited bytes", resource.Ref)
		}
	}
}

func TestBuildAuditFailsOnUnexpectedMissingFile(t *testing.T) {
	root := t.TempDir()
	snapshot, err := preset.LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	skipped := false
	for _, spec := range plan {
		if spec.Status != preset.CNResourceStatusFile {
			continue
		}
		if !skipped {
			skipped = true
			continue
		}
		path := filepath.Join(root, filepath.FromSlash(spec.RelativePath))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(spec.Ref), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := buildAudit(root); err == nil {
		t.Fatal("missing expected resource was accepted")
	}
}

func TestBuildAuditRejectsUnexpectedKnownAbsentFile(t *testing.T) {
	root := t.TempDir()
	snapshot, err := preset.LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range plan {
		path := filepath.Join(root, filepath.FromSlash(spec.RelativePath))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(spec.Ref), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := buildAudit(root); err == nil {
		t.Fatal("unexpected geoip:bing file was accepted")
	}
}
