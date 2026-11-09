package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

func fixtureCNReport(t *testing.T) auditDocument {
	t.Helper()
	s, err := preset.LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := preset.CNOfflineResourcePlan(s)
	if err != nil {
		t.Fatal(err)
	}
	d := auditDocument{
		SchemaVersion: 1,
		PresetSource:  auditSource{Repository: preset.CNSourceRepository, Commit: preset.CNSourceCommit, Path: preset.CNSourcePath},
		AssetSource:   auditAssetSource{Repository: preset.CNSourceRepository, Commit: preset.CNSourceCommit, Root: "assets/datas"},
		LicenseStatus: "blocked_unresolved_upstream_data_licenses",
		Summary:       auditSummary{LogicalRefs: len(plan)},
	}
	for _, spec := range plan {
		row := auditResource{Ref: spec.Ref, RelativePath: spec.RelativePath, Format: spec.Format, Status: string(spec.Status), Reason: spec.Reason}
		if spec.Status == preset.CNResourceStatusFile {
			sum := sha256.Sum256([]byte(spec.Ref))
			row.SHA256 = hex.EncodeToString(sum[:])
			row.Bytes = int64(len(spec.Ref))
			d.Summary.TotalBytes += row.Bytes
			d.Summary.Files++
		} else {
			d.Summary.UpstreamAbsent++
		}
		d.Resources = append(d.Resources, row)
	}
	return d
}

func TestVerifiedCNReportRemainsBlocked(t *testing.T) {
	d := fixtureCNReport(t)
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyCNAuditReportFile(path); err != nil {
		t.Fatal(err)
	}
	if d.DistributionReady {
		t.Fatal("report pretended to authorize distribution")
	}
}

func TestCNReportVerifierRejectsTampering(t *testing.T) {
	cases := []struct {
		name   string
		poison func(*auditDocument)
	}{
		{"fake license", func(d *auditDocument) { d.LicenseStatus = "approved" }},
		{"fake distribution", func(d *auditDocument) { d.DistributionReady = true }},
		{"wrong commit", func(d *auditDocument) { d.AssetSource.Commit = "other" }},
		{"wrong root", func(d *auditDocument) { d.AssetSource.Root = "other" }},
		{"missing ref", func(d *auditDocument) { d.Resources = d.Resources[:67] }},
		{"wrong order", func(d *auditDocument) { d.Resources[0], d.Resources[1] = d.Resources[1], d.Resources[0] }},
		{"wrong ref", func(d *auditDocument) { d.Resources[0].Ref = "geosite:fake" }},
		{"wrong path", func(d *auditDocument) { d.Resources[0].RelativePath = "../outside" }},
		{"wrong reason", func(d *auditDocument) { d.Resources[0].Reason = "fabricated" }},
		{"bad digest", func(d *auditDocument) { d.Resources[0].SHA256 = strings.Repeat("X", 64) }},
		{"uppercase", func(d *auditDocument) { d.Resources[0].SHA256 = strings.Repeat("A", 64) }},
		{"zero file", func(d *auditDocument) { d.Resources[0].Bytes = 0 }},
		{"oversize file", func(d *auditDocument) { d.Resources[0].Bytes = 8<<20 + 1 }},
		{"forged total", func(d *auditDocument) { d.Summary.TotalBytes++ }},
		{"forged count", func(d *auditDocument) { d.Summary.Files-- }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := fixtureCNReport(t)
			tc.poison(&d)
			raw, err := json.Marshal(d)
			if err != nil {
				t.Fatal(err)
			}
			if verifyCNAuditReport(raw) == nil {
				t.Fatal("forged report accepted")
			}
		})
	}
}

func TestCNReportVerifierRejectsUnboundedTrailingAndUnknown(t *testing.T) {
	d := fixtureCNReport(t)
	raw, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		append(append([]byte(nil), raw...), []byte(" {}")...),
		append(append([]byte(nil), raw...), []byte("garbage")...),
		append(append([]byte(nil), raw[:len(raw)-1]...), []byte(",\"unrecognized\":true}")...),
		[]byte(""), []byte(strings.Repeat(" ", maxCNReportBytes+1)),
	} {
		if verifyCNAuditReport(bad) == nil {
			t.Fatal("invalid audit accepted")
		}
	}
}
