package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

const maxCNReportBytes = 128 << 10

var errInvalidCNReport = errors.New("invalid source-only CN audit report")

// This checks a report's pinned shape only; it DOES NOT prove file bytes,
// authorize redistribution, or replace a fresh secure asset-root audit.
func verifyCNAuditReportFile(name string) error {
	f, err := os.Open(name)
	if err != nil {
		return errInvalidCNReport
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxCNReportBytes+1))
	if err != nil {
		return errInvalidCNReport
	}
	return verifyCNAuditReport(data)
}

func verifyCNAuditReport(data []byte) error {
	if len(data) == 0 || len(data) > maxCNReportBytes {
		return errInvalidCNReport
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var doc auditDocument
	if decoder.Decode(&doc) != nil {
		return errInvalidCNReport
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return errInvalidCNReport
	}
	if doc.SchemaVersion != 1 || doc.DistributionReady ||
		doc.LicenseStatus != "blocked_unresolved_upstream_data_licenses" ||
		doc.PresetSource != (auditSource{Repository: preset.CNSourceRepository, Commit: preset.CNSourceCommit, Path: preset.CNSourcePath}) ||
		doc.AssetSource != (auditAssetSource{Repository: preset.CNSourceRepository, Commit: preset.CNSourceCommit, Root: "assets/datas"}) {
		return errInvalidCNReport
	}
	snapshot, err := preset.LoadCN()
	if err != nil {
		return errInvalidCNReport
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil || len(doc.Resources) != len(plan) || doc.Summary.LogicalRefs != len(plan) {
		return errInvalidCNReport
	}
	var total int64
	var files, absent int
	for i, expected := range plan {
		row := doc.Resources[i]
		if row.Ref != expected.Ref || row.RelativePath != expected.RelativePath ||
			row.Format != expected.Format || row.Status != string(expected.Status) ||
			row.Reason != expected.Reason {
			return errInvalidCNReport
		}
		switch expected.Status {
		case preset.CNResourceStatusFile:
			if row.Bytes <= 0 || row.Bytes > 8<<20 || row.Bytes > maxCNTotalBytes-total ||
				len(row.SHA256) != sha256.Size*2 || row.SHA256 != strings.ToLower(row.SHA256) {
				return errInvalidCNReport
			}
			digest, err := hex.DecodeString(row.SHA256)
			if err != nil || len(digest) != sha256.Size {
				return errInvalidCNReport
			}
			total += row.Bytes
			files++
		case preset.CNResourceStatusUpstreamAbsent:
			if row.Bytes != 0 || row.SHA256 != "" {
				return errInvalidCNReport
			}
			absent++
		default:
			return errInvalidCNReport
		}
	}
	if files != preset.CNResourceExpectedFiles || absent != 1 ||
		total <= 0 || total > maxCNTotalBytes ||
		doc.Summary.Files != files || doc.Summary.UpstreamAbsent != absent ||
		doc.Summary.TotalBytes != total {
		return errInvalidCNReport
	}
	return nil
}
