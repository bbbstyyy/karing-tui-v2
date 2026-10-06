package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

type auditDocument struct {
	SchemaVersion     int              `json:"schema_version"`
	PresetSource      auditSource      `json:"preset_source"`
	AssetSource       auditAssetSource `json:"asset_source"`
	DistributionReady bool             `json:"distribution_ready"`
	LicenseStatus     string           `json:"license_status"`
	Summary           auditSummary     `json:"summary"`
	Resources         []auditResource  `json:"resources"`
}

type auditSource struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Path       string `json:"path"`
}

type auditAssetSource struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Root       string `json:"root"`
}

type auditSummary struct {
	LogicalRefs    int   `json:"logical_refs"`
	Files          int   `json:"files"`
	UpstreamAbsent int   `json:"upstream_absent"`
	TotalBytes     int64 `json:"total_bytes"`
}

type auditResource struct {
	Ref          string `json:"ref"`
	RelativePath string `json:"relative_path"`
	Format       string `json:"format"`
	Status       string `json:"status"`
	Bytes        int64  `json:"bytes,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

func main() {
	var assetRoot string
	var compact bool
	flag.StringVar(&assetRoot, "asset-root", "", "path to the pinned Karing assets/datas directory")
	flag.BoolVar(&compact, "compact", false, "emit compact single-line JSON")
	flag.Parse()

	if assetRoot == "" {
		fmt.Fprintln(os.Stderr, "cn-resource-audit: --asset-root is required")
		os.Exit(2)
	}
	document, err := buildAudit(assetRoot)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cn-resource-audit:", err)
		os.Exit(1)
	}

	var encoded []byte
	if compact {
		encoded, err = json.Marshal(document)
	} else {
		encoded, err = json.MarshalIndent(document, "", "  ")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "cn-resource-audit: encode:", err)
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(append(encoded, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "cn-resource-audit: write:", err)
		os.Exit(1)
	}
}

func buildAudit(assetRoot string) (auditDocument, error) {
	root, err := filepath.Abs(assetRoot)
	if err != nil {
		return auditDocument{}, fmt.Errorf("resolve asset root: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		return auditDocument{}, fmt.Errorf("stat asset root: %w", err)
	}
	if !info.IsDir() {
		return auditDocument{}, errors.New("asset root is not a directory")
	}

	snapshot, err := preset.LoadCN()
	if err != nil {
		return auditDocument{}, err
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil {
		return auditDocument{}, err
	}

	document := auditDocument{
		SchemaVersion:      1,
		PresetSource:       auditSource{
			Repository: preset.CNSourceRepository,
			Commit:     preset.CNSourceCommit,
			Path:       preset.CNSourcePath,
		},
		AssetSource:        auditAssetSource{
			Repository: preset.CNSourceRepository,
			Commit:     preset.CNSourceCommit,
			Root:       "assets/datas",
		},
		DistributionReady: false,
		LicenseStatus:      "blocked_unresolved_upstream_data_licenses",
		Resources:          make([]auditResource, 0, len(plan)),
	}
	for _, spec := range plan {
		entry := auditResource{
			Ref:          spec.Ref,
			RelativePath: spec.RelativePath,
			Format:       spec.Format,
			Status:       string(spec.Status),
			Reason:       spec.Reason,
		}
		fullPath := filepath.Join(root, filepath.FromSlash(spec.RelativePath))
		switch spec.Status {
		case preset.CNResourceStatusUpstreamAbsent:
			if _, err := os.Lstat(fullPath); err == nil {
				return auditDocument{}, fmt.Errorf(
					"known upstream-absent resource %q unexpectedly exists at %s",
					spec.Ref,
					fullPath,
				)
			} else if !errors.Is(err, os.ErrNotExist) {
				return auditDocument{}, fmt.Errorf("inspect absent resource %q: %w", spec.Ref, err)
			}
			document.Summary.UpstreamAbsent++
		case preset.CNResourceStatusFile:
			size, digest, err := hashRegularFile(fullPath)
			if err != nil {
				return auditDocument{}, fmt.Errorf("audit %q: %w", spec.Ref, err)
			}
			entry.Bytes = size
			entry.SHA256 = digest
			document.Summary.Files++
			document.Summary.TotalBytes += size
		default:
			return auditDocument{}, fmt.Errorf("unsupported resource status %q", spec.Status)
		}
		document.Resources = append(document.Resources, entry)
	}
	document.Summary.LogicalRefs = len(document.Resources)
	if document.Summary.Files != preset.CNResourceExpectedFiles ||
		document.Summary.UpstreamAbsent != 1 ||
		document.Summary.LogicalRefs != preset.CNResourceExpectedLogicalRefs {
		return auditDocument{}, fmt.Errorf("unexpected audited closure summary: %+v", document.Summary)
	}
	return document, nil
}

func hashRegularFile(path string) (int64, string, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return 0, "", err
	}
	if !info.Mode().IsRegular() {
		return 0, "", errors.New("resource is not a regular file")
	}
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return 0, "", err
	}
	if size != info.Size() {
		return 0, "", fmt.Errorf("read %d bytes, stat reported %d", size, info.Size())
	}
	return size, hex.EncodeToString(hash.Sum(nil)), nil
}
