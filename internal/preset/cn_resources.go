package preset

import (
	"errors"
	"fmt"
	"strings"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const (
	CNResourceExpectedLogicalRefs = 68
	CNResourceExpectedFiles       = 67

	CNResourceStatusFile           CNResourceStatus = "file"
	CNResourceStatusUpstreamAbsent CNResourceStatus = "upstream_absent"

	CNResourceFormatBinary = "binary"
)

var ErrInvalidCNResourcePlan = errors.New("invalid CN offline resource plan")

type CNResourceStatus string

type CNResourceSpec struct {
	Ref          string
	RelativePath string
	Format       string
	Status       CNResourceStatus
	Reason       string
}

func CNOfflineResourcePlan(snapshot CNSnapshot) ([]CNResourceSpec, error) {
	if snapshot.SourceRepository != CNSourceRepository ||
		snapshot.SourceCommit != CNSourceCommit ||
		snapshot.SourcePath != CNSourcePath {
		return nil, fmt.Errorf("%w: snapshot provenance does not match pinned CN baseline", ErrInvalidCNResourcePlan)
	}

	refs := append([]string(nil), snapshot.RuleSetRefs(false)...)
	regionRefs, err := domain.DefaultCNRegionAppendPlan().RuleSetRefs()
	if err != nil {
		return nil, fmt.Errorf("%w: region refs: %v", ErrInvalidCNResourcePlan, err)
	}
	refs = append(refs, regionRefs...)

	seen := make(map[string]struct{}, len(refs))
	result := make([]CNResourceSpec, 0, len(refs))
	for _, ref := range refs {
		if _, exists := seen[ref]; exists {
			continue
		}
		seen[ref] = struct{}{}

		path, err := cnResourceRelativePath(ref)
		if err != nil {
			return nil, err
		}
		spec := CNResourceSpec{
			Ref:          ref,
			RelativePath: path,
			Format:       CNResourceFormatBinary,
			Status:       CNResourceStatusFile,
		}
		if ref == "geoip:bing" {
			spec.Status = CNResourceStatusUpstreamAbsent
			spec.Reason = "referenced by the pinned CN preset but absent from the pinned Karing built-in asset inventory; the last public preset importer pruned unavailable built-in refs"
		}
		result = append(result, spec)
	}

	if len(result) != CNResourceExpectedLogicalRefs {
		return nil, fmt.Errorf(
			"%w: logical refs = %d, want %d",
			ErrInvalidCNResourcePlan,
			len(result),
			CNResourceExpectedLogicalRefs,
		)
	}
	files := 0
	absent := 0
	for _, spec := range result {
		switch spec.Status {
		case CNResourceStatusFile:
			files++
		case CNResourceStatusUpstreamAbsent:
			absent++
		default:
			return nil, fmt.Errorf("%w: unsupported status %q for %q", ErrInvalidCNResourcePlan, spec.Status, spec.Ref)
		}
	}
	if files != CNResourceExpectedFiles || absent != 1 {
		return nil, fmt.Errorf(
			"%w: files=%d absent=%d, want files=%d absent=1",
			ErrInvalidCNResourcePlan,
			files,
			absent,
			CNResourceExpectedFiles,
		)
	}
	return result, nil
}

func cnResourceRelativePath(ref string) (string, error) {
	kind, value, ok := strings.Cut(ref, ":")
	if !ok || value == "" {
		return "", fmt.Errorf("%w: malformed logical ref %q", ErrInvalidCNResourcePlan, ref)
	}
	switch kind {
	case "geosite":
		return "geosite/" + value + ".srs", nil
	case "geoip":
		return "geoip/" + value + ".srs", nil
	case "acl":
		return "acl/" + value + ".srs", nil
	default:
		return "", fmt.Errorf("%w: unsupported logical ref %q", ErrInvalidCNResourcePlan, ref)
	}
}
