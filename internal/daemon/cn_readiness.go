package daemon

import (
	"fmt"
	"net/http"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

// registerCNResourceReadinessRoute reports pinned CN source evidence only.
// It deliberately never claims that assets are installed, legally
// redistributable, or that a live Core route/DNS request has succeeded.
func registerCNResourceReadinessRoute(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/cn/resources/readiness", func(w http.ResponseWriter, _ *http.Request) {
		response, err := pinnedCNResourceReadiness()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, apiv1.ErrorResponse{
				Error: "pinned CN source inventory is unavailable",
			})
			return
		}
		writeJSON(w, http.StatusOK, response)
	})
}

func pinnedCNResourceReadiness() (apiv1.CNResourceReadinessResponse, error) {
	snapshot, err := preset.LoadCN()
	if err != nil {
		return apiv1.CNResourceReadinessResponse{}, err
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil {
		return apiv1.CNResourceReadinessResponse{}, err
	}
	region, err := domain.DefaultCNRegionAppendPlan().RuleSetRefs()
	if err != nil {
		return apiv1.CNResourceReadinessResponse{}, err
	}

	response := apiv1.CNResourceReadinessResponse{
		Evidence:            "pinned_source_inventory_only",
		SourceRepository:    snapshot.SourceRepository,
		SourceCommit:        snapshot.SourceCommit,
		SourcePath:          snapshot.SourcePath,
		DistributionReady:   false,
		LicenseStatus:       "blocked_unresolved_upstream_data_licenses",
		BlockingCodes:       []string{"unresolved_upstream_data_licenses"},
		KnownUpstreamAbsent: make([]string, 0, 1),
		LogicalResourceRefs: len(plan),
		RegionAppendRefs:    append([]string(nil), region...),
		TotalGroupCount:     len(snapshot.Groups),
		Groups:              make([]apiv1.CNPresetReadinessGroup, 0, len(snapshot.Groups)),
	}

	for _, spec := range plan {
		switch spec.Status {
		case preset.CNResourceStatusFile:
			response.FileBackedCandidates++
		case preset.CNResourceStatusUpstreamAbsent:
			response.KnownUpstreamAbsent = append(response.KnownUpstreamAbsent, spec.Ref)
		default:
			return apiv1.CNResourceReadinessResponse{}, fmt.Errorf(
				"unsupported pinned CN resource status for ref %q", spec.Ref,
			)
		}
	}
	if len(response.KnownUpstreamAbsent) != 0 {
		response.BlockingCodes = append(response.BlockingCodes, "upstream_resource_absent")
	}

	for _, group := range snapshot.Groups {
		if group.Enabled {
			response.DefaultEnabledCount++
		}
		response.Groups = append(response.Groups, apiv1.CNPresetReadinessGroup{
			ID:                      group.ID,
			Order:                   group.Order,
			Name:                    group.DisplayName,
			EnabledByDefault:        group.Enabled,
			TargetKind:              string(group.Target.Kind),
			RuleSetRefs:             append([]string{}, group.Source.RuleSetBuildIn...),
			DomainSuffixCount:       len(group.Source.DomainSuffix),
			DomainKeywordCount:      len(group.Source.DomainKeyword),
			IPCIDRCount:             len(group.Source.IPCIDR),
			ProcessNameCount:        len(group.Source.ProcessName),
			AndroidOnlyPackageCount: len(group.Source.Package),
		})
	}
	if response.TotalGroupCount != preset.CNExpectedGroups ||
		response.DefaultEnabledCount != preset.CNExpectedEnabled ||
		response.LogicalResourceRefs != preset.CNResourceExpectedLogicalRefs ||
		response.FileBackedCandidates != preset.CNResourceExpectedFiles ||
		len(response.KnownUpstreamAbsent) != 1 ||
		response.KnownUpstreamAbsent[0] != "geoip:bing" {
		return apiv1.CNResourceReadinessResponse{}, fmt.Errorf("unexpected pinned CN inventory closure")
	}
	return response, nil
}
