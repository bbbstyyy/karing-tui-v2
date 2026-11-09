package cnreadiness

import (
	"reflect"
	"slices"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

// ValidPinnedReport verifies EVERY public field of a CN readiness result
// against our immutable, source-audited Karing CN snapshot. This report is
// source evidence only, NOT proof of installed/licensed resources or live
// routing. Reject forged 'ready' states before showing any daemon text.
func ValidPinnedReport(r apiv1.CNResourceReadinessResponse) bool {
	snapshot, err := preset.LoadCN()
	if err != nil {
		return false
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil {
		return false
	}
	appendPlan, err := domain.DefaultCNRegionAppendPlan().RuleSetRefs()
	if err != nil {
		return false
	}
	if r.Evidence != "pinned_source_inventory_only" ||
		r.SourceRepository != snapshot.SourceRepository ||
		r.SourceCommit != snapshot.SourceCommit ||
		r.SourcePath != snapshot.SourcePath ||
		r.DistributionReady ||
		r.LicenseStatus != "blocked_unresolved_upstream_data_licenses" ||
		!reflect.DeepEqual(r.BlockingCodes, []string{
			"unresolved_upstream_data_licenses", "upstream_resource_absent",
		}) ||
		!reflect.DeepEqual(r.KnownUpstreamAbsent, []string{"geoip:bing"}) ||
		!reflect.DeepEqual(r.RegionAppendRefs, appendPlan) ||
		r.LogicalResourceRefs != len(plan) ||
		r.FileBackedCandidates != preset.CNResourceExpectedFiles ||
		r.TotalGroupCount != preset.CNExpectedGroups ||
		r.DefaultEnabledCount != preset.CNExpectedEnabled ||
		len(r.Groups) != len(snapshot.Groups) {
		return false
	}
	for i, group := range r.Groups {
		source := snapshot.Groups[i]
		if group.ID != source.ID || group.Order != source.Order ||
			group.Name != source.DisplayName ||
			group.EnabledByDefault != source.Enabled ||
			group.TargetKind != string(source.Target.Kind) ||
			!slices.Equal(group.RuleSetRefs, source.Source.RuleSetBuildIn) ||
			group.DomainSuffixCount != len(source.Source.DomainSuffix) ||
			group.DomainKeywordCount != len(source.Source.DomainKeyword) ||
			group.IPCIDRCount != len(source.Source.IPCIDR) ||
			group.ProcessNameCount != len(source.Source.ProcessName) ||
			group.AndroidOnlyPackageCount != len(source.Source.Package) {
			return false
		}
	}
	return true
}
