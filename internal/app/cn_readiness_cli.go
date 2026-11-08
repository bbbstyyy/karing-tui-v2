package app

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"slices"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

type cnReadinessClient interface {
	CNReadiness(context.Context) (apiv1.CNResourceReadinessResponse, error)
}

// Only a read-only inspection exists. This is intentionally NOT a command
// that can stage or apply CN groups, grant a resource license, or install a
// rule package. Invalid/untrusted response => zero stdout.
func runCNReadinessCLI(ctx context.Context, api cnReadinessClient, args []string, stdout, stderr io.Writer) int {
	jsonOutput := false
	switch {
	case len(args) == 0:
	case len(args) == 1 && args[0] == "--json":
		jsonOutput = true
	default:
		fmt.Fprintln(stderr, "usage: karing-tui config cn-readiness [--json] (read-only; not CN activation)")
		return 2
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	report, err := api.CNReadiness(bounded)
	if err != nil {
		// Do not echo transport/server errors which could contain URLs or
		// other confidential information.
		fmt.Fprintln(stderr, "CN source readiness unavailable; check daemon status")
		return 1
	}
	if !validPinnedCNReadinessReport(report) {
		fmt.Fprintln(stderr, "CN source readiness response is inconsistent; no claim of CN availability")
		return 1
	}
	if jsonOutput {
		return printJSON(stdout, stderr, report)
	}
	if _, err := fmt.Fprintln(stdout, "CN source inventory: NOT READY FOR APPLY OR REDISTRIBUTION"); err != nil {
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "source: %s @ %s\n", report.SourceRepository, report.SourceCommit)
	_, _ = fmt.Fprintf(stdout, "preset: %d groups / %d default enabled\n", report.TotalGroupCount, report.DefaultEnabledCount)
	_, _ = fmt.Fprintf(stdout, "rule refs: %d logical / %d file candidates\n", report.LogicalResourceRefs, report.FileBackedCandidates)
	_, _ = fmt.Fprintf(stdout, "known missing: %s\n", report.KnownUpstreamAbsent[0])
	_, _ = fmt.Fprintf(stdout, "blockers: %s, %s\n", report.BlockingCodes[0], report.BlockingCodes[1])
	_, _ = fmt.Fprintln(stdout, "groups (pinned source order; not live Core evidence):")
	for _, group := range report.Groups {
		status := "off"
		if group.EnabledByDefault {
			status = "on"
		}
		if _, err := fmt.Fprintf(stdout, "  %02d  %-24s  %s  %-16s  %s\n",
			group.Order, group.ID, status, group.TargetKind, group.Name); err != nil {
			return 1
		}
	}
	return 0
}

// Compare every user-visible field with the embedded immutable preset. This
// prevents an inconsistent or compromised daemon from presenting an
// unsupported CN version as installed, complete or licensed.
func validPinnedCNReadinessReport(r apiv1.CNResourceReadinessResponse) bool {
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

var _ cnReadinessClient = (*client.Client)(nil)
