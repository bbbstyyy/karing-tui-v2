package app

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/cnreadiness"
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

// Preserve this existing CLI validation entry point for its regression tests.
// TUI and CLI now enforce precisely the same immutable CN source proof.
func validPinnedCNReadinessReport(r apiv1.CNResourceReadinessResponse) bool {
	return cnreadiness.ValidPinnedReport(r)
}

var _ cnReadinessClient = (*client.Client)(nil)
