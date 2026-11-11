package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

type fakeCNReadinessClient struct {
	report apiv1.CNResourceReadinessResponse
	err    error
	calls  int
}

func (c *fakeCNReadinessClient) CNReadiness(ctx context.Context) (apiv1.CNResourceReadinessResponse, error) {
	c.calls++
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 4*time.Second {
		return apiv1.CNResourceReadinessResponse{}, errors.New("CN report call has no bounded deadline")
	}
	return c.report, c.err
}

func pinnedCNCLIReport(t *testing.T) apiv1.CNResourceReadinessResponse {
	t.Helper()
	snapshot, err := preset.LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := preset.CNOfflineResourcePlan(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	region, err := domain.DefaultCNRegionAppendPlan().RuleSetRefs()
	if err != nil {
		t.Fatal(err)
	}
	report := apiv1.CNResourceReadinessResponse{
		Evidence:             "pinned_source_inventory_only",
		SourceRepository:     snapshot.SourceRepository,
		SourceCommit:         snapshot.SourceCommit,
		SourcePath:           snapshot.SourcePath,
		DistributionReady:    false,
		LicenseStatus:        "blocked_unresolved_upstream_data_licenses",
		BlockingCodes:        []string{"unresolved_upstream_data_licenses", "upstream_resource_absent"},
		KnownUpstreamAbsent:  []string{"geoip:bing"},
		LogicalResourceRefs:  len(plan),
		FileBackedCandidates: preset.CNResourceExpectedFiles,
		TotalGroupCount:      preset.CNExpectedGroups,
		DefaultEnabledCount:  preset.CNExpectedEnabled,
		RegionAppendRefs:     region,
	}
	for _, source := range snapshot.Groups {
		report.Groups = append(report.Groups, apiv1.CNPresetReadinessGroup{
			ID:                      source.ID,
			Order:                   source.Order,
			Name:                    source.DisplayName,
			EnabledByDefault:        source.Enabled,
			TargetKind:              string(source.Target.Kind),
			RuleSetRefs:             append([]string{}, source.Source.RuleSetBuildIn...),
			DomainSuffixCount:       len(source.Source.DomainSuffix),
			DomainKeywordCount:      len(source.Source.DomainKeyword),
			IPCIDRCount:             len(source.Source.IPCIDR),
			ProcessNameCount:        len(source.Source.ProcessName),
			AndroidOnlyPackageCount: len(source.Source.Package),
		})
	}
	return report
}

func TestCNReadinessCLIPrintsEveryPinnedGroupAndExplicitBlockers(t *testing.T) {
	api := &fakeCNReadinessClient{report: pinnedCNCLIReport(t)}
	var stdout, stderr bytes.Buffer
	code := runCNReadinessCLI(context.Background(), api, nil, &stdout, &stderr)
	if code != 0 || api.calls != 1 || stderr.Len() != 0 {
		t.Fatalf("read-only CLI failed: code=%d stderr=%q", code, stderr.String())
	}
	got := stdout.String()
	for _, want := range []string{
		"NOT READY FOR APPLY OR REDISTRIBUTION",
		"28 groups / 6 default enabled",
		"68 logical / 67 file candidates",
		"geoip:bing",
		"unresolved_upstream_data_licenses",
		"cn.apple-services",
		"cn.google",
		"cn.bilibili",
		"cn.domestic-direct",
		"cn.foreign-proxy",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing required human evidence %q", want)
		}
	}
	if strings.Contains(got, "READY FOR APPLY\n") ||
		strings.Contains(got, "CN routing enabled") {
		t.Fatal("source-only inspection falsely advertised runnable CN routing")
	}
	if count := strings.Count(got, "\n  "); count != preset.CNExpectedGroups {
		t.Fatalf("expected full 28-group listing, got %d", count)
	}
}

func TestCNReadinessCLIJSONExplicitlyRefusesDistribution(t *testing.T) {
	api := &fakeCNReadinessClient{report: pinnedCNCLIReport(t)}
	var stdout, stderr bytes.Buffer
	if code := runCNReadinessCLI(context.Background(), api, []string{"--json"}, &stdout, &stderr); code != 0 ||
		!strings.Contains(stdout.String(), `"distribution_ready": false`) ||
		!strings.Contains(stdout.String(), `"evidence": "pinned_source_inventory_only"`) ||
		!strings.Contains(stdout.String(), `"known_upstream_absent"`) {
		t.Fatalf("machine-readable report rejected or overstated: %s %s", stdout.String(), stderr.String())
	}
}

func TestCNReadinessCLIRefusesMutatingOrUnknownArgumentsWithoutRPC(t *testing.T) {
	api := &fakeCNReadinessClient{report: pinnedCNCLIReport(t)}
	for _, args := range [][]string{
		{"--confirm"}, {"--apply"}, {"--enable"}, {"--install"}, {"--force"},
		{"--asset-root=/tmp"}, {"--json", "--confirm"}, {"enable", "cn.bing"},
	} {
		var stdout, stderr bytes.Buffer
		if code := runCNReadinessCLI(context.Background(), api, args, &stdout, &stderr); code != 2 ||
			stdout.Len() != 0 || !strings.Contains(stderr.String(), "read-only") {
			t.Fatalf("unsafe arguments %v accepted: stdout=%q stderr=%q", args, stdout.String(), stderr.String())
		}
	}
	if api.calls != 0 {
		t.Fatal("unsafe arguments issued an API request")
	}
}

func TestCNReadinessCLIRejectsForgedReadyPartialOrAlteredInventory(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*apiv1.CNResourceReadinessResponse)
	}{
		{"forged distribution ready", func(r *apiv1.CNResourceReadinessResponse) {
			r.DistributionReady = true
		}},
		{"forged license ready", func(r *apiv1.CNResourceReadinessResponse) {
			r.LicenseStatus = "approved"
		}},
		{"missing Bing", func(r *apiv1.CNResourceReadinessResponse) {
			r.KnownUpstreamAbsent = nil
		}},
		{"wrong source commit", func(r *apiv1.CNResourceReadinessResponse) {
			r.SourceCommit = "untrusted"
		}},
		{"truncated groups", func(r *apiv1.CNResourceReadinessResponse) {
			r.Groups = r.Groups[:27]
		}},
		{"reordered groups", func(r *apiv1.CNResourceReadinessResponse) {
			r.Groups[2], r.Groups[1] = r.Groups[1], r.Groups[2]
		}},
		{"hidden group matcher", func(r *apiv1.CNResourceReadinessResponse) {
			r.Groups[4].RuleSetRefs = nil
		}},
		{"fake enablement", func(r *apiv1.CNResourceReadinessResponse) {
			r.Groups[0].EnabledByDefault = true
		}},
		{"wrong Android exclusion", func(r *apiv1.CNResourceReadinessResponse) {
			r.Groups[7].AndroidOnlyPackageCount = 0
		}},
		{"unknown release blocker", func(r *apiv1.CNResourceReadinessResponse) {
			r.BlockingCodes = []string{"all_good"}
		}},
		{"fake live evidence", func(r *apiv1.CNResourceReadinessResponse) {
			r.Evidence = "core_running_cn"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeCNReadinessClient{report: pinnedCNCLIReport(t)}
			tc.mutate(&fake.report)
			var stdout, stderr bytes.Buffer
			if code := runCNReadinessCLI(context.Background(), fake, []string{"--json"}, &stdout, &stderr); code != 1 ||
				stdout.Len() != 0 || fake.calls != 1 ||
				!strings.Contains(stderr.String(), "inconsistent") {
				t.Fatalf("forged CN readiness accepted: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestCNReadinessCLIUnavailableNeverEchoesSensitivePath(t *testing.T) {
	api := &fakeCNReadinessClient{
		report: pinnedCNCLIReport(t),
		err:    errors.New("URL https://SECRET.invalid?token=TOPSECRET and /home/user/private"),
	}
	var stdout, stderr bytes.Buffer
	if code := runCNReadinessCLI(context.Background(), api, nil, &stdout, &stderr); code != 1 ||
		stdout.Len() != 0 || strings.Contains(stderr.String(), "TOPSECRET") ||
		strings.Contains(stderr.String(), "/home/user/private") {
		t.Fatalf("CN readiness leaked transport secret: output=%q error=%q", stdout.String(), stderr.String())
	}
}
