package tui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

type cnReadinessFakeAPI struct {
	*fakeAPI
	report      apiv1.CNResourceReadinessResponse
	err         error
	calls       int
	hasDeadline bool
}

func (f *cnReadinessFakeAPI) CNReadiness(ctx context.Context) (apiv1.CNResourceReadinessResponse, error) {
	f.calls++
	if d, ok := ctx.Deadline(); ok && time.Until(d) > 0 && time.Until(d) <= 3*time.Second {
		f.hasDeadline = true
	}
	return f.report, f.err
}

func cnReadinessFixture(t *testing.T) apiv1.CNResourceReadinessResponse {
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
	raw := apiv1.CNResourceReadinessResponse{
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
	for _, group := range snapshot.Groups {
		raw.Groups = append(raw.Groups, apiv1.CNPresetReadinessGroup{
			ID: group.ID, Order: group.Order, Name: group.DisplayName,
			EnabledByDefault:        group.Enabled,
			TargetKind:              string(group.Target.Kind),
			RuleSetRefs:             append([]string(nil), group.Source.RuleSetBuildIn...),
			DomainSuffixCount:       len(group.Source.DomainSuffix),
			DomainKeywordCount:      len(group.Source.DomainKeyword),
			IPCIDRCount:             len(group.Source.IPCIDR),
			ProcessNameCount:        len(group.Source.ProcessName),
			AndroidOnlyPackageCount: len(group.Source.Package),
		})
	}
	return raw
}

func cnKey(r rune) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}}
}

func TestCNReadinessTUIShowsAll28PinnedGroupsWithoutWrites(t *testing.T) {
	api := &cnReadinessFakeAPI{fakeAPI: &fakeAPI{}, report: cnReadinessFixture(t)}
	m := NewModel(context.Background(), api)
	m, cmd := updated(t, m, cnKey('0'))
	if cmd == nil || m.page != cnReadinessPage || !m.cnReadiness.active || api.calls != 0 {
		t.Fatal("CN page did not defer one read-only report")
	}
	m, retry := updated(t, m, cnKey('r'))
	if retry != nil {
		t.Fatal("concurrent CN report request must be suppressed")
	}
	m, _ = updated(t, m, cmd())
	if api.calls != 1 || !api.hasDeadline || !m.cnReadiness.ready ||
		m.cnReadiness.failed || len(m.cnReadiness.rows) != preset.CNExpectedGroups+5 {
		t.Fatalf("invalid CN source model: %+v", m.cnReadiness)
	}
	joined := strings.Join(m.cnReadiness.rows, "\n")
	for _, want := range []string{"28 groups / 6 default on", "68 logical refs / 67 file candidates",
		"geoip:bing", "cn.apple-services", "cn.bilibili", "cn.foreign-proxy", "subscription/ISP excluded"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("pinned group inventory missing %q", want)
		}
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 49, Height: 9})
	for i := 0; i < 60; i++ {
		m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyDown})
	}
	view := m.View()
	if !strings.Contains(view, "NOT READY") || !strings.Contains(view, "[0]CN") ||
		!strings.Contains(view, "CN SOURCE ONLY") {
		t.Fatalf("scrolled CN view lost visible blocker warning: %q", view)
	}
	if len(strings.Split(strings.TrimSuffix(view, "\n"), "\n")) > m.height {
		t.Fatal("CN inventory overflows small terminal")
	}
	for _, line := range strings.Split(strings.TrimSuffix(view, "\n"), "\n") {
		if runeWidthOfLine(line) > m.width {
			t.Fatalf("CN inventory overflows viewport: %q", line)
		}
	}
	// Read-only means even write-shaped key combinations never create
	// proposals, activate CN, modify overlays or send an apply RPC.
	for _, key := range []rune{'y', 'e', 'g', 't', 'd', 'f', 'a'} {
		var next tea.Cmd
		m, next = updated(t, m, cnKey(key))
		if next != nil || m.overlayConfirm != nil || m.checkedApply.pending != nil ||
			m.inspection.pending != nil {
			t.Fatalf("write-shaped key %q became active on CN page", key)
		}
	}
	m, cmd = updated(t, m, cnKey('r'))
	if cmd == nil {
		t.Fatal("CN page cannot refresh")
	}
	m, _ = updated(t, m, cmd())
	if api.calls != 2 || !m.cnReadiness.ready {
		t.Fatal("CN read-only refresh not completed")
	}
}

func TestCNReadinessTUIRejectsForgedUnlicensedOrTruncatedReports(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*apiv1.CNResourceReadinessResponse)
	}{
		{"forged ready", func(r *apiv1.CNResourceReadinessResponse) { r.DistributionReady = true }},
		{"fake licensing", func(r *apiv1.CNResourceReadinessResponse) { r.LicenseStatus = "approved" }},
		{"missing Bing blocker", func(r *apiv1.CNResourceReadinessResponse) { r.KnownUpstreamAbsent = nil }},
		{"missing a group", func(r *apiv1.CNResourceReadinessResponse) { r.Groups = r.Groups[:27] }},
		{"reordered groups", func(r *apiv1.CNResourceReadinessResponse) { r.Groups[0], r.Groups[1] = r.Groups[1], r.Groups[0] }},
		{"raw terminal injection", func(r *apiv1.CNResourceReadinessResponse) { r.Groups[0].Name = "token=SECRET\x1b[31m" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := cnReadinessFixture(t)
			tc.edit(&report)
			api := &cnReadinessFakeAPI{fakeAPI: &fakeAPI{}, report: report}
			m := NewModel(context.Background(), api)
			var cmd tea.Cmd
			m, cmd = updated(t, m, cnKey('0'))
			m, _ = updated(t, m, cmd())
			if m.cnReadiness.ready || !m.cnReadiness.failed ||
				len(m.cnReadiness.rows) != 0 || strings.Contains(m.View(), "SECRET") {
				t.Fatalf("unsafe daemon CN report accepted: %+v %q", m.cnReadiness, m.View())
			}
		})
	}
}

func TestCNReadinessTUIStaleReadOrTransportFailureNeverLeaks(t *testing.T) {
	api := &cnReadinessFakeAPI{fakeAPI: &fakeAPI{}, report: cnReadinessFixture(t),
		err: errors.New("private URL: https://example.invalid?token=SECRET")}
	m := NewModel(context.Background(), api)
	m, pending := updated(t, m, cnKey('0'))
	m, _ = updated(t, m, cnKey('1'))
	m, _ = updated(t, m, pending())
	if m.cnReadiness.ready || len(m.cnReadiness.rows) > 0 {
		t.Fatal("stale read after leaving CN page populated model")
	}
	m, cmd := updated(t, m, cnKey('0'))
	m, _ = updated(t, m, cmd())
	if !m.cnReadiness.failed || strings.Contains(m.View(), "SECRET") ||
		strings.Contains(m.View(), "https://") {
		t.Fatalf("unsafe error rendered in CN page: %q", m.View())
	}
}
