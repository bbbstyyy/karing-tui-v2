package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func persistedRouteExplainFixture() ([]compiler.RouteRule, []compiler.RouteSourceMapEntry) {
	rules := []compiler.RouteRule{
		{Inbound: []string{domain.InboundTagDirect}, Action: "route", Outbound: compiler.DirectOutboundTag},
		{Inbound: []string{domain.InboundTagSelected}, Action: "route", Outbound: compiler.CurrentSelectedOutboundTag},
		{
			Type:   "logical",
			Mode:   "and",
			Rules:  []compiler.RouteRule{
				{Inbound: []string{domain.InboundTagRule}},
				{DomainSuffix: []string{"blocked.invalid"}},
			},
			Action: "reject",
		},
		{Inbound: []string{domain.InboundTagRule}, Action: "route", Outbound: compiler.DirectOutboundTag},
	}
	sourceMap := []compiler.RouteSourceMapEntry{
		{
			RuleIndex: 2,
			Layer:     domain.LayerCustom,
			GroupID:   "blocked",
			Target:    domain.TargetRef{Kind: domain.TargetBlock},
			Action:    "reject",
		},
		{
			RuleIndex: 3,
			Layer:     domain.LayerFinal,
			Final:     true,
			Target:    domain.TargetRef{Kind: domain.TargetDirect},
			Action:    "route",
			Outbound:  compiler.DirectOutboundTag,
		},
	}
	return rules, sourceMap
}

func TestRouteExplainAcceptsConsistentPersistedRouteProvenance(t *testing.T) {
	rules, sourceMap := persistedRouteExplainFixture()
	manifest, nativeRules, mapped, err := decodeRouteExplainGeneration(
		9, routeExplainTestArtifacts(t, rules, sourceMap),
	)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.DeclarationRevision != 7 || len(nativeRules) != 4 || len(mapped) != 2 {
		t.Fatalf("unexpected independently validated provenance: %+v, %d rules, %d sources",
			manifest, len(nativeRules), len(mapped))
	}
}

func TestRouteExplainRejectsRehashedButMisleadingSourceMap(t *testing.T) {
	id := int64(42)
	tests := []struct {
		name   string
		mutate func(*[]compiler.RouteRule, *[]compiler.RouteSourceMapEntry)
	}{
		{"BLOCK relabelled DIRECT", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			(*s)[0].Target = domain.TargetRef{Kind: domain.TargetDirect}
		}},
		{"FINAL target relabelled Selected", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			(*s)[1].Target = domain.TargetRef{Kind: domain.TargetCurrentSelected}
		}},
		{"unknown subscription layer", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			(*s)[0].Layer = "subscription"
		}},
		{"invalid FINAL layer", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			(*s)[1].Layer = domain.LayerACL
		}},
		{"group fraudulently marked FINAL", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			(*s)[0].Final = true
		}},
		{"FINAL no longer identified", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			(*s)[1].Final = false
		}},
		{"FINAL given group identity", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			(*s)[1].GroupID = "fabricated"
		}},
		{"FINAL narrowed to Selected inbound", func(r *[]compiler.RouteRule, _ *[]compiler.RouteSourceMapEntry) {
			(*r)[3].Inbound = []string{domain.InboundTagSelected}
		}},
		{"FINAL quietly filtered to domain", func(r *[]compiler.RouteRule, _ *[]compiler.RouteSourceMapEntry) {
			(*r)[3].Domain = []string{"private.invalid"}
		}},
		{"user matcher changed to Selected", func(r *[]compiler.RouteRule, _ *[]compiler.RouteSourceMapEntry) {
			(*r)[2].Rules[0].Inbound = []string{domain.InboundTagSelected}
		}},
		{"missing user group source", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			*s = (*s)[1:]
		}},
		{"missing FINAL source", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			*s = (*s)[:1]
		}},
		{"reordered source rows", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			(*s)[0], (*s)[1] = (*s)[1], (*s)[0]
		}},
		{"duplicated rule index", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			(*s)[1].RuleIndex = (*s)[0].RuleIndex
		}},
		{"unmapped native user route", func(r *[]compiler.RouteRule, _ *[]compiler.RouteSourceMapEntry) {
			*r = append(*r, compiler.RouteRule{
				Type:   "logical",
				Mode:   "and",
				Rules:  []compiler.RouteRule{
					{Inbound: []string{domain.InboundTagRule}},
					{Domain: []string{"unmapped.invalid"}},
				},
				Action: "reject",
			})
		}},
		{"fake Group DNS attachment to BLOCK", func(_ *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			(*s)[0].DNSProfileID = "unapproved-profile"
		}},
		{"fake DNS resolver with matching route action bytes", func(r *[]compiler.RouteRule, s *[]compiler.RouteSourceMapEntry) {
			(*r)[2].Action = "resolve"
			(*r)[2].Server = "dns-forged"
			(*s)[0].Action = "resolve"
			(*s)[0].Server = "dns-forged"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rules, mapped := persistedRouteExplainFixture()
			tc.mutate(&rules, &mapped)
			// All three artifact hashes are correctly recalculated here.
			// The missing evidence is semantic agreement, not SHA validation.
			artifacts := routeExplainTestArtifacts(t, rules, mapped)
			coordinator, err := NewRouteExplainCoordinator(&fakeRouteExplainStore{
				snapshot:  storage.Snapshot{AppliedGenerationID: &id},
				artifacts: artifacts,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.Explain(context.Background(), apiv1.RouteExplainRequest{
				Domain:  "api.blocked.invalid",
				Network: "tcp",
			}); !errors.Is(err, ErrRouteExplainIntegrity) {
				t.Fatalf("coherently rehashed false provenance was accepted: %v", err)
			}
		})
	}
}
