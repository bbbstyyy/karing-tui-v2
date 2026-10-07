package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type fakeRouteExplainStore struct {
	snapshot  storage.Snapshot
	artifacts storage.GenerationArtifacts
	err       error
}

func (s *fakeRouteExplainStore) Snapshot(context.Context) (storage.Snapshot, error) {
	if s.err != nil {
		return storage.Snapshot{}, s.err
	}
	snapshot := s.snapshot
	if snapshot.RoutingMode == "" {
		snapshot.RoutingMode = storage.RoutingModeRule
	}
	return snapshot, nil
}

func (s *fakeRouteExplainStore) GenerationArtifacts(context.Context, int64) (storage.GenerationArtifacts, error) {
	if s.err != nil {
		return storage.GenerationArtifacts{}, s.err
	}
	out := s.artifacts
	out.ConfigJSON = append([]byte(nil), out.ConfigJSON...)
	out.ManifestJSON = append([]byte(nil), out.ManifestJSON...)
	out.SourceMapJSON = append([]byte(nil), out.SourceMapJSON...)
	return out, nil
}

func TestRouteExplainSimulatesMappedRuleAndFinal(t *testing.T) {
	id := int64(9)
	rules := []compiler.RouteRule{
		{Inbound: []string{domain.InboundTagDirect}, Action: "route", Outbound: compiler.DirectOutboundTag},
		{Inbound: []string{domain.InboundTagSelected}, Action: "route", Outbound: compiler.CurrentSelectedOutboundTag},
		{
			Type: "logical",
			Mode: "and",
			Rules: []compiler.RouteRule{
				{Inbound: []string{domain.InboundTagRule}},
				{DomainSuffix: []string{"example.com"}},
			},
			Action: "reject",
		},
		{Inbound: []string{domain.InboundTagRule}, Action: "route", Outbound: compiler.DirectOutboundTag},
	}
	sourceMap := []compiler.RouteSourceMapEntry{
		{
			RuleIndex: 2,
			Layer:     domain.LayerCustom,
			GroupID:   "blocked-domain",
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
	store := &fakeRouteExplainStore{
		snapshot:  storage.Snapshot{Revision: 4, AppliedGenerationID: &id},
		artifacts: routeExplainTestArtifacts(t, rules, sourceMap),
	}
	coordinator, err := NewRouteExplainCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}

	blocked, err := coordinator.Explain(context.Background(), apiv1.RouteExplainRequest{
		Entry:   "rule",
		Domain:  "api.example.com",
		Port:    443,
		Network: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Evidence != "simulated" || blocked.Decision != "reject" ||
		blocked.RuleIndex == nil || *blocked.RuleIndex != 2 ||
		blocked.Layer != domain.LayerCustom || blocked.GroupID != "blocked-domain" ||
		blocked.GenerationID != id || blocked.ConfigRevision != 4 ||
		blocked.DeclarationRevision != 7 {
		t.Fatalf("blocked explanation = %+v", blocked)
	}
	if blocked.Target == nil || blocked.Target.Kind != domain.TargetBlock {
		t.Fatalf("blocked target = %+v", blocked.Target)
	}

	final, err := coordinator.Explain(context.Background(), apiv1.RouteExplainRequest{
		Domain:  "other.test",
		Port:    443,
		Network: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if final.Evidence != "simulated" || final.Decision != "route" ||
		final.RuleIndex == nil || *final.RuleIndex != 3 ||
		final.Layer != domain.LayerFinal || !final.Final ||
		final.Target == nil || final.Target.Kind != domain.TargetDirect {
		t.Fatalf("final explanation = %+v", final)
	}
}

func TestRouteExplainDomainSuffixUsesLabelBoundary(t *testing.T) {
	id := int64(13)
	rules := []compiler.RouteRule{
		{Inbound: []string{domain.InboundTagDirect}, Action: "route", Outbound: compiler.DirectOutboundTag},
		{Inbound: []string{domain.InboundTagSelected}, Action: "route", Outbound: compiler.CurrentSelectedOutboundTag},
		{Inbound: []string{domain.InboundTagRule}, ClashMode: "Global", Action: "route", Outbound: compiler.CurrentSelectedOutboundTag},
		{Inbound: []string{domain.InboundTagRule}, ClashMode: "Direct", Action: "route", Outbound: compiler.DirectOutboundTag},
		{
			Type: "logical",
			Mode: "and",
			Rules: []compiler.RouteRule{
				{Inbound: []string{domain.InboundTagRule}},
				{DomainSuffix: []string{"example.com"}},
			},
			Action: "reject",
		},
		{Inbound: []string{domain.InboundTagRule}, Action: "route", Outbound: compiler.DirectOutboundTag},
	}
	sourceMap := []compiler.RouteSourceMapEntry{
		{
			RuleIndex: 4,
			Layer:     domain.LayerCustom,
			GroupID:   "suffix-block",
			Target:    domain.TargetRef{Kind: domain.TargetBlock},
			Action:    "reject",
		},
		{
			RuleIndex: 5,
			Layer:     domain.LayerFinal,
			Final:     true,
			Target:    domain.TargetRef{Kind: domain.TargetDirect},
			Action:    "route",
			Outbound:  compiler.DirectOutboundTag,
		},
	}
	store := &fakeRouteExplainStore{
		snapshot: storage.Snapshot{
			Revision:            7,
			AppliedGenerationID: &id,
			RoutingMode:         storage.RoutingModeRule,
		},
		artifacts: routeExplainTestArtifacts(t, rules, sourceMap),
	}
	coordinator, err := NewRouteExplainCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"example.com", "api.example.com"} {
		response, err := coordinator.Explain(context.Background(), apiv1.RouteExplainRequest{
			Domain:  name,
			Port:    443,
			Network: "tcp",
		})
		if err != nil {
			t.Fatal(err)
		}
		if response.Decision != "reject" || response.RuleIndex == nil || *response.RuleIndex != 4 {
			t.Fatalf("suffix match for %q = %+v", name, response)
		}
	}

	response, err := coordinator.Explain(context.Background(), apiv1.RouteExplainRequest{
		Domain:  "notexample.com",
		Port:    443,
		Network: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Decision != "route" || response.RuleIndex == nil || *response.RuleIndex != 5 ||
		response.Target == nil || response.Target.Kind != domain.TargetDirect {
		t.Fatalf("label-boundary suffix non-match = %+v", response)
	}
}

func TestRouteExplainStopsAtUnknownOpaqueRuleSet(t *testing.T) {
	id := int64(10)
	rules := []compiler.RouteRule{
		{Inbound: []string{domain.InboundTagDirect}, Action: "route", Outbound: compiler.DirectOutboundTag},
		{Inbound: []string{domain.InboundTagSelected}, Action: "route", Outbound: compiler.CurrentSelectedOutboundTag},
		{
			Type: "logical",
			Mode: "and",
			Rules: []compiler.RouteRule{
				{Inbound: []string{domain.InboundTagRule}},
				{RuleSet: []string{"rs-opaque"}},
			},
			Action:   "route",
			Outbound: compiler.DirectOutboundTag,
		},
		{Inbound: []string{domain.InboundTagRule}, Action: "reject"},
	}
	sourceMap := []compiler.RouteSourceMapEntry{
		{
			RuleIndex: 2,
			Layer:     domain.LayerGeoSite,
			GroupID:   "opaque-rules",
			Target:    domain.TargetRef{Kind: domain.TargetDirect},
			Action:    "route",
			Outbound:  compiler.DirectOutboundTag,
		},
		{
			RuleIndex: 3,
			Layer:     domain.LayerFinal,
			Final:     true,
			Target:    domain.TargetRef{Kind: domain.TargetBlock},
			Action:    "reject",
		},
	}
	store := &fakeRouteExplainStore{
		snapshot:  storage.Snapshot{Revision: 5, AppliedGenerationID: &id},
		artifacts: routeExplainTestArtifacts(t, rules, sourceMap),
	}
	coordinator, _ := NewRouteExplainCoordinator(store)
	response, err := coordinator.Explain(context.Background(), apiv1.RouteExplainRequest{
		Domain:  "example.com",
		Network: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Evidence != "unknown" || response.Decision != "unknown" ||
		response.RuleIndex == nil || *response.RuleIndex != 2 ||
		len(response.UnknownConditions) != 1 || response.UnknownConditions[0] != "rule_set:rs-opaque" {
		t.Fatalf("unknown explanation = %+v", response)
	}
	if len(response.Trace) != 3 || response.Trace[2].Result != "unknown" {
		t.Fatalf("unexpected trace = %+v", response.Trace)
	}
}

func TestRouteExplainUsesNativeSyntheticDirectRule(t *testing.T) {
	id := int64(11)
	rules := []compiler.RouteRule{
		{Inbound: []string{domain.InboundTagDirect}, Action: "route", Outbound: compiler.DirectOutboundTag},
		{Inbound: []string{domain.InboundTagSelected}, Action: "route", Outbound: compiler.CurrentSelectedOutboundTag},
		{Inbound: []string{domain.InboundTagRule}, Action: "reject"},
	}
	sourceMap := []compiler.RouteSourceMapEntry{{
		RuleIndex: 2,
		Layer:     domain.LayerFinal,
		Final:     true,
		Target:    domain.TargetRef{Kind: domain.TargetBlock},
		Action:    "reject",
	}}
	store := &fakeRouteExplainStore{
		snapshot:  storage.Snapshot{Revision: 6, AppliedGenerationID: &id},
		artifacts: routeExplainTestArtifacts(t, rules, sourceMap),
	}
	coordinator, _ := NewRouteExplainCoordinator(store)
	response, err := coordinator.Explain(context.Background(), apiv1.RouteExplainRequest{
		Entry:   "direct",
		Domain:  "example.com",
		Port:    80,
		Network: "tcp",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Decision != "route" || response.Source != "synthetic" ||
		response.RuleIndex == nil || *response.RuleIndex != 0 ||
		response.Target == nil || response.Target.Kind != domain.TargetDirect {
		t.Fatalf("direct explanation = %+v", response)
	}
}

func TestRouteExplainRejectsTamperedGenerationMetadata(t *testing.T) {
	id := int64(12)
	artifacts := routeExplainTestArtifacts(t, []compiler.RouteRule{{
		Inbound:  []string{domain.InboundTagRule},
		Action:   "route",
		Outbound: compiler.DirectOutboundTag,
	}}, []compiler.RouteSourceMapEntry{{
		RuleIndex: 0,
		Layer:     domain.LayerFinal,
		Final:     true,
		Target:    domain.TargetRef{Kind: domain.TargetDirect},
		Action:    "route",
		Outbound:  compiler.DirectOutboundTag,
	}})
	artifacts.SourceMapJSON = []byte("[]")
	store := &fakeRouteExplainStore{
		snapshot:  storage.Snapshot{AppliedGenerationID: &id},
		artifacts: artifacts,
	}
	coordinator, _ := NewRouteExplainCoordinator(store)
	if _, err := coordinator.Explain(context.Background(), apiv1.RouteExplainRequest{}); !errors.Is(err, ErrRouteExplainIntegrity) {
		t.Fatalf("tampered source map error = %v", err)
	}
}

func TestRouteExplainRejectsInvalidInput(t *testing.T) {
	coordinator, _ := NewRouteExplainCoordinator(&fakeRouteExplainStore{})
	if _, err := coordinator.Explain(context.Background(), apiv1.RouteExplainRequest{Entry: "tun"}); !errors.Is(err, ErrRouteExplainInput) {
		t.Fatalf("invalid entry error = %v", err)
	}
	if _, err := coordinator.Explain(context.Background(), apiv1.RouteExplainRequest{IP: "not-an-ip"}); !errors.Is(err, ErrRouteExplainInput) {
		t.Fatalf("invalid IP error = %v", err)
	}
}

func routeExplainTestArtifacts(
	t *testing.T,
	rules []compiler.RouteRule,
	sourceMap []compiler.RouteSourceMapEntry,
) storage.GenerationArtifacts {
	t.Helper()
	config, err := json.Marshal(struct {
		Route struct {
			Rules []compiler.RouteRule `json:"rules"`
		} `json:"route"`
	}{
		Route: struct {
			Rules []compiler.RouteRule `json:"rules"`
		}{Rules: rules},
	})
	if err != nil {
		t.Fatal(err)
	}
	configHash := routeExplainTestHash(config)
	manifestJSON, err := json.Marshal(compiler.NativeManifest{
		SchemaID:            compiler.NativeSchemaID,
		ConfigSHA256:        configHash,
		DeclarationRevision: 7,
		DeclarationSHA256:   strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	sourceJSON, err := json.Marshal(sourceMap)
	if err != nil {
		t.Fatal(err)
	}
	return storage.GenerationArtifacts{
		ConfigJSON:      config,
		ConfigSHA256:    configHash,
		ManifestJSON:    manifestJSON,
		ManifestSHA256:  routeExplainTestHash(manifestJSON),
		SourceMapJSON:   sourceJSON,
		SourceMapSHA256: routeExplainTestHash(sourceJSON),
	}
}

func routeExplainTestHash(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func TestRouteExplainAPIUsesAppliedGeneration(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()

	rules := []compiler.RouteRule{
		{Inbound: []string{domain.InboundTagDirect}, Action: "route", Outbound: compiler.DirectOutboundTag},
		{Inbound: []string{domain.InboundTagSelected}, Action: "route", Outbound: compiler.CurrentSelectedOutboundTag},
		{
			Type: "logical",
			Mode: "and",
			Rules: []compiler.RouteRule{
				{Inbound: []string{domain.InboundTagRule}},
				{Domain: []string{"blocked.example"}},
			},
			Action: "reject",
		},
		{Inbound: []string{domain.InboundTagRule}, Action: "route", Outbound: compiler.DirectOutboundTag},
	}
	sourceMap := []compiler.RouteSourceMapEntry{
		{
			RuleIndex: 2,
			Layer:     domain.LayerACL,
			GroupID:   "api-block",
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
	artifacts := routeExplainTestArtifacts(t, rules, sourceMap)
	attempt, err := store.PrepareApplyWithMetadata(
		ctx,
		0,
		artifacts.ConfigJSON,
		artifacts.ManifestJSON,
		artifacts.SourceMapJSON,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginVerification(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitApplied(ctx, attempt.ID, true); err != nil {
		t.Fatal(err)
	}

	handler := New(runtimepath.Paths{}).handler(store, nil)
	body := `{"domain":"blocked.example","port":443,"network":"tcp"}`
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodPost, "/v1/route/explain", strings.NewReader(body)),
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("route explain status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response apiv1.RouteExplainResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Evidence != "simulated" || response.Decision != "reject" ||
		response.GenerationID != attempt.GenerationID ||
		response.ConfigRevision != attempt.TargetRevision ||
		response.GroupID != "api-block" || response.Layer != domain.LayerACL {
		t.Fatalf("route explain API response = %+v", response)
	}

	bad := httptest.NewRecorder()
	handler.ServeHTTP(
		bad,
		httptest.NewRequest(
			http.MethodPost,
			"/v1/route/explain",
			strings.NewReader(`{"domain":"blocked.example","unknown":true}`),
		),
	)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("route explain unknown-field status=%d body=%s", bad.Code, bad.Body.String())
	}
}

func TestRouteExplainHonorsPersistedRoutingMode(t *testing.T) {
	generationID := int64(21)
	rules := []compiler.RouteRule{
		{
			Inbound:   []string{domain.InboundTagRule},
			ClashMode: "Global",
			Action:    "route",
			Outbound:  compiler.CurrentSelectedOutboundTag,
		},
		{
			Inbound:   []string{domain.InboundTagRule},
			ClashMode: "GlobalNoPrivate",
			Action:    "route",
			Outbound:  compiler.CurrentSelectedOutboundTag,
		},
		{
			Inbound:   []string{domain.InboundTagRule},
			ClashMode: "Direct",
			Action:    "route",
			Outbound:  compiler.DirectOutboundTag,
		},
		{
			Inbound: []string{domain.InboundTagRule},
			Action:  "reject",
		},
	}
	sourceMap := []compiler.RouteSourceMapEntry{{
		RuleIndex: 3,
		Layer:     domain.LayerFinal,
		Final:     true,
		Target:    domain.TargetRef{Kind: domain.TargetBlock},
		Action:    "reject",
	}}
	artifacts := routeExplainTestArtifacts(t, rules, sourceMap)

	cases := []struct {
		name          string
		mode          storage.RoutingMode
		privateDirect bool
		decision      string
		ruleIndex     int
		clashMode     string
		target        domain.TargetKind
		source        string
	}{
		{
			name:      "rule",
			mode:      storage.RoutingModeRule,
			decision:  "reject",
			ruleIndex: 3,
			target:    domain.TargetBlock,
			source:    "source_map",
		},
		{
			name:          "global_private",
			mode:          storage.RoutingModeGlobal,
			privateDirect: true,
			decision:      "route",
			ruleIndex:     0,
			clashMode:     "Global",
			target:        domain.TargetCurrentSelected,
			source:        "synthetic",
		},
		{
			name:      "global_no_private",
			mode:      storage.RoutingModeGlobal,
			decision:  "route",
			ruleIndex: 1,
			clashMode: "GlobalNoPrivate",
			target:    domain.TargetCurrentSelected,
			source:    "synthetic",
		},
		{
			name:      "direct",
			mode:      storage.RoutingModeDirect,
			decision:  "route",
			ruleIndex: 2,
			clashMode: "Direct",
			target:    domain.TargetDirect,
			source:    "synthetic",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeRouteExplainStore{
				snapshot: storage.Snapshot{
					Revision:            8,
					AppliedGenerationID: &generationID,
					RoutingMode:         tc.mode,
					PrivateDirect:       tc.privateDirect,
				},
				artifacts: artifacts,
			}
			coordinator, err := NewRouteExplainCoordinator(store)
			if err != nil {
				t.Fatal(err)
			}
			response, err := coordinator.Explain(context.Background(), apiv1.RouteExplainRequest{
				Domain:  "example.test",
				Port:    443,
				Network: "tcp",
			})
			if err != nil {
				t.Fatal(err)
			}
			if response.Evidence != "simulated" ||
				response.Decision != tc.decision ||
				response.RuleIndex == nil || *response.RuleIndex != tc.ruleIndex ||
				response.RoutingMode != string(tc.mode) ||
				response.PrivateDirect != tc.privateDirect ||
				response.Source != tc.source ||
				response.Target == nil || response.Target.Kind != tc.target {
				t.Fatalf("policy %q/%t explanation = %+v", tc.mode, tc.privateDirect, response)
			}
			if response.Trace[tc.ruleIndex].ClashMode != tc.clashMode {
				t.Fatalf("policy %q/%t trace clash_mode = %q, want %q",
					tc.mode, tc.privateDirect, response.Trace[tc.ruleIndex].ClashMode, tc.clashMode)
			}
		})
	}
}

func TestRouteExplainPrivateAddressPredicateMatchesPinnedCoreSemantics(t *testing.T) {
	cases := []struct {
		address string
		private bool
	}{
		{"10.0.0.1", true},
		{"127.0.0.1", true},
		{"169.254.1.1", true},
		{"224.0.0.1", true},
		{"0.0.0.0", true},
		{"8.8.8.8", false},
	}
	for _, tc := range cases {
		address := netip.MustParseAddr(tc.address)
		if got := routeAddressIsPrivate(address); got != tc.private {
			t.Fatalf("routeAddressIsPrivate(%s)=%t, want %t", tc.address, got, tc.private)
		}
	}
}
