package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
)

func TestConfigInspectionAppliedBindingAndStagedSemanticDrift(t *testing.T) {
	store, document, coreFake, handler := appliedSelectionFixture(t)
	defer store.Close()
	response := selectionAPICall(t, handler, http.MethodGet, "/v1/config/inspection", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("inspection = %d, %s", response.Code, response.Body.String())
	}
	var first apiv1.ConfigInspectionResponse
	if err := json.NewDecoder(response.Body).Decode(&first); err != nil { t.Fatal(err) }
	if first.Evidence != "applied_declaration" || first.GenerationID < 1 ||
		first.ConfigRevision != 1 || first.AppliedDeclarationRevision != 1 ||
		first.CurrentDeclarationRevision != 1 || first.StagedUnapplied ||
		first.RoutingChanged || first.DNSChanged || first.RouteTotal != 1 ||
		len(first.Layers) != 5 || first.Layers[4].Groups[0].Target.Kind != domain.TargetCurrentSelected ||
		first.DNS.ProfileCount != 1 || len(first.DNS.Profiles) != 1 {
		t.Fatalf("unexpected applied projection: %+v", first)
	}
	for _, secret := range []string{"127.0.0.1", "\"nodes\"", "\"server\""} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatalf("raw node/DNS endpoint disclosed: %q", secret)
		}
	}
	current, err := store.CurrentDeclaration(context.Background())
	if err != nil { t.Fatal(err) }
	next := strings.Replace(string(document), "\"final\":{\"kind\":\"current_selected\"}",
		"\"final\":{\"kind\":\"direct\"}", 1)
	next = strings.Replace(next, "\"port\":53", "\"port\":54", 1)
	if next == string(document) { t.Fatal("staged fixture unchanged") }
	if _, err := store.CommitDeclaration(context.Background(), current.Revision, []byte(next), "test:inspection-pending"); err != nil {
		t.Fatal(err)
	}
	response = selectionAPICall(t, handler, http.MethodGet, "/v1/config/inspection", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("staged inspection = %d, %s", response.Code, response.Body.String())
	}
	var second apiv1.ConfigInspectionResponse
	if err := json.NewDecoder(response.Body).Decode(&second); err != nil { t.Fatal(err) }
	if !second.StagedUnapplied || !second.RoutingChanged || !second.DNSChanged ||
		second.AppliedDeclarationRevision != 1 || second.CurrentDeclarationRevision != 2 ||
		second.Layers[4].Groups[0].Target.Kind != domain.TargetCurrentSelected ||
		coreFake.selectCalls != 0 {
		t.Fatalf("unapplied content misrepresented as applied: %+v, calls=%d", second, coreFake.selectCalls)
	}
}

func TestConfigInspectionRefusesNoAppliedGeneration(t *testing.T) {
	store := openServerTestStore(t, context.Background())
	defer store.Close()
	if _, err := store.CommitDeclaration(context.Background(), 0, currentSelectionTestDeclaration(), "test:unapplied"); err != nil { t.Fatal(err) }
	handler := New(runtimepath.Paths{}).handler(store, nil)
	response := selectionAPICall(t, handler, http.MethodGet, "/v1/config/inspection", nil)
	if response.Code != http.StatusConflict || strings.Contains(response.Body.String(), "127.0.0.1") {
		t.Fatalf("unapplied config presented as applied: %d %s", response.Code, response.Body.String())
	}
}

func TestConfigInspectionCNInterleavingRegionAndSecretFreeDNS(t *testing.T) {
	model := declaration.Model{
		Routing: domain.RoutingPlan{Final: domain.TargetRef{Kind: domain.TargetCurrentSelected}},
		CNPreset: &declaration.CNPresetPlan{SourceCommit: preset.CNSourceCommit},
		RegionAppend: &domain.RegionAppendPlan{
			RegionCode: "cn", GeoSiteEnabled: true, GeoIPEnabled: true,
			Target: domain.TargetRef{Kind: domain.TargetDirect},
		},
		DNS: domain.DNSPlan{
			OutboundProfileID: "outbound",
			Profiles: []domain.DNSProfile{
				{ID: "bootstrap", Role: domain.DNSRoleBootstrap, Transport: domain.DNSTransportUDP, Server: "192.0.2.3", Port: 53},
				{ID: "outbound", Role: domain.DNSRoleOutbound, Transport: domain.DNSTransportTCP, Server: "dns-private.example", Port: 5353, BootstrapProfileID: "bootstrap"},
				{ID: "group-dns", Role: domain.DNSRoleGroup, Transport: domain.DNSTransportUDP, Server: "203.0.113.4", Port: 53,
					DetourTarget: domain.TargetRef{Kind: domain.TargetCurrentSelected}},
			},
		},
	}
	effective, err := declaration.EffectiveRouting(model)
	if err != nil { t.Fatal(err) }
	result, err := projectConfigurationInspection(7, 11, 13, 13, model, effective)
	if err != nil { t.Fatal(err) }
	if !result.CNPreset || !result.RegionAppend ||
		result.RouteTotal != preset.CNExpectedGroups+3 ||
		result.Layers[0].GroupCount != preset.CNExpectedGroups ||
		result.Layers[0].Groups[0].Origin != "cn_preset" ||
		result.Layers[1].Groups[0].Origin != "region_append" ||
		result.Layers[2].Groups[0].Origin != "region_append" ||
		result.DNS.ProfileCount != 3 || len(result.DNS.Profiles) != 3 ||
		result.DNS.Profiles[1].UpstreamKind != "hostname (bootstrap required)" ||
		result.DNS.Profiles[2].Detour == nil {
		t.Fatalf("CN/region/DNS provenance incorrect: %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil { t.Fatal(err) }
	for _, sensitive := range []string{"dns-private.example", "192.0.2.3", "203.0.113.4", "\"server\""} {
		if strings.Contains(string(encoded), sensitive) { t.Fatalf("raw DNS endpoint disclosed: %q", sensitive) }
	}
}

func TestConfigInspectionCapsGroupsAndDNSProfiles(t *testing.T) {
	model := declaration.Model{
		Routing: domain.RoutingPlan{Final: domain.TargetRef{Kind: domain.TargetDirect}},
		DNS: domain.DNSPlan{OutboundProfileID: "outbound"},
	}
	for i := 0; i < maxInspectedRouteGroups+10; i++ {
		match := domain.Atom(domain.Predicate{
			Kind: domain.PredicateDomainSuffix, Value: fmt.Sprintf("credential-%d.private.example", i),
		})
		model.Routing.Custom = append(model.Routing.Custom, domain.RouteGroup{
			ID: fmt.Sprintf("g-%d", i), Layer: domain.LayerCustom, Order: uint32(i+1), Match: &match,
			Binding: domain.RouteBinding{Enabled: true, Target: domain.TargetRef{Kind: domain.TargetDirect}},
		})
	}
	for i := 0; i < maxInspectedDNSProfiles+3; i++ {
		role := domain.DNSRoleBootstrap
		name := fmt.Sprintf("resolver-%d", i)
		if i == 0 { role, name = domain.DNSRoleOutbound, "outbound" }
		model.DNS.Profiles = append(model.DNS.Profiles, domain.DNSProfile{
			ID: name, Role: role, Transport: domain.DNSTransportUDP,
			Server: "192.0.2.8", Port: 53,
		})
	}
	result, err := projectConfigurationInspection(2, 8, 4, 4, model, model.Routing)
	if err != nil { t.Fatal(err) }
	if !result.RouteTruncated || result.RouteTotal != maxInspectedRouteGroups+11 ||
		len(result.Layers[0].Groups) != maxInspectedRouteGroups ||
		result.Layers[4].GroupCount != 1 || len(result.Layers[4].Groups) != 1 ||
		!result.DNS.Truncated || result.DNS.ProfileCount != maxInspectedDNSProfiles+3 ||
		len(result.DNS.Profiles) != maxInspectedDNSProfiles {
		t.Fatalf("bounded projection = %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil { t.Fatal(err) }
	if strings.Contains(string(encoded), "credential-") {
		t.Fatal("route matcher values leaked in category-only projection")
	}
}
