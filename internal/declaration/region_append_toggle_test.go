package declaration

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func regionToggleFixture(t *testing.T, site, ip bool) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(routePatchFixture(t), &doc); err != nil {
		t.Fatal(err)
	}
	doc["routing"].(map[string]any)["region_append"] = map[string]any{
		"region_code": "cn", "geosite_enabled": site, "geoip_enabled": ip,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseV1(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestCNRegionAppendToggleIndependentLayerAndReverse(t *testing.T) {
	for _, tc := range []struct {
		name  string
		layer domain.RoutingLayer
		group string
		site  bool
		ip    bool
		value bool
	}{
		{"disable geosite", domain.LayerGeoSite, "region:auto-geosite:cn", true, true, false},
		{"disable geoip", domain.LayerGeoIP, "region:auto-geoip:cn", true, true, false},
		{"enable geosite", domain.LayerGeoSite, "region:auto-geosite:cn", false, true, true},
		{"enable geoip", domain.LayerGeoIP, "region:auto-geoip:cn", true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := regionToggleFixture(t, tc.site, tc.ip)
			before, err := ParseV1(source)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := PatchRouteGroupV1(source, RoutePatch{
				Layer: tc.layer, GroupID: tc.group, Enabled: &tc.value,
			})
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Origin != "region_append_toggle" ||
				receipt.Before.Target.Kind != domain.TargetDirect ||
				receipt.After.Target.Kind != domain.TargetDirect ||
				receipt.After.Enabled != tc.value ||
				receipt.Before.Enabled == receipt.After.Enabled ||
				receipt.After.DNSProfileID != "" {
				t.Fatalf("unsafe region receipt: %+v", receipt)
			}
			after, err := ParseV1(receipt.Document)
			if err != nil {
				t.Fatal(err)
			}
			expectedSite, expectedIP := tc.site, tc.ip
			if tc.layer == domain.LayerGeoSite {
				expectedSite = tc.value
			} else {
				expectedIP = tc.value
			}
			if after.RegionAppend.GeoSiteEnabled != expectedSite ||
				after.RegionAppend.GeoIPEnabled != expectedIP {
				t.Fatalf("unexpected independent flags: %+v", after.RegionAppend)
			}
			before.RegionAppend, after.RegionAppend = nil, nil
			if !reflect.DeepEqual(before, after) ||
				!bytes.Contains(receipt.Document, []byte("credential-preserve-me")) {
				t.Fatal("region toggle modified unrelated matcher, CN source, node, DNS or credential")
			}
			if _, err := PatchRouteGroupV1(receipt.Document, RoutePatch{
				Layer: tc.layer, GroupID: tc.group, Enabled: &tc.value,
			}); !errors.Is(err, ErrRoutePatchNoChange) {
				t.Fatalf("duplicate region switch unexpectedly accepted: %v", err)
			}
		})
	}
}

func TestCNRegionAppendToggleRejectsTargetsDNSAndForgedIdentities(t *testing.T) {
	source := regionToggleFixture(t, true, true)
	no := false
	direct := domain.TargetRef{Kind: domain.TargetDirect}
	dns := "group-dns"
	for name, patch := range map[string]RoutePatch{
		"target not editable": {Layer: domain.LayerGeoSite, GroupID: "region:auto-geosite:cn", Target: &direct},
		"dns not editable":    {Layer: domain.LayerGeoIP, GroupID: "region:auto-geoip:cn", DNSProfileID: &dns},
		"multiple fields":     {Layer: domain.LayerGeoIP, GroupID: "region:auto-geoip:cn", Target: &direct, Enabled: &no},
		"wrong layer":         {Layer: domain.LayerCustom, GroupID: "region:auto-geosite:cn", Enabled: &no},
		"wrong country":       {Layer: domain.LayerGeoSite, GroupID: "region:auto-geosite:us", Enabled: &no},
		"forged group":        {Layer: domain.LayerGeoSite, GroupID: "region:auto-geosite:cn-extra", Enabled: &no},
		"wrong geo layer":     {Layer: domain.LayerGeoSite, GroupID: "region:auto-geoip:cn", Enabled: &no},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := PatchRouteGroupV1(source, patch); !errors.Is(err, ErrRoutePatchInvalid) {
				t.Fatalf("invalid edit accepted: %v", err)
			}
		})
	}
	without := routePatchFixture(t)
	if _, err := PatchRouteGroupV1(without, RoutePatch{
		Layer: domain.LayerGeoSite, GroupID: "region:auto-geosite:cn", Enabled: &no,
	}); !errors.Is(err, ErrRoutePatchInvalid) {
		t.Fatalf("created implicit region append: %v", err)
	}
}

func TestCNRegionAppendToggleRejectsGeneratedIDCollision(t *testing.T) {
	// A collision in an inactive layer must not become an accidentally
	// authorized edit when the generated flag is later enabled.
	source := regionToggleFixture(t, false, true)
	var doc map[string]any
	if err := json.Unmarshal(source, &doc); err != nil {
		t.Fatal(err)
	}
	route := doc["routing"].(map[string]any)
	route["geosite"] = []any{map[string]any{
		"id": "region:auto-geosite:cn", "order": float64(1), "enabled": true,
		"target": map[string]any{"kind": "direct"},
		"match": map[string]any{"op": "atom", "predicate": map[string]any{
			"kind": "domain_suffix", "value": "fake.example",
		}},
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	value := true
	if _, err := PatchRouteGroupV1(raw, RoutePatch{
		Layer: domain.LayerGeoSite, GroupID: "region:auto-geosite:cn", Enabled: &value,
	}); !errors.Is(err, ErrRoutePatchInvalid) {
		t.Fatalf("generated identity collision accepted: %v", err)
	}
}
