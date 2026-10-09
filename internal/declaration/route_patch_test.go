package declaration

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

func routePatchFixture(t *testing.T) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(minimalDeclaration(), &doc); err != nil { t.Fatal(err) }
	route := doc["routing"].(map[string]any)
	route["custom"] = []any{map[string]any{
		"id": "ordinary", "order": float64(1), "enabled": true,
		"target": map[string]any{"kind":"direct"},
		"match": map[string]any{"op":"atom", "predicate":map[string]any{
			"kind":"domain_suffix", "value":"private.example",
		}},
	}}
	dns := doc["dns"].(map[string]any)
	dns["profiles"] = append(dns["profiles"].([]any), map[string]any{
		"id":"group-dns", "role":"group", "transport":"tcp",
		"server":"192.0.2.8", "port":float64(5533),
		"detour_target": map[string]any{"kind":"current_selected"},
	})
	nodes := doc["nodes"].([]any)
	nodes[0].(map[string]any)["http"] = map[string]any{
		"username": "user", "password": "credential-preserve-me",
	}
	raw, err := json.Marshal(doc)
	if err != nil { t.Fatal(err) }
	if _, err := ParseV1(raw); err != nil { t.Fatal(err) }
	return raw
}

func TestPatchRouteGroupV1SingleFieldAndOtherFieldsPreserved(t *testing.T) {
	source := routePatchFixture(t)
	value := "group-dns"
	edit, err := PatchRouteGroupV1(source, RoutePatch{
		Layer: domain.LayerCustom, GroupID:"ordinary", DNSProfileID: &value,
	})
	if err != nil { t.Fatal(err) }
	if edit.Origin != "custom" || edit.Before.DNSProfileID != "" ||
		edit.After.DNSProfileID != "group-dns" || !edit.After.Enabled {
		t.Fatalf("unexpected binding delta: %+v", edit)
	}
	if !bytes.Contains(edit.Document, []byte("credential-preserve-me")) ||
		!bytes.Contains(edit.Document, []byte("private.example")) {
		t.Fatal("unrelated credential/matcher bytes lost while editing")
	}
	parsed, err := ParseV1(edit.Document)
	if err != nil { t.Fatal(err) }
	if got := parsed.Routing.Custom[0].Binding.DNSProfileID; got != "group-dns" {
		t.Fatalf("group DNS binding = %q", got)
	}
	original, err := ParseV1(source)
	if err != nil { t.Fatal(err) }
	if !reflect.DeepEqual(original.Nodes, parsed.Nodes) ||
		!reflect.DeepEqual(original.Selection, parsed.Selection) ||
		!reflect.DeepEqual(original.DNS, parsed.DNS) {
		t.Fatal("route patch unexpectedly changed unrelated model state")
	}
	if _, err := PatchRouteGroupV1(edit.Document, RoutePatch{
		Layer: domain.LayerCustom, GroupID:"ordinary", DNSProfileID:&value,
	}); !errors.Is(err, ErrRoutePatchNoChange) {
		t.Fatalf("same value was not rejected: %v", err)
	}
	enabled := false
	edit, err = PatchRouteGroupV1(source, RoutePatch{Layer:domain.LayerCustom, GroupID:"ordinary", Enabled:&enabled})
	if err != nil || edit.After.Enabled { t.Fatalf("disable edit: %+v %v", edit, err) }
	target := domain.TargetRef{Kind:domain.TargetCurrentSelected}
	edit, err = PatchRouteGroupV1(source, RoutePatch{Layer:domain.LayerFinal, GroupID:"FINAL",Target:&target})
	if err != nil || edit.After.Target != target { t.Fatalf("FINAL target edit: %+v %v", edit, err) }
}

func TestPatchRouteGroupV1CNUsesOverrideNotPresetMutation(t *testing.T) {
	var doc map[string]any
	if err := json.Unmarshal(minimalDeclaration(), &doc); err != nil { t.Fatal(err) }
	routing := doc["routing"].(map[string]any)
	routing["cn_preset"] = map[string]any{"source_commit":preset.CNSourceCommit}
	raw, err := json.Marshal(doc)
	if err != nil { t.Fatal(err) }
	target := domain.TargetRef{Kind:domain.TargetSpecificNode,ProfileID:"p1",NodeID:"n1"}
	edit, err := PatchRouteGroupV1(raw, RoutePatch{Layer: domain.LayerCustom,
		GroupID:"cn.ad-block", Target:&target})
	if err != nil { t.Fatal(err) }
	if edit.Origin != "cn_preset_override" || edit.After.Target != target {
		t.Fatalf("CN override projection = %+v", edit)
	}
	if !bytes.Contains(edit.Document, []byte("cn.ad-block")) ||
		!bytes.Contains(edit.Document, []byte(preset.CNSourceCommit)) {
		t.Fatal("CN pinned identity or override lost")
	}
	model, err := ParseV1(edit.Document)
	if err != nil { t.Fatal(err) }
	if model.CNPreset == nil || len(model.CNPreset.Overrides) != 1 ||
		!reflect.DeepEqual(*model.CNPreset.Overrides[0].Target, target) {
		t.Fatalf("CN override not persisted: %+v", model.CNPreset)
	}
	effective, err := EffectiveRouting(model)
	if err != nil { t.Fatal(err) }
	if len(effective.Custom) != preset.CNExpectedGroups {
		t.Fatalf("expected %d CN groups, got %d",preset.CNExpectedGroups,len(effective.Custom))
	}
}

func TestPatchRouteGroupV1CannotEditGeneratedOrUnrelatedFields(t *testing.T) {
	source := routePatchFixture(t)
	direct := domain.TargetRef{Kind:domain.TargetDirect}
	dns := "outbound" // outbound-role is NOT group DNS.
	enabled := false
	for name, patch := range map[string]RoutePatch{
		"multiple fields": {Layer:domain.LayerCustom,GroupID:"ordinary",Enabled:&enabled,Target:&direct},
		"unknown group": {Layer:domain.LayerCustom,GroupID:"missing",Enabled:&enabled},
		"wrong layer": {Layer:domain.LayerGeoIP,GroupID:"ordinary",Enabled:&enabled},
		"FINAL DNS": {Layer:domain.LayerFinal,GroupID:"FINAL",DNSProfileID:&dns},
		"non group DNS role": {Layer:domain.LayerCustom,GroupID:"ordinary",DNSProfileID:&dns},
		"unsupported layer": {Layer:"isp",GroupID:"ordinary",Target:&direct},
		"no edit": {Layer:domain.LayerCustom,GroupID:"ordinary"},
	} {
		if _, err := PatchRouteGroupV1(source, patch); err == nil {
			t.Errorf("%s was accepted",name)
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(source,&doc); err != nil { t.Fatal(err) }
	doc["routing"].(map[string]any)["region_append"] = map[string]any{
		"region_code":"cn", "geosite_enabled":true,"geoip_enabled":true,
	}
	raw, err := json.Marshal(doc)
	if err != nil { t.Fatal(err) }
	if _, err := PatchRouteGroupV1(raw, RoutePatch{
		Layer:domain.LayerGeoSite,GroupID:"region:auto-geosite:cn",Target:&direct,
	}); !errors.Is(err,ErrRoutePatchInvalid) {
		t.Fatalf("generated region group was editable: %v",err)
	}
}
