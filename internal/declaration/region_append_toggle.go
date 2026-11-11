package declaration

import (
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

// patchCNRegionAppendToggleV1 changes exactly one declared region switch.
// The canonical generated IDs are transport identities ONLY: they do not
// authorize editing generated matchers, DNS, or their mandatory DIRECT target.
func patchCNRegionAppendToggleV1(document []byte, model Model, patch RoutePatch) (RoutePatchResult, error) {
	if model.RegionAppend == nil || model.RegionAppend.RegionCode != "cn" ||
		patch.Enabled == nil || patch.Target != nil || patch.DNSProfileID != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: CN region append permits one enabled switch only", ErrRoutePatchInvalid)
	}
	var field string
	var previous bool
	var originalGroups []domain.RouteGroup
	switch {
	case patch.Layer == domain.LayerGeoSite && patch.GroupID == "region:auto-geosite:cn":
		field, previous, originalGroups = "geosite_enabled", model.RegionAppend.GeoSiteEnabled, model.Routing.GeoSite
	case patch.Layer == domain.LayerGeoIP && patch.GroupID == "region:auto-geoip:cn":
		field, previous, originalGroups = "geoip_enabled", model.RegionAppend.GeoIPEnabled, model.Routing.GeoIP
	default:
		return RoutePatchResult{}, fmt.Errorf("%w: unknown CN region append switch", ErrRoutePatchInvalid)
	}
	// Reject a user group that squats on a generated identity, even when
	// its region switch is currently off and the collision is latent.
	for _, group := range originalGroups {
		if group.ID == patch.GroupID {
			return RoutePatchResult{}, fmt.Errorf("%w: generated group ID collides with user group", ErrRoutePatchInvalid)
		}
	}
	if previous == *patch.Enabled {
		return RoutePatchResult{}, ErrRoutePatchNoChange
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(document, &top); err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: decode original declaration", ErrRoutePatchInvalid)
	}
	var routing map[string]json.RawMessage
	if err := json.Unmarshal(top["routing"], &routing); err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: decode original routing", ErrRoutePatchInvalid)
	}
	var region map[string]json.RawMessage
	if err := json.Unmarshal(routing["region_append"], &region); err != nil || region == nil {
		return RoutePatchResult{}, fmt.Errorf("%w: region append declaration unavailable", ErrRoutePatchInvalid)
	}
	var regionCode string
	if err := json.Unmarshal(region["region_code"], &regionCode); err != nil || regionCode != "cn" {
		return RoutePatchResult{}, fmt.Errorf("%w: region identity changed", ErrRoutePatchInvalid)
	}
	updatedFlag, err := json.Marshal(*patch.Enabled)
	if err != nil {
		return RoutePatchResult{}, ErrRoutePatchInvalid
	}
	region[field] = updatedFlag
	routing["region_append"], err = json.Marshal(region)
	if err != nil {
		return RoutePatchResult{}, ErrRoutePatchInvalid
	}
	top["routing"], err = json.Marshal(routing)
	if err != nil {
		return RoutePatchResult{}, ErrRoutePatchInvalid
	}
	candidate, err := json.Marshal(top)
	if err != nil {
		return RoutePatchResult{}, ErrRoutePatchInvalid
	}
	parsed, err := ParseV1(candidate)
	if err != nil || parsed.RegionAppend == nil || parsed.RegionAppend.RegionCode != "cn" ||
		parsed.RegionAppend.Target.Kind != domain.TargetDirect {
		return RoutePatchResult{}, fmt.Errorf("%w: edited region could not validate", ErrRoutePatchInvalid)
	}
	// Verify the OTHER independent region switch survived and the expected
	// flag was actually changed, including a transition from off to on.
	switch field {
	case "geosite_enabled":
		if parsed.RegionAppend.GeoSiteEnabled != *patch.Enabled ||
			parsed.RegionAppend.GeoIPEnabled != model.RegionAppend.GeoIPEnabled {
			return RoutePatchResult{}, fmt.Errorf("%w: region switch drift", ErrRoutePatchInvalid)
		}
	case "geoip_enabled":
		if parsed.RegionAppend.GeoIPEnabled != *patch.Enabled ||
			parsed.RegionAppend.GeoSiteEnabled != model.RegionAppend.GeoSiteEnabled {
			return RoutePatchResult{}, fmt.Errorf("%w: region switch drift", ErrRoutePatchInvalid)
		}
	}
	// This edit cannot rewrite any CN source, user routing, DNS, node, rule
	// resource, selector or credential; only the typed region plan changes.
	originalModel, updatedModel := model, parsed
	originalModel.RegionAppend, updatedModel.RegionAppend = nil, nil
	if !reflect.DeepEqual(originalModel, updatedModel) {
		return RoutePatchResult{}, fmt.Errorf("%w: unrelated declaration changed", ErrRoutePatchInvalid)
	}
	effective, err := EffectiveRouting(parsed)
	if err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: region routing failed", ErrRoutePatchInvalid)
	}
	var actual []domain.RouteGroup
	if patch.Layer == domain.LayerGeoSite {
		actual = effective.GeoSite
	} else {
		actual = effective.GeoIP
	}
	found := false
	for _, group := range actual {
		if group.ID == patch.GroupID {
			if found || !*patch.Enabled || !group.Binding.Enabled ||
				group.Binding.Target.Kind != domain.TargetDirect ||
				group.Binding.DNSProfileID != "" {
				return RoutePatchResult{}, fmt.Errorf("%w: generated region group changed semantics", ErrRoutePatchInvalid)
			}
			found = true
		}
	}
	if found != *patch.Enabled {
		return RoutePatchResult{}, fmt.Errorf("%w: region enable switch not reflected in effective routing", ErrRoutePatchInvalid)
	}
	target := domain.TargetRef{Kind: domain.TargetDirect}
	return RoutePatchResult{
		Document: candidate,
		Origin:   "region_append_toggle",
		Before:   domain.RouteBinding{Enabled: previous, Target: target},
		After:    domain.RouteBinding{Enabled: *patch.Enabled, Target: target},
	}, nil
}
