package declaration

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

var (
	ErrRoutePatchInvalid  = errors.New("invalid route or DNS binding edit")
	ErrRoutePatchNoChange = errors.New("route edit has no effective change")
)

// RoutePatch changes exactly ONE binding field of an existing routing group.
// It cannot alter match expressions, the CN-28 snapshot, order, layer switches,
// region auto-append, full DNS resolvers, subscriptions or the core config.
type RoutePatch struct {
	Layer        domain.RoutingLayer
	GroupID      string
	Enabled      *bool
	Target       *domain.TargetRef
	DNSProfileID *string
}

type RoutePatchResult struct {
	Document []byte
	Origin   string
	Before   domain.RouteBinding
	After    domain.RouteBinding
}

func PatchRouteGroupV1(document []byte, patch RoutePatch) (RoutePatchResult, error) {
	fields := 0
	if patch.Enabled != nil {
		fields++
	}
	if patch.Target != nil {
		fields++
		if err := patch.Target.Validate(); err != nil {
			return RoutePatchResult{}, fmt.Errorf("%w: target: %v", ErrRoutePatchInvalid, err)
		}
	}
	if patch.DNSProfileID != nil {
		fields++
	}
	if fields != 1 || patch.GroupID == "" {
		return RoutePatchResult{}, fmt.Errorf("%w: exactly one edit field and group ID required", ErrRoutePatchInvalid)
	}
	switch patch.Layer {
	case domain.LayerCustom, domain.LayerGeoSite, domain.LayerGeoIP, domain.LayerACL, domain.LayerFinal:
	default:
		return RoutePatchResult{}, fmt.Errorf("%w: unsupported routing layer", ErrRoutePatchInvalid)
	}
	model, err := ParseV1(document)
	if err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: invalid base declaration", ErrRoutePatchInvalid)
	}
	effective, err := EffectiveRouting(model)
	if err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: unresolved base routing", ErrRoutePatchInvalid)
	}
	var old domain.RouteGroup
	if patch.Layer == domain.LayerFinal {
		if patch.GroupID != "FINAL" || patch.Target == nil {
			return RoutePatchResult{}, fmt.Errorf("%w: FINAL supports only target editing", ErrRoutePatchInvalid)
		}
		old = domain.RouteGroup{
			ID: "FINAL", Layer: domain.LayerFinal,
			Binding: domain.RouteBinding{Enabled: true, Target: effective.Final},
		}
	} else {
		groups := map[domain.RoutingLayer][]domain.RouteGroup{
			domain.LayerCustom: effective.Custom, domain.LayerGeoSite: effective.GeoSite,
			domain.LayerGeoIP: effective.GeoIP, domain.LayerACL: effective.ACL,
		}[patch.Layer]
		found := false
		for _, group := range groups {
			if group.ID == patch.GroupID {
				old, found = group, true
				break
			}
		}
		if !found {
			return RoutePatchResult{}, fmt.Errorf("%w: group does not exist in specified layer", ErrRoutePatchInvalid)
		}
	}
	if patch.Layer != domain.LayerFinal && model.RegionAppend != nil && ((patch.Layer == domain.LayerGeoSite && patch.GroupID == "region:auto-geosite:"+model.RegionAppend.RegionCode) ||
		(patch.Layer == domain.LayerGeoIP && patch.GroupID == "region:auto-geoip:"+model.RegionAppend.RegionCode)) {
		return RoutePatchResult{}, fmt.Errorf("%w: generated region groups are not directly editable", ErrRoutePatchInvalid)
	}
	before := old.Binding
	after := before
	if patch.Enabled != nil {
		after.Enabled = *patch.Enabled
	}
	if patch.Target != nil {
		after.Target = *patch.Target
	}
	if patch.DNSProfileID != nil {
		after.DNSProfileID = *patch.DNSProfileID
		if *patch.DNSProfileID != "" {
			profile, ok := model.DNS.Profile(*patch.DNSProfileID)
			if !ok || profile.Role != domain.DNSRoleGroup {
				return RoutePatchResult{}, fmt.Errorf("%w: DNS binding must reference an existing group-role resolver", ErrRoutePatchInvalid)
			}
		}
	}
	if err := after.Validate(); err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: invalid edited binding", ErrRoutePatchInvalid)
	}
	if reflect.DeepEqual(before, after) {
		return RoutePatchResult{}, ErrRoutePatchNoChange
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(document, &top); err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: decode declaration", ErrRoutePatchInvalid)
	}
	var routing map[string]json.RawMessage
	if err := json.Unmarshal(top["routing"], &routing); err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: decode routing", ErrRoutePatchInvalid)
	}
	origin := "custom"
	switch patch.Layer {
	case domain.LayerFinal:
		if err := assignRoutePatchField(routing, "final", patch); err != nil {
			return RoutePatchResult{}, err
		}
		origin = "declaration"
	default:
		isCN := false
		if model.CNPreset != nil && patch.Layer == domain.LayerCustom {
			snapshot, err := preset.LoadCN()
			if err != nil {
				return RoutePatchResult{}, fmt.Errorf("%w: missing pinned CN snapshot", ErrRoutePatchInvalid)
			}
			for _, group := range snapshot.Groups {
				if group.ID == patch.GroupID {
					isCN = true
					break
				}
			}
		}
		if isCN {
			origin = "cn_preset_override"
			if err := patchCNOverride(routing, patch); err != nil {
				return RoutePatchResult{}, err
			}
		} else {
			if err := patchOrdinaryRoute(routing, patch); err != nil {
				return RoutePatchResult{}, err
			}
		}
	}
	updatedRouting, err := json.Marshal(routing)
	if err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: encode routing", ErrRoutePatchInvalid)
	}
	top["routing"] = updatedRouting
	candidate, err := json.Marshal(top)
	if err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: encode candidate", ErrRoutePatchInvalid)
	}
	// Ensure the exact compiler declaration schema and the effective target
	// semantics still agree with the operator's one-field patch.
	parsed, err := ParseV1(candidate)
	if err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: edited declaration does not validate", ErrRoutePatchInvalid)
	}
	newRouting, err := EffectiveRouting(parsed)
	if err != nil {
		return RoutePatchResult{}, fmt.Errorf("%w: edited route cannot lower", ErrRoutePatchInvalid)
	}
	var found domain.RouteBinding
	if patch.Layer == domain.LayerFinal {
		found = domain.RouteBinding{Enabled: true, Target: newRouting.Final}
	} else {
		var groups []domain.RouteGroup
		switch patch.Layer {
		case domain.LayerCustom:
			groups = newRouting.Custom
		case domain.LayerGeoSite:
			groups = newRouting.GeoSite
		case domain.LayerGeoIP:
			groups = newRouting.GeoIP
		case domain.LayerACL:
			groups = newRouting.ACL
		}
		ok := false
		for _, group := range groups {
			if group.ID == patch.GroupID {
				found, ok = group.Binding, true
				break
			}
		}
		if !ok {
			return RoutePatchResult{}, fmt.Errorf("%w: edited group disappeared", ErrRoutePatchInvalid)
		}
	}
	if !reflect.DeepEqual(found, after) {
		return RoutePatchResult{}, fmt.Errorf("%w: edited binding mismatch", ErrRoutePatchInvalid)
	}
	return RoutePatchResult{Document: candidate, Origin: origin, Before: before, After: after}, nil
}

func patchOrdinaryRoute(routing map[string]json.RawMessage, patch RoutePatch) error {
	field := string(patch.Layer)
	var rows []json.RawMessage
	if err := json.Unmarshal(routing[field], &rows); err != nil {
		return fmt.Errorf("%w: decode route groups", ErrRoutePatchInvalid)
	}
	found := false
	for i, raw := range rows {
		var entry map[string]json.RawMessage
		if err := json.Unmarshal(raw, &entry); err != nil {
			return fmt.Errorf("%w: decode group", ErrRoutePatchInvalid)
		}
		var id string
		if err := json.Unmarshal(entry["id"], &id); err != nil {
			return fmt.Errorf("%w: decode group ID", ErrRoutePatchInvalid)
		}
		if id != patch.GroupID {
			continue
		}
		if found {
			return fmt.Errorf("%w: duplicate group ID", ErrRoutePatchInvalid)
		}
		found = true
		if err := assignRoutePatchField(entry, "", patch); err != nil {
			return err
		}
		encoded, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("%w: encode group", ErrRoutePatchInvalid)
		}
		rows[i] = encoded
	}
	if !found {
		return fmt.Errorf("%w: group absent from declared layer", ErrRoutePatchInvalid)
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		return fmt.Errorf("%w: encode layer", ErrRoutePatchInvalid)
	}
	routing[field] = encoded
	return nil
}

func patchCNOverride(routing map[string]json.RawMessage, patch RoutePatch) error {
	var cn map[string]json.RawMessage
	if err := json.Unmarshal(routing["cn_preset"], &cn); err != nil {
		return fmt.Errorf("%w: CN override document unavailable", ErrRoutePatchInvalid)
	}
	var overrides []json.RawMessage
	if len(cn["overrides"]) != 0 {
		if err := json.Unmarshal(cn["overrides"], &overrides); err != nil {
			return fmt.Errorf("%w: decode CN overrides", ErrRoutePatchInvalid)
		}
	}
	index := -1
	var item map[string]json.RawMessage
	for i, raw := range overrides {
		var value map[string]json.RawMessage
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("%w: decode CN override", ErrRoutePatchInvalid)
		}
		var id string
		if err := json.Unmarshal(value["group_id"], &id); err != nil {
			return fmt.Errorf("%w: decode CN override ID", ErrRoutePatchInvalid)
		}
		if id == patch.GroupID {
			if index >= 0 {
				return fmt.Errorf("%w: duplicate CN override", ErrRoutePatchInvalid)
			}
			index, item = i, value
		}
	}
	if index < 0 {
		item = make(map[string]json.RawMessage)
		item["group_id"], _ = json.Marshal(patch.GroupID)
	}
	if err := assignRoutePatchField(item, "", patch); err != nil {
		return err
	}
	encoded, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("%w: encode CN override", ErrRoutePatchInvalid)
	}
	if index >= 0 {
		overrides[index] = encoded
	} else {
		overrides = append(overrides, encoded)
	}
	cn["overrides"], err = json.Marshal(overrides)
	if err != nil {
		return fmt.Errorf("%w: encode CN overrides", ErrRoutePatchInvalid)
	}
	routing["cn_preset"], err = json.Marshal(cn)
	if err != nil {
		return fmt.Errorf("%w: encode CN preset", ErrRoutePatchInvalid)
	}
	return nil
}

func assignRoutePatchField(object map[string]json.RawMessage, final string, patch RoutePatch) error {
	field := ""
	var value any
	switch {
	case patch.Enabled != nil:
		field, value = "enabled", *patch.Enabled
	case patch.Target != nil:
		field, value = "target", *patch.Target
		if final != "" {
			field = final
		}
	case patch.DNSProfileID != nil:
		field, value = "dns_profile_id", *patch.DNSProfileID
	default:
		return ErrRoutePatchInvalid
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("%w: encode edit field", ErrRoutePatchInvalid)
	}
	object[field] = encoded
	return nil
}
