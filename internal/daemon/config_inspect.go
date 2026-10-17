package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"sort"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

const (
	maxInspectedRouteGroups = 128
	maxInspectedDNSProfiles = 64
)

var ErrConfigInspectionUnavailable = errors.New("applied configuration inspection unavailable")

// inspectConfiguration projects only non-secret, bounded structural data.
// Provenance means a stored applied-generation DECLARATION. No packet or DNS
// request is observed, and no core config, credentials or match values leave
// the daemon. Staged change indicators are semantic comparisons, not applies.
func inspectConfiguration(ctx context.Context, store *storage.Store) (apiv1.ConfigInspectionResponse, error) {
	if store == nil {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		return apiv1.ConfigInspectionResponse{}, err
	}
	if snapshot.AppliedGenerationID == nil || snapshot.RecoveryRequired || snapshot.ActiveAttemptID != nil {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	artifacts, err := store.GenerationArtifacts(ctx, *snapshot.AppliedGenerationID)
	if err != nil {
		return apiv1.ConfigInspectionResponse{}, err
	}
	if len(artifacts.ManifestJSON) == 0 || artifacts.ManifestSHA256 == "" ||
		len(artifacts.ConfigJSON) == 0 || artifacts.ConfigSHA256 == "" {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	configHash := sha256.Sum256(artifacts.ConfigJSON)
	if hex.EncodeToString(configHash[:]) != artifacts.ConfigSHA256 {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	hash := sha256.Sum256(artifacts.ManifestJSON)
	if hex.EncodeToString(hash[:]) != artifacts.ManifestSHA256 {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	var manifest compiler.NativeManifest
	if err := json.Unmarshal(artifacts.ManifestJSON, &manifest); err != nil {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	if manifest.SchemaID != compiler.NativeSchemaID ||
		manifest.ConfigSHA256 != artifacts.ConfigSHA256 ||
		manifest.ValidateDeclarationBinding(true) != nil {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	applied, err := store.Declaration(ctx, manifest.DeclarationRevision)
	if err != nil || len(applied.DocumentJSON) == 0 ||
		applied.SHA256 != manifest.DeclarationSHA256 {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	appliedModel, err := declaration.ParseV1(applied.DocumentJSON)
	if err != nil {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	effective, err := declaration.EffectiveRouting(appliedModel)
	if err != nil {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil || current.Revision == 0 || len(current.DocumentJSON) == 0 {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	result, err := projectConfigurationInspection(snapshot.Revision, *snapshot.AppliedGenerationID,
		applied.Revision, current.Revision, appliedModel, effective)
	if err != nil {
		return apiv1.ConfigInspectionResponse{}, err
	}
	if current.Revision == applied.Revision && current.SHA256 != applied.SHA256 {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	if current.Revision != applied.Revision {
		staged, err := declaration.ParseV1(current.DocumentJSON)
		if err != nil {
			return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
		}
		stagedRouting, err := declaration.EffectiveRouting(staged)
		if err != nil {
			return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
		}
		result.StagedUnapplied = true
		result.RoutingChanged = !reflect.DeepEqual(effective, stagedRouting)
		result.DNSChanged = !reflect.DeepEqual(appliedModel.DNS, staged.DNS)
		result.RuleSetsChanged = !reflect.DeepEqual(appliedModel.RuleSets, staged.RuleSets)
	}

	// Reads may race a new apply or a declaration commit. Never present mixed
	// snapshot identities as a coherent applied/staged comparison.
	again, err := store.Snapshot(ctx)
	if err != nil || again.Revision != snapshot.Revision ||
		!sameGenerationID(again.AppliedGenerationID, snapshot.AppliedGenerationID) ||
		again.RecoveryRequired || again.ActiveAttemptID != nil {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	head, err := store.CurrentDeclaration(ctx)
	if err != nil || head.Revision != current.Revision || head.SHA256 != current.SHA256 {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	return result, nil
}

// Keep projection a pure function to test CN provenance, region interleaving,
// privacy and caps without a live daemon or network access.
func projectConfigurationInspection(
	configRevision uint64, generationID int64, appliedRevision uint64,
	currentRevision uint64, model declaration.Model, effective domain.RoutingPlan,
) (apiv1.ConfigInspectionResponse, error) {
	if generationID <= 0 || appliedRevision == 0 {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	if err := effective.Validate(); err != nil {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	if err := model.DNS.ValidateActiveRouteBindings(effective); err != nil {
		return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
	}
	cnIDs := make(map[string]bool)
	if model.CNPreset != nil {
		source, err := preset.LoadCN()
		if err != nil {
			return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
		}
		for _, item := range source.Groups {
			cnIDs[item.ID] = true
		}
	}
	result := apiv1.ConfigInspectionResponse{
		APIVersion:                 apiv1.Version,
		Evidence:                   "applied_declaration",
		ConfigRevision:             configRevision,
		GenerationID:               generationID,
		AppliedDeclarationRevision: appliedRevision,
		CurrentDeclarationRevision: currentRevision,
		CNPreset:                   model.CNPreset != nil,
		RegionAppend:               model.RegionAppend != nil,
		Layers:                     make([]apiv1.ConfigInspectionLayer, 0, 5),
	}
	budget := maxInspectedRouteGroups
	for _, section := range []struct {
		layer  domain.RoutingLayer
		groups []domain.RouteGroup
	}{
		{domain.LayerCustom, effective.Custom},
		{domain.LayerGeoSite, effective.GeoSite},
		{domain.LayerGeoIP, effective.GeoIP},
		{domain.LayerACL, effective.ACL},
	} {
		out := apiv1.ConfigInspectionLayer{
			Layer: section.layer, Enabled: effective.Layers.Enabled(section.layer),
			GroupCount: len(section.groups),
			Groups:     make([]apiv1.ConfigInspectionRouteGroup, 0, min(len(section.groups), budget)),
		}
		result.RouteTotal += len(section.groups)
		for _, group := range section.groups {
			if group.Binding.Enabled && out.Enabled {
				out.ActiveCount++
			}
			if budget == 0 {
				result.RouteTruncated = true
				continue
			}
			origin := "custom"
			if section.layer == domain.LayerCustom && cnIDs[group.ID] {
				origin = "cn_preset"
			} else if model.RegionAppend != nil && ((section.layer == domain.LayerGeoSite && group.ID == "region:auto-geosite:"+model.RegionAppend.RegionCode) ||
				(section.layer == domain.LayerGeoIP && group.ID == "region:auto-geoip:"+model.RegionAppend.RegionCode)) {
				origin = "region_append"
			}
			target := group.Binding.Target
			// An unconfigured disabled binding has no actionable target.
			if target.Kind != "" && target.Validate() != nil {
				return apiv1.ConfigInspectionResponse{}, ErrConfigInspectionUnavailable
			}
			out.Groups = append(out.Groups, apiv1.ConfigInspectionRouteGroup{
				ID: group.ID, Order: group.Order, Enabled: group.Binding.Enabled,
				Origin: origin, Target: target, DNSProfile: group.Binding.DNSProfileID,
				MatchKinds: inspectionMatchKinds(group.Match),
			})
			budget--
		}
		result.Layers = append(result.Layers, out)
	}
	result.RouteTotal++
	result.Layers = append(result.Layers, apiv1.ConfigInspectionLayer{
		Layer: domain.LayerFinal, Enabled: true, GroupCount: 1, ActiveCount: 1,
		Groups: []apiv1.ConfigInspectionRouteGroup{{
			ID: "FINAL", Enabled: true, Origin: "declaration",
			Target: effective.Final,
		}},
	})
	dns := apiv1.ConfigInspectionDNS{
		OutboundProfile: model.DNS.OutboundProfileID,
		DirectProfile:   model.DNS.DirectProfileID,
		ProxyProfile:    model.DNS.ProxyProfileID,
		FallbackProfile: model.DNS.FallbackProfileID,
		ProfileCount:    len(model.DNS.Profiles),
	}
	dns.Truncated = len(model.DNS.Profiles) > maxInspectedDNSProfiles
	limit := min(len(model.DNS.Profiles), maxInspectedDNSProfiles)
	dns.Profiles = make([]apiv1.ConfigInspectionDNSProfile, 0, limit)
	for _, profile := range model.DNS.Profiles[:limit] {
		upstream := "hostname (bootstrap required)"
		if parsed, err := netip.ParseAddr(profile.Server); err == nil && parsed.IsValid() {
			upstream = "IP literal"
		}
		entry := apiv1.ConfigInspectionDNSProfile{
			ID: profile.ID, Role: profile.Role, Transport: profile.Transport,
			Port: profile.Port, UpstreamKind: upstream,
			BootstrapID: profile.BootstrapProfileID,
		}
		if profile.Role == domain.DNSRoleGroup {
			detour := profile.DetourTarget
			entry.Detour = &detour
		}
		dns.Profiles = append(dns.Profiles, entry)
	}
	result.DNS = dns
	return result, nil
}

func inspectionMatchKinds(match *domain.MatchExpr) []string {
	if match == nil {
		return nil
	}
	seen := make(map[string]bool)
	var visit func(*domain.MatchExpr)
	visit = func(e *domain.MatchExpr) {
		if e.Predicate != nil {
			seen[string(e.Predicate.Kind)] = true
		}
		for i := range e.Children {
			visit(&e.Children[i])
		}
	}
	visit(match)
	result := make([]string, 0, len(seen))
	for kind := range seen {
		result = append(result, kind)
	}
	sort.Strings(result)
	return result
}
