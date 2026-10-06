package domain

import (
	"errors"
	"fmt"
)

var ErrInvalidRegionAppend = errors.New("invalid region auto-append policy")

type RegionAppendPlan struct {
	RegionCode     string
	GeoSiteEnabled bool
	GeoIPEnabled   bool
	Target         TargetRef
}

func DefaultCNRegionAppendPlan() RegionAppendPlan {
	return RegionAppendPlan{
		RegionCode:     "cn",
		GeoSiteEnabled: true,
		GeoIPEnabled:   true,
		Target:         TargetRef{Kind: TargetDirect},
	}
}

func (p RegionAppendPlan) Validate() error {
	if len(p.RegionCode) != 2 ||
		p.RegionCode[0] < 'a' || p.RegionCode[0] > 'z' ||
		p.RegionCode[1] < 'a' || p.RegionCode[1] > 'z' {
		return fmt.Errorf("%w: region code %q must be lowercase ISO-3166 alpha-2", ErrInvalidRegionAppend, p.RegionCode)
	}
	if err := p.Target.Validate(); err != nil {
		return fmt.Errorf("%w: target: %v", ErrInvalidRegionAppend, err)
	}
	if p.Target.Kind != TargetDirect {
		return fmt.Errorf("%w: automatic region entries must target DIRECT", ErrInvalidRegionAppend)
	}
	return nil
}

func (p RegionAppendPlan) RuleSetRefs() ([]string, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	refs := make([]string, 0, 2)
	if p.GeoSiteEnabled {
		refs = append(refs, "geosite:"+p.RegionCode)
	}
	if p.GeoIPEnabled {
		refs = append(refs, "geoip:"+p.RegionCode)
	}
	return refs, nil
}
