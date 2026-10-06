package preset

import (
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

var (
	ErrCNRuleHasNoLinuxMatch        = errors.New("CN preset rule has no supported Linux matcher")
	ErrCNProcessSemanticsUnverified = errors.New("CN preset processName semantics are not verified for Linux")
)

// LowerCNCustomRouting lowers the immutable CN preset plus user overrides into
// L1 custom routing groups for Linux.
//
// The pinned preset omits the historical "or" flag. The last public Karing
// builder defaulted that flag to true and emitted each non-empty field family
// as a child of a logical OR rule. Android package predicates were emitted only
// on Android, so they are intentionally absent here.
//
// The exact mapping of the preset's legacy camelCase processName field into the
// later platform-specific process fields is not available in the pinned public
// tree. Enabling such a group therefore fails closed instead of silently
// dropping or guessing its process predicate.
func LowerCNCustomRouting(snapshot CNSnapshot, overrides []CNOverride) ([]domain.RouteGroup, error) {
	effective, err := ApplyCNOverrides(snapshot, overrides)
	if err != nil {
		return nil, err
	}

	groups := make([]domain.RouteGroup, 0, len(effective))
	for _, source := range effective {
		group := domain.RouteGroup{
			ID:    source.ID,
			Layer: domain.LayerCustom,
			Order: source.Order,
			Binding: domain.RouteBinding{
				Enabled:      source.Enabled,
				Target:       source.Target,
				DNSProfileID: source.DNSProfileID,
			},
		}
		if source.Enabled {
			match, err := lowerCNRuleLinux(source.Source)
			if err != nil {
				return nil, fmt.Errorf("lower CN group %q: %w", source.ID, err)
			}
			group.Match = &match
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func lowerCNRuleLinux(rule CNRule) (domain.MatchExpr, error) {
	if len(rule.ProcessName) != 0 {
		return domain.MatchExpr{}, fmt.Errorf("%w: %q", ErrCNProcessSemanticsUnverified, rule.Name)
	}

	children := make([]domain.MatchExpr, 0,
		len(rule.RuleSetBuildIn)+
			len(rule.DomainSuffix)+
			len(rule.DomainKeyword)+
			len(rule.IPCIDR),
	)
	for _, ref := range rule.RuleSetBuildIn {
		children = append(children, domain.Atom(domain.Predicate{
			Kind:  domain.PredicateRuleSet,
			Value: ref,
		}))
	}
	for _, value := range rule.DomainSuffix {
		children = append(children, domain.Atom(domain.Predicate{
			Kind:  domain.PredicateDomainSuffix,
			Value: value,
		}))
	}
	for _, value := range rule.DomainKeyword {
		children = append(children, domain.Atom(domain.Predicate{
			Kind:  domain.PredicateDomainKeyword,
			Value: value,
		}))
	}
	for _, cidr := range rule.IPCIDR {
		children = append(children, domain.Atom(domain.Predicate{
			Kind: domain.PredicateIPCIDR,
			CIDR: cidr,
		}))
	}

	// package is intentionally not included: the historical builder guarded it
	// with Platform.isAndroid. On Linux it contributed no matcher.
	if len(children) == 0 {
		return domain.MatchExpr{}, fmt.Errorf("%w: %q", ErrCNRuleHasNoLinuxMatch, rule.Name)
	}
	match := domain.Any(children...)
	if err := match.Validate(); err != nil {
		return domain.MatchExpr{}, fmt.Errorf("validate lowered CN matcher: %w", err)
	}
	return match, nil
}
