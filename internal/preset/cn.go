package preset

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const (
	CNSourceRepository = "KaringX/karing"
	CNSourceCommit     = "9d28b22fbbcca5818d147629aae151d49d4dcb7b"
	CNSourcePath       = "assets/datas/preset/cn.json"
	CNExpectedGroups   = 28
	CNExpectedEnabled  = 6
)

//go:embed cn.json
var cnFS embed.FS

var cnStableGroupIDs = [...]string{
	"cn.ad-block",
	"cn.app-cleanup",
	"cn.malware",
	"cn.apple-push",
	"cn.apple-services",
	"cn.youtube",
	"cn.google-gemini",
	"cn.google-play",
	"cn.google-fcm",
	"cn.google",
	"cn.facebook",
	"cn.x",
	"cn.tiktok",
	"cn.instagram",
	"cn.netflix",
	"cn.whatsapp",
	"cn.telegram",
	"cn.claude",
	"cn.openai",
	"cn.github",
	"cn.bing",
	"cn.onedrive",
	"cn.microsoft",
	"cn.gaming",
	"cn.bilibili",
	"cn.netease-music",
	"cn.domestic-direct",
	"cn.foreign-proxy",
}

var (
	ErrInvalidCNPreset         = errors.New("invalid CN preset snapshot")
	ErrUnsupportedPresetTarget = errors.New("unsupported preset target")
)

type CNRule struct {
	RuleSetBuildIn []string `json:"rule_set_build_in,omitempty"`
	DomainSuffix   []string `json:"domain_suffix,omitempty"`
	DomainKeyword  []string `json:"domain_keyword,omitempty"`
	IPCIDR         []string `json:"ip_cidr,omitempty"`
	Package        []string `json:"package,omitempty"`
	ProcessName    []string `json:"processName,omitempty"`
	Outbound       string   `json:"outbound"`
	Name           string   `json:"name"`
	Switch         bool     `json:"switch"`
}

type cnDocument struct {
	Rules []CNRule `json:"rules"`
}

type CNGroup struct {
	ID          string
	Order       uint32
	DisplayName string
	Enabled     bool
	Target      domain.TargetRef
	Source      CNRule
}

type CNSnapshot struct {
	SourceRepository string
	SourceCommit     string
	SourcePath       string
	Groups           []CNGroup
}

func LoadCN() (CNSnapshot, error) {
	raw, err := cnFS.ReadFile("cn.json")
	if err != nil {
		return CNSnapshot{}, fmt.Errorf("read embedded CN preset: %w", err)
	}
	return ParseCN(raw)
}

func ParseCN(raw []byte) (CNSnapshot, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()

	var document cnDocument
	if err := decoder.Decode(&document); err != nil {
		return CNSnapshot{}, fmt.Errorf("%w: decode snapshot: %v", ErrInvalidCNPreset, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return CNSnapshot{}, fmt.Errorf("%w: trailing JSON content", ErrInvalidCNPreset)
		}
		return CNSnapshot{}, fmt.Errorf("%w: trailing JSON: %v", ErrInvalidCNPreset, err)
	}
	if len(document.Rules) != CNExpectedGroups {
		return CNSnapshot{}, fmt.Errorf("%w: groups = %d, want %d", ErrInvalidCNPreset, len(document.Rules), CNExpectedGroups)
	}

	groups := make([]CNGroup, 0, len(document.Rules))
	enabled := 0
	for i, rule := range document.Rules {
		if err := validateCNRule(rule, i); err != nil {
			return CNSnapshot{}, err
		}
		target, err := presetTarget(rule.Outbound)
		if err != nil {
			return CNSnapshot{}, fmt.Errorf("%w: group %d %q: %v", ErrInvalidCNPreset, i+1, rule.Name, err)
		}
		if rule.Switch {
			enabled++
		}
		groups = append(groups, CNGroup{
			ID:          cnStableGroupIDs[i],
			Order:       uint32(i + 1),
			DisplayName: rule.Name,
			Enabled:     rule.Switch,
			Target:      target,
			Source:      cloneCNRule(rule),
		})
	}
	if enabled != CNExpectedEnabled {
		return CNSnapshot{}, fmt.Errorf("%w: enabled groups = %d, want %d", ErrInvalidCNPreset, enabled, CNExpectedEnabled)
	}

	return CNSnapshot{
		SourceRepository: CNSourceRepository,
		SourceCommit:     CNSourceCommit,
		SourcePath:       CNSourcePath,
		Groups:           groups,
	}, nil
}

func validateCNRule(rule CNRule, index int) error {
	if rule.Name == "" {
		return fmt.Errorf("%w: group %d has empty name", ErrInvalidCNPreset, index+1)
	}
	if rule.Outbound == "" {
		return fmt.Errorf("%w: group %d %q has empty outbound", ErrInvalidCNPreset, index+1, rule.Name)
	}
	if len(rule.RuleSetBuildIn) == 0 &&
		len(rule.DomainSuffix) == 0 &&
		len(rule.DomainKeyword) == 0 &&
		len(rule.IPCIDR) == 0 &&
		len(rule.Package) == 0 &&
		len(rule.ProcessName) == 0 {
		return fmt.Errorf("%w: group %d %q has no source conditions", ErrInvalidCNPreset, index+1, rule.Name)
	}
	return nil
}

func presetTarget(value string) (domain.TargetRef, error) {
	switch value {
	case "direct":
		return domain.TargetRef{Kind: domain.TargetDirect}, nil
	case "block":
		return domain.TargetRef{Kind: domain.TargetBlock}, nil
	case "currentSelected":
		return domain.TargetRef{Kind: domain.TargetCurrentSelected}, nil
	default:
		return domain.TargetRef{}, fmt.Errorf("%w: %q", ErrUnsupportedPresetTarget, value)
	}
}

func (s CNSnapshot) RuleSetRefs(enabledOnly bool) []string {
	seen := make(map[string]struct{})
	refs := make([]string, 0)
	for _, group := range s.Groups {
		if enabledOnly && !group.Enabled {
			continue
		}
		for _, ref := range group.Source.RuleSetBuildIn {
			if _, exists := seen[ref]; exists {
				continue
			}
			seen[ref] = struct{}{}
			refs = append(refs, ref)
		}
	}
	return refs
}

func cloneCNRule(rule CNRule) CNRule {
	rule.RuleSetBuildIn = append([]string(nil), rule.RuleSetBuildIn...)
	rule.DomainSuffix = append([]string(nil), rule.DomainSuffix...)
	rule.DomainKeyword = append([]string(nil), rule.DomainKeyword...)
	rule.IPCIDR = append([]string(nil), rule.IPCIDR...)
	rule.Package = append([]string(nil), rule.Package...)
	rule.ProcessName = append([]string(nil), rule.ProcessName...)
	return rule
}
