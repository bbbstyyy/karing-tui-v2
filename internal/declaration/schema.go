package declaration

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

type documentV1 struct {
	SchemaVersion int                 `json:"schema_version"`
	LogLevel      string              `json:"log_level"`
	RuleSets      []ruleSetResourceV1 `json:"rule_sets,omitempty"`
	Nodes         []nodeV1            `json:"nodes"`
	Selection     selectionV1         `json:"selection"`
	Routing       routingV1           `json:"routing"`
	DNS           dnsV1               `json:"dns"`
}

type ruleSetResourceV1 struct {
	Ref    string                 `json:"ref"`
	SHA256 string                 `json:"sha256"`
	Format compiler.RuleSetFormat `json:"format"`
}

func parseRuleSetResources(items []ruleSetResourceV1) ([]RuleSetResource, error) {
	result := make([]RuleSetResource, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for i, item := range items {
		if err := (domain.Predicate{Kind: domain.PredicateRuleSet, Value: item.Ref}).Validate(); err != nil {
			return nil, fmt.Errorf("%w: rule_sets[%d] ref: %v", ErrInvalidDocument, i, err)
		}
		if _, exists := seen[item.Ref]; exists {
			return nil, fmt.Errorf("%w: duplicate rule-set ref %q", ErrInvalidDocument, item.Ref)
		}
		seen[item.Ref] = struct{}{}
		switch item.Format {
		case compiler.RuleSetFormatSource, compiler.RuleSetFormatBinary:
		default:
			return nil, fmt.Errorf("%w: rule_sets[%d] has unsupported format %q", ErrInvalidDocument, i, item.Format)
		}
		decoded, err := hex.DecodeString(item.SHA256)
		if err != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("%w: rule_sets[%d] SHA-256 must be 64 hexadecimal characters", ErrInvalidDocument, i)
		}
		result = append(result, RuleSetResource{
			Ref:    item.Ref,
			SHA256: hex.EncodeToString(decoded),
			Format: item.Format,
		})
	}
	return result, nil
}

type nodeV1 struct {
	ProfileID   string          `json:"profile_id"`
	NodeID      string          `json:"node_id"`
	Type        domain.NodeKind `json:"type"`
	Server      string          `json:"server"`
	Port        uint16          `json:"port"`
	SOCKS       *socksV1        `json:"socks,omitempty"`
	HTTP        *httpV1         `json:"http,omitempty"`
	Shadowsocks *shadowsocksV1  `json:"shadowsocks,omitempty"`
	VMess       *vmessV1        `json:"vmess,omitempty"`
}

type socksV1 struct {
	Version  domain.SOCKSVersion `json:"version"`
	Username string              `json:"username,omitempty"`
	Password string              `json:"password,omitempty"`
	Network  domain.ProxyNetwork `json:"network"`
}

type httpV1 struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type shadowsocksV1 struct {
	Method        string              `json:"method"`
	Password      string              `json:"password"`
	Plugin        string              `json:"plugin,omitempty"`
	PluginOptions string              `json:"plugin_opts,omitempty"`
	Network       domain.ProxyNetwork `json:"network"`
}

type vmessV1 struct {
	UUID                string              `json:"uuid"`
	Security            string              `json:"security"`
	AlterID             uint16              `json:"alter_id,omitempty"`
	GlobalPadding       bool                `json:"global_padding,omitempty"`
	AuthenticatedLength bool                `json:"authenticated_length,omitempty"`
	Network             domain.ProxyNetwork `json:"network"`
	PacketEncoding      string              `json:"packet_encoding,omitempty"`
}


func (n nodeV1) toDomain() (domain.Node, error) {
	result := domain.Node{
		ProfileID: n.ProfileID,
		NodeID:    n.NodeID,
		Kind:      n.Type,
		Server:    n.Server,
		Port:      n.Port,
	}
	switch n.Type {
	case domain.NodeSOCKS:
		if n.SOCKS == nil || n.HTTP != nil || n.Shadowsocks != nil || n.VMess != nil {
			return domain.Node{}, errors.New("SOCKS node requires socks options and forbids other protocol options")
		}
		result.SOCKS = &domain.SOCKSNodeOptions{
			Version:  n.SOCKS.Version,
			Username: n.SOCKS.Username,
			Password: n.SOCKS.Password,
			Network:  n.SOCKS.Network,
		}
	case domain.NodeHTTP:
		if n.HTTP == nil || n.SOCKS != nil || n.Shadowsocks != nil || n.VMess != nil {
			return domain.Node{}, errors.New("HTTP node requires http options and forbids other protocol options")
		}
		result.HTTP = &domain.HTTPNodeOptions{Username: n.HTTP.Username, Password: n.HTTP.Password}
	case domain.NodeShadowsocks:
		if n.Shadowsocks == nil || n.SOCKS != nil || n.HTTP != nil || n.VMess != nil {
			return domain.Node{}, errors.New("Shadowsocks node requires shadowsocks options and forbids other protocol options")
		}
		result.Shadowsocks = &domain.ShadowsocksNodeOptions{
			Method:        n.Shadowsocks.Method,
			Password:      n.Shadowsocks.Password,
			Plugin:        n.Shadowsocks.Plugin,
			PluginOptions: n.Shadowsocks.PluginOptions,
			Network:       n.Shadowsocks.Network,
		}
	case domain.NodeVMess:
		if n.VMess == nil || n.SOCKS != nil || n.HTTP != nil || n.Shadowsocks != nil {
			return domain.Node{}, errors.New("VMess node requires vmess options and forbids other protocol options")
		}
		result.VMess = &domain.VMessNodeOptions{
			UUID:                n.VMess.UUID,
			Security:            n.VMess.Security,
			AlterID:             n.VMess.AlterID,
			GlobalPadding:       n.VMess.GlobalPadding,
			AuthenticatedLength: n.VMess.AuthenticatedLength,
			Network:             n.VMess.Network,
			PacketEncoding:      n.VMess.PacketEncoding,
		}
	default:
		return domain.Node{}, fmt.Errorf("unsupported node type %q", n.Type)
	}
	return result, nil
}

type selectionV1 struct {
	Current currentSelectionV1 `json:"current"`
	Global  *urlTestGroupV1    `json:"global,omitempty"`
	Custom  []urlTestGroupV1   `json:"custom,omitempty"`
}

type currentSelectionV1 struct {
	Members                   []domain.TargetRef `json:"members"`
	Default                   domain.TargetRef   `json:"default"`
	InterruptExistConnections bool               `json:"interrupt_exist_connections,omitempty"`
}

type urlTestGroupV1 struct {
	ID      string             `json:"id,omitempty"`
	Members []domain.TargetRef `json:"members"`
	Policy  urlTestPolicyV1    `json:"policy"`
}

type urlTestPolicyV1 struct {
	URL                       string `json:"url"`
	Interval                  string `json:"interval"`
	Tolerance                 uint16 `json:"tolerance"`
	IdleTimeout               string `json:"idle_timeout"`
	InterruptExistConnections bool   `json:"interrupt_exist_connections,omitempty"`
}

func (s selectionV1) toDomain() (domain.SelectionPlan, error) {
	result := domain.SelectionPlan{
		Current: domain.CurrentSelection{
			Members:                   append([]domain.TargetRef(nil), s.Current.Members...),
			Default:                   s.Current.Default,
			InterruptExistConnections: s.Current.InterruptExistConnections,
		},
	}
	if s.Global != nil {
		group, err := s.Global.toDomain(false)
		if err != nil {
			return domain.SelectionPlan{}, fmt.Errorf("%w: global URLTest: %v", ErrInvalidDocument, err)
		}
		result.Global = &group
	}
	result.Custom = make([]domain.URLTestGroup, 0, len(s.Custom))
	for i := range s.Custom {
		group, err := s.Custom[i].toDomain(true)
		if err != nil {
			return domain.SelectionPlan{}, fmt.Errorf("%w: custom URLTest %d: %v", ErrInvalidDocument, i, err)
		}
		result.Custom = append(result.Custom, group)
	}
	return result, nil
}

func (g urlTestGroupV1) toDomain(requireID bool) (domain.URLTestGroup, error) {
	if requireID && g.ID == "" {
		return domain.URLTestGroup{}, errors.New("custom URLTest requires id")
	}
	if !requireID && g.ID != "" {
		return domain.URLTestGroup{}, errors.New("global URLTest must not carry id")
	}
	interval, err := time.ParseDuration(g.Policy.Interval)
	if err != nil {
		return domain.URLTestGroup{}, fmt.Errorf("invalid interval: %w", err)
	}
	idleTimeout, err := time.ParseDuration(g.Policy.IdleTimeout)
	if err != nil {
		return domain.URLTestGroup{}, fmt.Errorf("invalid idle_timeout: %w", err)
	}
	return domain.URLTestGroup{
		GroupID: g.ID,
		Members: append([]domain.TargetRef(nil), g.Members...),
		Policy: domain.URLTestPolicy{
			URL:                       g.Policy.URL,
			Interval:                  interval,
			Tolerance:                 g.Policy.Tolerance,
			IdleTimeout:               idleTimeout,
			InterruptExistConnections: g.Policy.InterruptExistConnections,
		},
	}, nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: multiple JSON values are not allowed", ErrInvalidDocument)
		}
		return fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	return nil
}

func validateLogLevel(level string) error {
	switch level {
	case "trace", "debug", "info", "warn", "error", "fatal", "panic":
		return nil
	default:
		return fmt.Errorf("%w: unsupported log_level %q", ErrInvalidDocument, level)
	}
}
