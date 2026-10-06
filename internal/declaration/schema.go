package declaration

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

type documentV1 struct {
	SchemaVersion int         `json:"schema_version"`
	LogLevel      string      `json:"log_level"`
	Nodes         []nodeV1    `json:"nodes"`
	Selection     selectionV1 `json:"selection"`
	Routing       routingV1   `json:"routing"`
	DNS           dnsV1       `json:"dns"`
}

type nodeV1 struct {
	ProfileID string          `json:"profile_id"`
	NodeID    string          `json:"node_id"`
	Type      domain.NodeKind `json:"type"`
	Server    string          `json:"server"`
	Port      uint16          `json:"port"`
	SOCKS     *socksV1        `json:"socks,omitempty"`
	HTTP      *httpV1         `json:"http,omitempty"`
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
		if n.SOCKS == nil || n.HTTP != nil {
			return domain.Node{}, errors.New("SOCKS node requires socks options and forbids http options")
		}
		result.SOCKS = &domain.SOCKSNodeOptions{
			Version:  n.SOCKS.Version,
			Username: n.SOCKS.Username,
			Password: n.SOCKS.Password,
			Network:  n.SOCKS.Network,
		}
	case domain.NodeHTTP:
		if n.HTTP == nil || n.SOCKS != nil {
			return domain.Node{}, errors.New("HTTP node requires http options and forbids socks options")
		}
		result.HTTP = &domain.HTTPNodeOptions{Username: n.HTTP.Username, Password: n.HTTP.Password}
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
