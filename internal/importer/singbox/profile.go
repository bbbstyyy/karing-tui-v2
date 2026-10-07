package singbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

type DiagnosticLevel string

const (
	DiagnosticInfo  DiagnosticLevel = "info"
	DiagnosticError DiagnosticLevel = "error"
)

type Diagnostic struct {
	Level   DiagnosticLevel
	Path    string
	Code    string
	Message string
}

type BasicNode struct {
	Source profile.SourceNode
	Kind   domain.NodeKind
	Server string
	Port   uint16
	SOCKS  *domain.SOCKSNodeOptions
	HTTP   *domain.HTTPNodeOptions
}

func (n BasicNode) Materialize(identity profile.NodeIdentity) (domain.Node, error) {
	if identity.ProfileID == "" || identity.NodeID == "" || identity.SourceKey == "" {
		return domain.Node{}, errors.New("profile node identity is incomplete")
	}
	if identity.SourceKey != n.Source.SourceKey {
		return domain.Node{}, fmt.Errorf("profile identity source key %q does not match imported node %q", identity.SourceKey, n.Source.SourceKey)
	}
	node := domain.Node{
		ProfileID: identity.ProfileID,
		NodeID:    identity.NodeID,
		Kind:      n.Kind,
		Server:    n.Server,
		Port:      n.Port,
	}
	if n.SOCKS != nil {
		value := *n.SOCKS
		node.SOCKS = &value
	}
	if n.HTTP != nil {
		value := *n.HTTP
		node.HTTP = &value
	}
	if err := node.Validate(); err != nil {
		return domain.Node{}, err
	}
	return node, nil
}

type ProfileAnalysis struct {
	ProfileID    string
	SourceSHA256 string
	Nodes        []BasicNode
	Diagnostics  []Diagnostic
}

func (a ProfileAnalysis) CanCommit() bool {
	if len(a.Nodes) == 0 {
		return false
	}
	for _, diagnostic := range a.Diagnostics {
		if diagnostic.Level == DiagnosticError {
			return false
		}
	}
	return true
}

func (a ProfileAnalysis) SnapshotNodes() (profileNodes []profile.SourceNode, sourceSHA256 string, ok bool) {
	if !a.CanCommit() {
		return nil, a.SourceSHA256, false
	}
	nodes := make([]profile.SourceNode, 0, len(a.Nodes))
	for _, node := range a.Nodes {
		nodes = append(nodes, node.Source)
	}
	return nodes, a.SourceSHA256, true
}

func AnalyzeBasicProfile(data []byte, profileID string) (ProfileAnalysis, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return ProfileAnalysis{}, err
	}
	if len(data) == 0 {
		return ProfileAnalysis{}, errors.New("sing-box profile is empty")
	}
	if err := ValidateProxyOnlyConfig(data); err != nil {
		return ProfileAnalysis{}, err
	}

	var root map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&root); err != nil {
		return ProfileAnalysis{}, fmt.Errorf("decode sing-box profile: %w", err)
	}
	if err := requireAnalysisEOF(decoder); err != nil {
		return ProfileAnalysis{}, err
	}

	sum := sha256.Sum256(data)
	analysis := ProfileAnalysis{
		ProfileID:    profileID,
		SourceSHA256: hex.EncodeToString(sum[:]),
	}

	for _, key := range []string{"route", "dns"} {
		if raw, exists := root[key]; exists && !isJSONNull(raw) {
			analysis.Diagnostics = append(analysis.Diagnostics, Diagnostic{
				Level:   DiagnosticInfo,
				Path:    key,
				Code:    "ignored_by_product_policy",
				Message: "source routing/DNS policy is not imported into the project routing tree",
			})
		}
	}
	for _, key := range []string{"inbounds", "experimental"} {
		if raw, exists := root[key]; exists && !isJSONNull(raw) {
			analysis.Diagnostics = append(analysis.Diagnostics, Diagnostic{
				Level:   DiagnosticInfo,
				Path:    key,
				Code:    "source_context_not_imported",
				Message: "source runtime context is inspected for safety where applicable but is not imported as profile node state",
			})
		}
	}

	rawOutbounds, exists := root["outbounds"]
	if !exists {
		return analysis, errors.New("sing-box profile has no outbounds")
	}
	var outbounds []json.RawMessage
	if err := json.Unmarshal(rawOutbounds, &outbounds); err != nil {
		return ProfileAnalysis{}, fmt.Errorf("decode sing-box outbounds: %w", err)
	}
	if len(outbounds) == 0 {
		return analysis, errors.New("sing-box profile has no outbounds")
	}

	seenTags := make(map[string]struct{}, len(outbounds))
	for index, raw := range outbounds {
		path := fmt.Sprintf("outbounds[%d]", index)
		var base struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &base); err != nil {
			return ProfileAnalysis{}, fmt.Errorf("decode %s: %w", path, err)
		}
		if base.Type == "" {
			analysis.Diagnostics = append(analysis.Diagnostics, Diagnostic{
				Level: DiagnosticError, Path: path + ".type", Code: "missing_type", Message: "outbound type is required",
			})
			continue
		}
		switch base.Type {
		case "direct", "block", "dns":
			analysis.Diagnostics = append(analysis.Diagnostics, Diagnostic{
				Level: DiagnosticInfo, Path: path, Code: "non_node_outbound_ignored",
				Message: fmt.Sprintf("outbound type %q is runtime policy plumbing, not a profile proxy node", base.Type),
			})
			continue
		}
		if base.Tag == "" {
			analysis.Diagnostics = append(analysis.Diagnostics, Diagnostic{
				Level: DiagnosticError, Path: path + ".tag", Code: "missing_tag",
				Message: "supported proxy outbounds require a stable tag for profile identity",
			})
			continue
		}
		if _, duplicate := seenTags[base.Tag]; duplicate {
			analysis.Diagnostics = append(analysis.Diagnostics, Diagnostic{
				Level: DiagnosticError, Path: path + ".tag", Code: "duplicate_tag",
				Message: fmt.Sprintf("outbound tag %q is duplicated", base.Tag),
			})
			continue
		}
		seenTags[base.Tag] = struct{}{}

		var (
			node BasicNode
			err  error
		)
		switch base.Type {
		case "socks":
			node, err = parseBasicSOCKSOutbound(raw, base.Tag)
		case "http":
			node, err = parseBasicHTTPOutbound(raw, base.Tag)
		default:
			analysis.Diagnostics = append(analysis.Diagnostics, Diagnostic{
				Level: DiagnosticError, Path: path + ".type", Code: "unsupported_proxy_protocol",
				Message: fmt.Sprintf("proxy outbound type %q is not materialized by the current node model", base.Type),
			})
			continue
		}
		if err != nil {
			analysis.Diagnostics = append(analysis.Diagnostics, Diagnostic{
				Level: DiagnosticError, Path: path, Code: "unsupported_or_invalid_node", Message: err.Error(),
			})
			continue
		}
		analysis.Nodes = append(analysis.Nodes, node)
	}

	return analysis, nil
}

func parseBasicSOCKSOutbound(raw []byte, tag string) (BasicNode, error) {
	allowed := map[string]struct{}{
		"type": {}, "tag": {}, "server": {}, "server_port": {}, "version": {},
		"username": {}, "password": {}, "network": {},
	}
	if extras, err := unsupportedObjectFields(raw, allowed); err != nil {
		return BasicNode{}, err
	} else if len(extras) != 0 {
		return BasicNode{}, fmt.Errorf("unsupported SOCKS fields: %s", strings.Join(extras, ", "))
	}
	var wire struct {
		Type     string `json:"type"`
		Tag      string `json:"tag"`
		Server   string `json:"server"`
		Port     uint16 `json:"server_port"`
		Version  string `json:"version"`
		Username string `json:"username"`
		Password string `json:"password"`
		Network  string `json:"network"`
	}
	if err := decodeStrictObject(raw, &wire); err != nil {
		return BasicNode{}, err
	}
	version := domain.SOCKSVersion(wire.Version)
	if version == "" {
		version = domain.SOCKS5
	}
	network := domain.ProxyNetwork(wire.Network)
	if network == "" {
		network = domain.ProxyNetworkBoth
	}
	node := BasicNode{
		Source: profile.SourceNode{SourceKey: tag, SourceName: tag, PayloadJSON: append([]byte(nil), raw...)},
		Kind:   domain.NodeSOCKS,
		Server: wire.Server,
		Port:   wire.Port,
		SOCKS: &domain.SOCKSNodeOptions{
			Version: version, Username: wire.Username, Password: wire.Password, Network: network,
		},
	}
	identity, err := profile.StableNodeID("validation-profile", tag)
	if err != nil {
		return BasicNode{}, err
	}
	if _, err := node.Materialize(profile.NodeIdentity{
		ProfileID: "validation-profile", NodeID: identity, SourceKey: tag, SourceName: tag,
	}); err != nil {
		return BasicNode{}, err
	}
	return node, nil
}

func parseBasicHTTPOutbound(raw []byte, tag string) (BasicNode, error) {
	allowed := map[string]struct{}{
		"type": {}, "tag": {}, "server": {}, "server_port": {}, "username": {}, "password": {},
	}
	if extras, err := unsupportedObjectFields(raw, allowed); err != nil {
		return BasicNode{}, err
	} else if len(extras) != 0 {
		return BasicNode{}, fmt.Errorf("unsupported HTTP fields: %s", strings.Join(extras, ", "))
	}
	var wire struct {
		Type     string `json:"type"`
		Tag      string `json:"tag"`
		Server   string `json:"server"`
		Port     uint16 `json:"server_port"`
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeStrictObject(raw, &wire); err != nil {
		return BasicNode{}, err
	}
	node := BasicNode{
		Source: profile.SourceNode{SourceKey: tag, SourceName: tag, PayloadJSON: append([]byte(nil), raw...)},
		Kind:   domain.NodeHTTP,
		Server: wire.Server,
		Port:   wire.Port,
		HTTP:   &domain.HTTPNodeOptions{Username: wire.Username, Password: wire.Password},
	}
	identity, err := profile.StableNodeID("validation-profile", tag)
	if err != nil {
		return BasicNode{}, err
	}
	if _, err := node.Materialize(profile.NodeIdentity{
		ProfileID: "validation-profile", NodeID: identity, SourceKey: tag, SourceName: tag,
	}); err != nil {
		return BasicNode{}, err
	}
	return node, nil
}

func unsupportedObjectFields(raw []byte, allowed map[string]struct{}) ([]string, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	var extras []string
	for key := range object {
		if _, ok := allowed[key]; !ok {
			extras = append(extras, key)
		}
	}
	sort.Strings(extras)
	return extras, nil
}

func decodeStrictObject(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	return requireAnalysisEOF(decoder)
}

func requireAnalysisEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func isJSONNull(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "null"
}
