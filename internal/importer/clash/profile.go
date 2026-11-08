package clash

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	singboximport "github.com/bbbstyyy/karing-tui-v2/internal/importer/singbox"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
	"go.yaml.in/yaml/v3"
)

const (
	MaxClashSourceBytes = 2 << 20
	MaxClashProxyCount  = 4096
	maxClashSyntaxNodes = 160000
	maxClashSyntaxDepth = 48
	maxClashScalarBytes = 16 << 10
)

var errInvalidClash = errors.New("invalid or unsupported Clash YAML syntax")

// AnalyzeBasicProfile imports only a bounded Clash proxy-node subset.
// Subscription proxy-groups, rules and DNS are explicitly reported as ignored
// and cannot modify the project's five-layer CN routing or resolver policy.
// Any unsupported proxy field blocks the WHOLE refresh, not only that node.
func AnalyzeBasicProfile(data []byte, profileID string) (singboximport.ProfileAnalysis, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return singboximport.ProfileAnalysis{}, err
	}
	if len(data) == 0 || len(data) > MaxClashSourceBytes || !utf8.Valid(data) {
		return singboximport.ProfileAnalysis{}, errors.New("Clash YAML source must be bounded, non-empty UTF-8")
	}
	var document yaml.Node
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		// YAML library errors can quote source scalars containing secrets.
		return singboximport.ProfileAnalysis{}, errInvalidClash
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return singboximport.ProfileAnalysis{}, errors.New("Clash YAML must contain exactly one document")
	}
	remaining := maxClashSyntaxNodes
	if err := validateClashSyntax(&document, 0, &remaining); err != nil {
		return singboximport.ProfileAnalysis{}, err
	}
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return singboximport.ProfileAnalysis{}, errInvalidClash
	}
	root, ok := clashMapping(document.Content[0])
	if !ok {
		return singboximport.ProfileAnalysis{}, errors.New("Clash YAML root must be a mapping")
	}
	sum := sha256.Sum256(data)
	analysis := singboximport.ProfileAnalysis{
		ProfileID: profileID, SourceSHA256: hex.EncodeToString(sum[:]),
	}
	for key := range root {
		switch key {
		case "proxies":
		case "proxy-groups", "rules", "dns":
			analysis.Diagnostics = append(analysis.Diagnostics, singboximport.Diagnostic{
				Level: singboximport.DiagnosticInfo, Path: key,
				Code:    "ignored_by_product_policy",
				Message: "subscription routing/DNS/groups are not imported into project policy",
			})
		case "port", "socks-port", "mixed-port", "allow-lan", "mode", "log-level", "ipv6", "external-controller":
			analysis.Diagnostics = append(analysis.Diagnostics, singboximport.Diagnostic{
				Level: singboximport.DiagnosticInfo, Path: key,
				Code:    "source_context_not_imported",
				Message: "source runtime settings are not imported into local inbounds",
			})
		default:
			analysis.Diagnostics = append(analysis.Diagnostics, singboximport.Diagnostic{
				Level: singboximport.DiagnosticError, Path: "root",
				Code:    "unsupported_top_level_field",
				Message: "Clash YAML contains an unsupported top-level field",
			})
		}
	}
	proxies, ok := root["proxies"]
	if !ok || proxies.Kind != yaml.SequenceNode || len(proxies.Content) == 0 {
		return analysis, errors.New("Clash YAML requires a non-empty proxies sequence")
	}
	if len(proxies.Content) > MaxClashProxyCount {
		return analysis, errors.New("Clash YAML exceeds the supported proxy count")
	}
	seen := make(map[string]int, len(proxies.Content))
	seenNames := make(map[string]int, len(proxies.Content))
	for i, item := range proxies.Content {
		path := fmt.Sprintf("proxies[%d]", i)
		nodeJSON, sourceKey, sourceName, err := convertClashProxy(item)
		if err != nil {
			analysis.Diagnostics = append(analysis.Diagnostics, singboximport.Diagnostic{
				Level: singboximport.DiagnosticError, Path: path,
				Code:    "unsupported_or_invalid_proxy",
				Message: "Clash proxy has invalid or unsupported fields; source not committed",
			})
			continue
		}
		if prior, exists := seenNames[sourceName]; exists {
			analysis.Diagnostics = append(analysis.Diagnostics, singboximport.Diagnostic{
				Level: singboximport.DiagnosticError, Path: path,
				Code:    "duplicate_proxy_name",
				Message: fmt.Sprintf("Clash proxy name duplicates proxies[%d]", prior),
			})
			continue
		}
		seenNames[sourceName] = i
		if prior, exists := seen[sourceKey]; exists {
			analysis.Diagnostics = append(analysis.Diagnostics, singboximport.Diagnostic{
				Level: singboximport.DiagnosticError, Path: path,
				Code:    "duplicate_semantic_proxy",
				Message: fmt.Sprintf("Clash proxy duplicates proxies[%d]", prior),
			})
			continue
		}
		seen[sourceKey] = i
		documentJSON, err := json.Marshal(struct {
			Outbounds []json.RawMessage `json:"outbounds"`
		}{Outbounds: []json.RawMessage{nodeJSON}})
		if err != nil {
			return analysis, errors.New("cannot encode canonical Clash outbound")
		}
		validated, err := singboximport.AnalyzeBasicProfile(documentJSON, profileID)
		if err != nil || validated.HasBlockingDiagnostics() || len(validated.Nodes) != 1 {
			analysis.Diagnostics = append(analysis.Diagnostics, singboximport.Diagnostic{
				Level: singboximport.DiagnosticError, Path: path,
				Code:    "unsupported_or_invalid_proxy",
				Message: "Clash proxy is not supported by the validated basic node model",
			})
			continue
		}
		node := validated.Nodes[0]
		node.Source.SourceKey = sourceKey
		node.Source.SourceName = sourceName
		node.Source.PayloadJSON = append([]byte(nil), nodeJSON...)
		analysis.Nodes = append(analysis.Nodes, node)
	}
	return analysis, nil
}

func validateClashSyntax(n *yaml.Node, depth int, remaining *int) error {
	*remaining--
	if n == nil || *remaining < 0 || depth > maxClashSyntaxDepth ||
		n.Kind == yaml.AliasNode || n.Anchor != "" ||
		n.Style&yaml.TaggedStyle != 0 || len(n.Value) > maxClashScalarBytes {
		return errInvalidClash
	}
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range n.Content {
			if err := validateClashSyntax(child, depth+1, remaining); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		if len(n.Content)%2 != 0 {
			return errInvalidClash
		}
		seen := make(map[string]struct{}, len(n.Content)/2)
		for i := 0; i < len(n.Content); i += 2 {
			key := n.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" ||
				key.Value == "" || len(key.Value) > 256 {
				return errInvalidClash
			}
			if _, exists := seen[key.Value]; exists {
				return errors.New("Clash YAML contains a duplicate mapping key")
			}
			seen[key.Value] = struct{}{}
			if err := validateClashSyntax(key, depth+1, remaining); err != nil {
				return err
			}
			if err := validateClashSyntax(n.Content[i+1], depth+1, remaining); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		switch n.Tag {
		case "!!str", "!!int", "!!bool", "!!float", "!!null":
		default:
			return errInvalidClash
		}
	default:
		return errInvalidClash
	}
	return nil
}

func clashMapping(n *yaml.Node) (map[string]*yaml.Node, bool) {
	if n == nil || n.Kind != yaml.MappingNode || len(n.Content)%2 != 0 {
		return nil, false
	}
	fields := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i < len(n.Content); i += 2 {
		key := n.Content[i]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return nil, false
		}
		fields[key.Value] = n.Content[i+1]
	}
	return fields, true
}

func clashString(value *yaml.Node) (string, bool) {
	if value == nil || value.Kind != yaml.ScalarNode || value.Tag != "!!str" {
		return "", false
	}
	return value.Value, true
}

func clashStringRequired(fields map[string]*yaml.Node, key string) (string, bool) {
	value, ok := clashString(fields[key])
	return value, ok && value != "" && strings.TrimSpace(value) == value
}

func clashOptionalString(fields map[string]*yaml.Node, key string) (string, bool) {
	value, exists := fields[key]
	if !exists {
		return "", true
	}
	return clashString(value)
}

func clashOptionalExact(fields map[string]*yaml.Node, key, exact string) bool {
	value, exists := fields[key]
	if !exists {
		return true
	}
	got, ok := clashString(value)
	return ok && got == exact
}

func clashOptionalBoolean(fields map[string]*yaml.Node, key string, expect bool) bool {
	value, exists := fields[key]
	if !exists {
		return true
	}
	if value.Kind != yaml.ScalarNode || value.Tag != "!!bool" {
		return false
	}
	return (value.Value == "true" && expect) || (value.Value == "false" && !expect)
}

func clashPort(fields map[string]*yaml.Node) (uint16, bool) {
	n := fields["port"]
	if n == nil || n.Kind != yaml.ScalarNode ||
		(n.Tag != "!!int" && n.Tag != "!!str") || n.Value == "" {
		return 0, false
	}
	for _, digit := range n.Value {
		if digit < '0' || digit > '9' {
			return 0, false
		}
	}
	port, err := strconv.ParseUint(n.Value, 10, 16)
	return uint16(port), err == nil && port != 0
}

func clashName(value string) bool {
	if len(value) == 0 || len(value) > 256 || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func convertClashProxy(item *yaml.Node) (json.RawMessage, string, string, error) {
	fields, ok := clashMapping(item)
	if !ok {
		return nil, "", "", errInvalidClash
	}
	name, nameOK := clashStringRequired(fields, "name")
	protocol, typeOK := clashStringRequired(fields, "type")
	server, serverOK := clashStringRequired(fields, "server")
	port, portOK := clashPort(fields)
	if !nameOK || !clashName(name) || !typeOK || !serverOK || !portOK {
		return nil, "", "", errInvalidClash
	}
	if !clashOptionalExact(fields, "network", "tcp") ||
		!clashOptionalBoolean(fields, "udp", false) {
		return nil, "", "", errInvalidClash
	}
	var identity map[string]any
	switch protocol {
	case "ss":
		if !clashAllowedFields(fields, "name", "type", "server", "port",
			"cipher", "password", "udp", "network") {
			return nil, "", "", errInvalidClash
		}
		method, methodOK := clashStringRequired(fields, "cipher")
		password, pwdOK := clashStringRequired(fields, "password")
		// Only AES-256-GCM TCP is covered by the pinned real-Core fixture.
		if !methodOK || method != "aes-256-gcm" || !pwdOK {
			return nil, "", "", errInvalidClash
		}
		identity = map[string]any{
			"type": "shadowsocks", "server": server, "server_port": port,
			"method": method, "password": password, "network": "tcp",
		}
	case "trojan", "vless":
		if !clashAllowedFields(fields, "name", "type", "server", "port",
			"password", "uuid", "tls", "servername", "sni", "network",
			"skip-cert-verify", "udp", "encryption") ||
			!clashOptionalBoolean(fields, "skip-cert-verify", false) ||
			!clashOptionalBoolean(fields, "tls", true) ||
			!clashOptionalExact(fields, "encryption", "none") {
			return nil, "", "", errInvalidClash
		}
		if fields["servername"] != nil && fields["sni"] != nil {
			return nil, "", "", errInvalidClash
		}
		if protocol == "vless" && fields["tls"] == nil {
			// VLESS plaintext must not be inferred from ambiguous defaults.
			return nil, "", "", errInvalidClash
		}
		tls := map[string]any{"enabled": true}
		sni, sniOK := clashOptionalString(fields, "servername")
		if fields["servername"] == nil {
			sni, sniOK = clashOptionalString(fields, "sni")
		}
		if !sniOK || (fields["servername"] != nil && sni == "") ||
			(fields["sni"] != nil && sni == "") {
			return nil, "", "", errInvalidClash
		}
		if sni != "" {
			tls["server_name"] = sni
		}
		identity = map[string]any{
			"type": protocol, "server": server, "server_port": port,
			"network": "tcp", "tls": tls,
		}
		if protocol == "trojan" {
			if fields["uuid"] != nil || fields["encryption"] != nil {
				return nil, "", "", errInvalidClash
			}
			password, ok := clashStringRequired(fields, "password")
			if !ok {
				return nil, "", "", errInvalidClash
			}
			identity["password"] = password
		} else {
			if fields["password"] != nil {
				return nil, "", "", errInvalidClash
			}
			uuid, ok := clashStringRequired(fields, "uuid")
			if !ok {
				return nil, "", "", errInvalidClash
			}
			identity["uuid"] = strings.ToLower(uuid)
			identity["encryption"] = "none"
		}
	default:
		return nil, "", "", errInvalidClash
	}
	canonical, err := json.Marshal(identity)
	if err != nil {
		return nil, "", "", errors.New("cannot encode Clash node identity")
	}
	sum := sha256.Sum256(canonical)
	sourceKey := "clash-" + hex.EncodeToString(sum[:])
	identity["tag"] = sourceKey
	payload, err := json.Marshal(identity)
	if err != nil {
		return nil, "", "", errors.New("cannot encode Clash node payload")
	}
	return payload, sourceKey, name, nil
}

func clashAllowedFields(fields map[string]*yaml.Node, allowed ...string) bool {
	whitelist := make(map[string]struct{}, len(allowed))
	for _, field := range allowed {
		whitelist[field] = struct{}{}
	}
	for key := range fields {
		if _, ok := whitelist[key]; !ok {
			return false
		}
	}
	return true
}
