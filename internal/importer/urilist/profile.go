package urilist

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	singboximport "github.com/bbbstyyy/karing-tui-v2/internal/importer/singbox"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

const (
	MaxURILineBytes = 16 << 10
	MaxURINodes     = 10000
)

type shadowsocksOutbound struct {
	Type          string `json:"type"`
	Tag           string `json:"tag,omitempty"`
	Server        string `json:"server"`
	ServerPort    uint16 `json:"server_port"`
	Password      string `json:"password"`
	Method        string `json:"method"`
	Plugin        string `json:"plugin,omitempty"`
	PluginOptions string `json:"plugin_opts,omitempty"`
}

func AnalyzeBasicProfile(
	data []byte,
	profileID string,
) (singboximport.ProfileAnalysis, error) {
	if err := profile.ValidateProfileID(profileID); err != nil {
		return singboximport.ProfileAnalysis{}, err
	}
	if len(data) == 0 {
		return singboximport.ProfileAnalysis{}, errors.New("URI-list profile is empty")
	}
	if !utf8.Valid(data) {
		return singboximport.ProfileAnalysis{}, errors.New("URI-list profile is not valid UTF-8")
	}

	sum := sha256.Sum256(data)
	result := singboximport.ProfileAnalysis{
		ProfileID:    profileID,
		SourceSHA256: hex.EncodeToString(sum[:]),
	}
	seen := make(map[string]int)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), MaxURILineBytes)
	lineIndex := -1
	nodeCount := 0
	for scanner.Scan() {
		lineIndex++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		nodeCount++
		if nodeCount > MaxURINodes {
			result.Diagnostics = append(result.Diagnostics, singboximport.Diagnostic{
				Level:   singboximport.DiagnosticError,
				Path:    fmt.Sprintf("lines[%d]", lineIndex),
				Code:    "too_many_nodes",
				Message: fmt.Sprintf("URI-list exceeds %d nodes", MaxURINodes),
			})
			break
		}

		payload, sourceKey, sourceName, err := parseURI(line)
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, singboximport.Diagnostic{
				Level:   singboximport.DiagnosticError,
				Path:    fmt.Sprintf("lines[%d]", lineIndex),
				Code:    "unsupported_or_invalid_uri",
				Message: err.Error(),
			})
			continue
		}
		if prior, exists := seen[sourceKey]; exists {
			result.Diagnostics = append(result.Diagnostics, singboximport.Diagnostic{
				Level: singboximport.DiagnosticError,
				Path:  fmt.Sprintf("lines[%d]", lineIndex),
				Code:  "duplicate_node",
				Message: fmt.Sprintf(
					"URI duplicates the semantic node on lines[%d]",
					prior,
				),
			})
			continue
		}
		seen[sourceKey] = lineIndex

		document, err := json.Marshal(struct {
			Outbounds []json.RawMessage `json:"outbounds"`
		}{
			Outbounds: []json.RawMessage{payload},
		})
		if err != nil {
			return result, fmt.Errorf("marshal canonical URI-list node: %w", err)
		}
		analysis, err := singboximport.AnalyzeBasicProfile(document, profileID)
		if err != nil {
			result.Diagnostics = append(result.Diagnostics, singboximport.Diagnostic{
				Level:   singboximport.DiagnosticError,
				Path:    fmt.Sprintf("lines[%d]", lineIndex),
				Code:    "unsupported_or_invalid_uri",
				Message: err.Error(),
			})
			continue
		}
		if analysis.HasBlockingDiagnostics() || len(analysis.Nodes) != 1 {
			message := "canonical node did not produce exactly one supported node"
			if len(analysis.Diagnostics) != 0 {
				message = analysis.Diagnostics[len(analysis.Diagnostics)-1].Message
			}
			result.Diagnostics = append(result.Diagnostics, singboximport.Diagnostic{
				Level:   singboximport.DiagnosticError,
				Path:    fmt.Sprintf("lines[%d]", lineIndex),
				Code:    "unsupported_or_invalid_uri",
				Message: message,
			})
			continue
		}
		node := analysis.Nodes[0]
		node.Source.SourceKey = sourceKey
		node.Source.SourceName = sourceName
		node.Source.PayloadJSON = append([]byte(nil), payload...)
		result.Nodes = append(result.Nodes, node)
	}
	if err := scanner.Err(); err != nil {
		return result, fmt.Errorf(
			"scan URI-list profile (line limit %d bytes): %w",
			MaxURILineBytes,
			err,
		)
	}
	return result, nil
}

func parseURI(raw string) (json.RawMessage, string, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, "", "", fmt.Errorf("parse URI: %w", err)
	}
	switch strings.ToLower(parsed.Scheme) {
	case "ss":
		return parseShadowsocksSIP002(parsed)
	default:
		return nil, "", "", fmt.Errorf(
			"unsupported URI scheme %q; current URI-list subset supports ss:// only",
			parsed.Scheme,
		)
	}
}

func parseShadowsocksSIP002(
	parsed *url.URL,
) (json.RawMessage, string, string, error) {
	if parsed == nil {
		return nil, "", "", errors.New("Shadowsocks URI is nil")
	}
	if parsed.Opaque != "" ||
		parsed.User == nil ||
		parsed.Hostname() == "" ||
		parsed.Port() == "" ||
		parsed.Path != "" {
		return nil, "", "", errors.New(
			"Shadowsocks URI must use SIP002 ss://BASE64(method:password)@host:port form",
		)
	}
	if _, hasPassword := parsed.User.Password(); hasPassword {
		return nil, "", "", errors.New(
			"Shadowsocks SIP002 userinfo must be one base64url token",
		)
	}
	credentials, err := decodeSIP002UserInfo(parsed.User.Username())
	if err != nil {
		return nil, "", "", fmt.Errorf("decode Shadowsocks SIP002 userinfo: %w", err)
	}
	if !utf8.Valid(credentials) {
		return nil, "", "", errors.New("Shadowsocks credentials are not valid UTF-8")
	}
	method, password, ok := strings.Cut(string(credentials), ":")
	if !ok || method == "" || password == "" {
		return nil, "", "", errors.New(
			"Shadowsocks SIP002 userinfo must decode to non-empty method:password",
		)
	}

	portValue, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || portValue == 0 {
		return nil, "", "", fmt.Errorf("invalid Shadowsocks server port %q", parsed.Port())
	}

	query := parsed.Query()
	for key, values := range query {
		if key != "plugin" {
			return nil, "", "", fmt.Errorf(
				"unsupported Shadowsocks URI query parameter %q",
				key,
			)
		}
		if len(values) != 1 {
			return nil, "", "", fmt.Errorf(
				"Shadowsocks URI query parameter %q must occur once",
				key,
			)
		}
	}
	var plugin, pluginOptions string
	if values, exists := query["plugin"]; exists {
		if len(values) != 1 || values[0] == "" {
			return nil, "", "", errors.New(
				"Shadowsocks plugin query must contain one non-empty value",
			)
		}
		plugin, pluginOptions, _ = strings.Cut(values[0], ";")
		if plugin == "" {
			return nil, "", "", errors.New("Shadowsocks plugin name is empty")
		}
	}

	identity := shadowsocksOutbound{
		Type:          "shadowsocks",
		Server:        parsed.Hostname(),
		ServerPort:    uint16(portValue),
		Password:      password,
		Method:        method,
		Plugin:        plugin,
		PluginOptions: pluginOptions,
	}
	identityJSON, err := json.Marshal(identity)
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal Shadowsocks URI identity: %w", err)
	}
	sum := sha256.Sum256(identityJSON)
	sourceKey := "uri-" + hex.EncodeToString(sum[:])

	payload := identity
	payload.Tag = sourceKey
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal Shadowsocks URI node: %w", err)
	}

	sourceName := parsed.Fragment
	if sourceName == "" {
		sourceName = fmt.Sprintf("%s:%d", parsed.Hostname(), portValue)
	}
	if err := validateSourceName(sourceName); err != nil {
		return nil, "", "", err
	}
	return payloadJSON, sourceKey, sourceName, nil
}

func decodeSIP002UserInfo(value string) ([]byte, error) {
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
	} {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("userinfo is not valid URL-safe base64")
}

func validateSourceName(value string) error {
	if value == "" {
		return errors.New("source name is empty")
	}
	if len(value) > 4096 {
		return errors.New("source name exceeds 4096 bytes")
	}
	if !utf8.ValidString(value) {
		return errors.New("source name is not valid UTF-8")
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("source name contains a control character")
		}
	}
	return nil
}
