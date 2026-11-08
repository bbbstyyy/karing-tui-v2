package urilist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// VLESS share URIs are accepted only for TCP with verified TLS. Flow, Reality,
// WebSocket/gRPC, fingerprint, ALPN, advanced TLS and UDP packet encoding are
// deliberately not modeled; any such field rejects the WHOLE source refresh.
type vlessTLSOutbound struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name,omitempty"`
}

type vlessOutbound struct {
	Type       string           `json:"type"`
	Tag        string           `json:"tag,omitempty"`
	Server     string           `json:"server"`
	ServerPort uint16           `json:"server_port"`
	UUID       string           `json:"uuid"`
	Encryption string           `json:"encryption"`
	Network    string           `json:"network"`
	TLS        vlessTLSOutbound `json:"tls"`
}

// parseVLESSTLSURI converts the strict share URI to the existing sing-box
// basic-node validation model. Nothing in an error may contain decoded UUID,
// userinfo, URL, query values, fragments, or source secrets.
func parseVLESSTLSURI(parsed *url.URL) (json.RawMessage, string, string, error) {
	if parsed == nil || parsed.Opaque != "" || parsed.User == nil ||
		parsed.Hostname() == "" || parsed.Port() == "" ||
		parsed.Path != "" || parsed.RawPath != "" {
		return nil, "", "", errors.New("VLESS URI must use vless://UUID@host:port")
	}
	if _, hasPassword := parsed.User.Password(); hasPassword {
		return nil, "", "", errors.New("VLESS URI userinfo must contain one UUID token")
	}
	uuid, err := canonicalVLESSUUID(parsed.User.Username())
	if err != nil {
		return nil, "", "", err
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, "", "", errors.New("VLESS URI port must be 1..65535")
	}

	params, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return nil, "", "", errors.New("malformed VLESS URI query")
	}
	var sni string
	var hasTLS, hasEncryption bool
	for key, values := range params {
		if len(values) != 1 {
			return nil, "", "", errors.New("VLESS URI query parameters must occur once")
		}
		value := values[0]
		switch key {
		case "type":
			if value != "tcp" {
				return nil, "", "", errors.New("VLESS URI only supports TCP transport")
			}
		case "security":
			if value != "tls" {
				return nil, "", "", errors.New("VLESS URI requires verified TLS, not Reality or plaintext")
			}
			hasTLS = true
		case "encryption":
			if value != "none" {
				return nil, "", "", errors.New("VLESS URI only supports encryption=none")
			}
			hasEncryption = true
		case "sni":
			if value == "" {
				return nil, "", "", errors.New("VLESS URI SNI must not be empty")
			}
			sni = value
		case "allowInsecure":
			if value != "0" && value != "false" {
				return nil, "", "", errors.New("VLESS URI insecure TLS verification is unsupported")
			}
		default:
			return nil, "", "", errors.New("unsupported VLESS URI query parameter")
		}
	}
	if !hasTLS || !hasEncryption {
		return nil, "", "", errors.New("VLESS URI requires explicit security=tls and encryption=none")
	}

	identity := vlessOutbound{
		Type:       "vless",
		Server:     parsed.Hostname(),
		ServerPort: uint16(port),
		UUID:       uuid,
		Encryption: "none",
		Network:    "tcp",
		TLS:        vlessTLSOutbound{Enabled: true, ServerName: sni},
	}
	identityJSON, err := json.Marshal(identity)
	if err != nil {
		return nil, "", "", errors.New("cannot marshal VLESS identity")
	}
	sum := sha256.Sum256(identityJSON)
	sourceKey := "uri-" + hex.EncodeToString(sum[:])
	identity.Tag = sourceKey
	payload, err := json.Marshal(identity)
	if err != nil {
		return nil, "", "", errors.New("cannot marshal VLESS node")
	}
	name := parsed.Fragment
	if name == "" {
		name = fmt.Sprintf("%s:%d", parsed.Hostname(), port)
	}
	if err := validateSourceName(name); err != nil {
		return nil, "", "", err
	}
	return payload, sourceKey, name, nil
}

func canonicalVLESSUUID(value string) (string, error) {
	if len(value) != 32 && len(value) != 36 {
		return "", errors.New("VLESS UUID must contain 32 hexadecimal digits")
	}
	if len(value) == 36 {
		for _, pos := range []int{8, 13, 18, 23} {
			if value[pos] != '-' {
				return "", errors.New("VLESS UUID has invalid canonical hyphens")
			}
		}
	}
	digits := strings.ReplaceAll(value, "-", "")
	if len(digits) != 32 {
		return "", errors.New("VLESS UUID must contain 32 hexadecimal digits")
	}
	for _, digit := range digits {
		if !((digit >= '0' && digit <= '9') ||
			(digit >= 'a' && digit <= 'f') ||
			(digit >= 'A' && digit <= 'F')) {
			return "", errors.New("VLESS UUID contains a non-hexadecimal character")
		}
	}
	digits = strings.ToLower(digits)
	return digits[:8] + "-" + digits[8:12] + "-" + digits[12:16] + "-" +
		digits[16:20] + "-" + digits[20:], nil
}
