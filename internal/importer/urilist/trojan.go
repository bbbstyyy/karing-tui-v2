package urilist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

// Trojan URI support is intentionally restricted to the common TCP-over-TLS
// subset. Unknown transport, TLS or plugin parameters reject the WHOLE source
// refresh through the caller's blocking diagnostics; they are never ignored.
type trojanTLSOutbound struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name,omitempty"`
}

type trojanOutbound struct {
	Type       string            `json:"type"`
	Tag        string            `json:"tag,omitempty"`
	Server     string            `json:"server"`
	ServerPort uint16            `json:"server_port"`
	Password   string            `json:"password"`
	Network    string            `json:"network"`
	TLS        trojanTLSOutbound `json:"tls"`
}

// parseTrojanTLSURI emits the same basic node representation validated by
// singbox.AnalyzeBasicProfile. Do not include userinfo, URI, query values or
// decoded credentials in errors, diagnostics, logs or API responses.
func parseTrojanTLSURI(parsed *url.URL) (json.RawMessage, string, string, error) {
	if parsed == nil || parsed.Opaque != "" || parsed.User == nil ||
		parsed.Hostname() == "" || parsed.Port() == "" ||
		parsed.Path != "" || parsed.RawPath != "" {
		return nil, "", "", errors.New("Trojan URI must use trojan://PASSWORD@host:port")
	}
	if _, hasPassword := parsed.User.Password(); hasPassword {
		return nil, "", "", errors.New("Trojan URI userinfo must contain a single password token")
	}
	password := parsed.User.Username()
	if password == "" {
		return nil, "", "", errors.New("Trojan URI password must not be empty")
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	if err != nil || port == 0 {
		return nil, "", "", errors.New("Trojan URI port must be 1..65535")
	}

	params, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return nil, "", "", errors.New("malformed Trojan URI query")
	}
	var sni string
	for key, values := range params {
		if len(values) != 1 {
			return nil, "", "", errors.New("Trojan URI query parameters must occur once")
		}
		value := values[0]
		switch key {
		case "type":
			if value != "tcp" {
				return nil, "", "", errors.New("Trojan URI only supports TCP transport")
			}
		case "security":
			if value != "tls" {
				return nil, "", "", errors.New("Trojan URI requires TLS; Reality and other security modes are unsupported")
			}
		case "sni":
			if value == "" {
				return nil, "", "", errors.New("Trojan URI SNI must not be empty")
			}
			sni = value
		case "allowInsecure":
			if value != "0" && value != "false" {
				return nil, "", "", errors.New("Trojan URI insecure TLS verification is unsupported")
			}
		default:
			return nil, "", "", errors.New("unsupported Trojan URI query parameter")
		}
	}

	identity := trojanOutbound{
		Type:       "trojan",
		Server:     parsed.Hostname(),
		ServerPort: uint16(port),
		Password:   password,
		Network:    "tcp",
		TLS:        trojanTLSOutbound{Enabled: true, ServerName: sni},
	}
	identityJSON, err := json.Marshal(identity)
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal Trojan identity: %w", err)
	}
	sum := sha256.Sum256(identityJSON)
	sourceKey := "uri-" + hex.EncodeToString(sum[:])
	identity.Tag = sourceKey
	payload, err := json.Marshal(identity)
	if err != nil {
		return nil, "", "", fmt.Errorf("marshal Trojan node: %w", err)
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
