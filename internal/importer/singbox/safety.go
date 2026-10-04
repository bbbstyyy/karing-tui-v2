package singbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

var ErrPrivilegedNetworkFeature = errors.New("configuration requests a privileged or transparent networking feature")

var forbiddenInboundTypes = map[string]struct{}{
	"tun":      {},
	"tproxy":   {},
	"redirect": {},
}

func ValidateProxyOnlyConfig(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()

	var root map[string]any
	if err := decoder.Decode(&root); err != nil {
		return fmt.Errorf("decode sing-box configuration: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("decode sing-box configuration: multiple JSON values")
		}
		return fmt.Errorf("decode trailing sing-box configuration data: %w", err)
	}

	inbounds, ok := root["inbounds"]
	if !ok {
		return nil
	}
	items, ok := inbounds.([]any)
	if !ok {
		return errors.New("sing-box inbounds must be an array")
	}
	for index, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("sing-box inbound %d must be an object", index)
		}
		typeName, _ := item["type"].(string)
		typeName = strings.ToLower(strings.TrimSpace(typeName))
		if _, forbidden := forbiddenInboundTypes[typeName]; forbidden {
			return fmt.Errorf("%w: inbound %d uses type %q", ErrPrivilegedNetworkFeature, index, typeName)
		}
		for _, key := range []string{"auto_route", "auto_redirect", "set_system_proxy"} {
			if enabled, _ := item[key].(bool); enabled {
				return fmt.Errorf("%w: inbound %d enables %s", ErrPrivilegedNetworkFeature, index, key)
			}
		}
	}
	return nil
}
