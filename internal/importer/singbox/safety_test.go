package singbox

import (
	"errors"
	"testing"
)

func TestValidateProxyOnlyConfigAllowsMixedInbound(t *testing.T) {
	data := []byte(`{"inbounds":[{"type":"mixed","tag":"rule","listen":"127.0.0.1","listen_port":2080}]}`)
	if err := ValidateProxyOnlyConfig(data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateProxyOnlyConfigRejectsTransparentInbound(t *testing.T) {
	for _, typeName := range []string{"tun", "tproxy", "redirect"} {
		t.Run(typeName, func(t *testing.T) {
			data := []byte(`{"inbounds":[{"type":"` + typeName + `"}]}`)
			err := ValidateProxyOnlyConfig(data)
			if !errors.Is(err, ErrPrivilegedNetworkFeature) {
				t.Fatalf("expected privileged feature error, got %v", err)
			}
		})
	}
}

func TestValidateProxyOnlyConfigRejectsAutoRoute(t *testing.T) {
	data := []byte(`{"inbounds":[{"type":"mixed","auto_route":true}]}`)
	err := ValidateProxyOnlyConfig(data)
	if !errors.Is(err, ErrPrivilegedNetworkFeature) {
		t.Fatalf("expected privileged feature error, got %v", err)
	}
}

func TestValidateProxyOnlyConfigRejectsMultipleJSONValues(t *testing.T) {
	err := ValidateProxyOnlyConfig([]byte(`{} {}`))
	if err == nil {
		t.Fatal("expected error for multiple JSON values")
	}
}
