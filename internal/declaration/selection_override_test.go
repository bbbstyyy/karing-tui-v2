package declaration

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestNativeCompilerCurrentSelectionOverrideChangesSelectorDefault(t *testing.T) {
	engine, err := NewNativeCompiler(NativeCompilerOptions{
		Inbounds:       domain.DefaultInboundSet(),
		ControlAddress: netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:  testSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	target := domain.TargetRef{
		Kind:      domain.TargetSpecificNode,
		ProfileID: "p1",
		NodeID:    "n2",
	}
	artifact, err := engine.CompileDeclarationWithCurrentSelection(
		context.Background(),
		selectionOverrideDeclaration(),
		target,
	)
	if err != nil {
		t.Fatal(err)
	}

	catalog, err := compiler.NewTargetCatalog(nil, []compiler.NodeTargetKey{
		{ProfileID: "p1", NodeID: "n1"},
		{ProfileID: "p1", NodeID: "n2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantDefault := catalog.NodeTags[compiler.NodeTargetKey{ProfileID: "p1", NodeID: "n2"}]

	var native struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(artifact.JSON, &native); err != nil {
		t.Fatal(err)
	}
	for _, outbound := range native.Outbounds {
		if outbound["tag"] != compiler.CurrentSelectedOutboundTag {
			continue
		}
		if outbound["type"] != "selector" {
			t.Fatalf("CurrentSelected native type = %#v", outbound["type"])
		}
		if outbound["default"] != wantDefault {
			t.Fatalf("CurrentSelected default = %#v, want %q", outbound["default"], wantDefault)
		}
		return
	}
	t.Fatalf("CurrentSelected outbound %q not found", compiler.CurrentSelectedOutboundTag)
}

func TestNativeCompilerCurrentSelectionOverrideRejectsNonMember(t *testing.T) {
	engine, err := NewNativeCompiler(NativeCompilerOptions{
		Inbounds:       domain.DefaultInboundSet(),
		ControlAddress: netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:  testSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = engine.CompileDeclarationWithCurrentSelection(
		context.Background(),
		selectionOverrideDeclaration(),
		domain.TargetRef{
			Kind:      domain.TargetSpecificNode,
			ProfileID: "p1",
			NodeID:    "missing",
		},
	)
	if err == nil {
		t.Fatal("non-member CurrentSelected override unexpectedly compiled")
	}
}

func selectionOverrideDeclaration() []byte {
	return []byte(`{
  "schema_version":1,
  "log_level":"warn",
  "nodes":[{
    "profile_id":"p1",
    "node_id":"n1",
    "type":"http",
    "server":"127.0.0.1",
    "port":10001,
    "http":{}
  },{
    "profile_id":"p1",
    "node_id":"n2",
    "type":"http",
    "server":"127.0.0.1",
    "port":10002,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[
        {"kind":"specific_node","profile_id":"p1","node_id":"n1"},
        {"kind":"specific_node","profile_id":"p1","node_id":"n2"}
      ],
      "default":{"kind":"specific_node","profile_id":"p1","node_id":"n1"}
    },
    "custom":[]
  },
  "routing":{
    "custom":[],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":{"kind":"current_selected"}
  },
  "dns":{
    "profiles":[{
      "id":"outbound",
      "role":"outbound",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":53
    }],
    "outbound_profile_id":"outbound"
  }
}`)
}
