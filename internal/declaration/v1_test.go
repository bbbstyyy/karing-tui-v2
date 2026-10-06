package declaration

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const testSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestValidateV1AcceptsMinimalCompilableDeclaration(t *testing.T) {
	document := minimalDeclaration()
	if err := ValidateV1(document); err != nil {
		t.Fatal(err)
	}
	model, err := ParseV1(document)
	if err != nil {
		t.Fatal(err)
	}
	if model.LogLevel != "warn" || len(model.Nodes) != 1 || model.Routing.Final.Kind != domain.TargetDirect {
		t.Fatalf("unexpected model: %+v", model)
	}
}

func TestNativeCompilerBuildsArtifactFromV1(t *testing.T) {
	engine, err := NewNativeCompiler(NativeCompilerOptions{
		Inbounds:       domain.DefaultInboundSet(),
		ControlAddress: netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:  testSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := engine.CompileDeclaration(context.Background(), minimalDeclaration())
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Manifest.SchemaID != compiler.NativeSchemaID || artifact.SHA256 == "" {
		t.Fatalf("unexpected artifact identity: %+v", artifact.Manifest)
	}
	if len(artifact.Manifest.InboundTags) != 3 || len(artifact.Manifest.OutboundTags) != 3 {
		t.Fatalf("unexpected manifest closure: %+v", artifact.Manifest)
	}
	if artifact.Manifest.DeclarationRevision != 0 || artifact.Manifest.DeclarationSHA256 != "" {
		t.Fatalf("schema compiler must not self-bind declaration provenance: %+v", artifact.Manifest)
	}
}

func TestValidateV1RejectsUnknownFields(t *testing.T) {
	document := strings.Replace(string(minimalDeclaration()), `"log_level":"warn"`, `"log_level":"warn","unexpected":true`, 1)
	if err := ValidateV1([]byte(document)); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("unknown field error = %v", err)
	}
}

type fakeRuleSetResolver struct {
	path   string
	err    error
	calls  int
	sha    string
	format string
}

func (r *fakeRuleSetResolver) ResolveRuleSet(_ context.Context, sha, format string) (string, error) {
	r.calls++
	r.sha = sha
	r.format = format
	if r.err != nil {
		return "", r.err
	}
	return r.path, nil
}

func TestValidateV1RequiresMetadataForActiveRuleSet(t *testing.T) {
	document := declarationWithRuleSet("", false)
	if err := ValidateV1(document); !errors.Is(err, ErrRuleSetResourceMissing) {
		t.Fatalf("missing rule-set metadata error = %v", err)
	}
}

func TestValidateV1AcceptsImmutableRuleSetMetadata(t *testing.T) {
	hash := strings.Repeat("a", 64)
	if err := ValidateV1(declarationWithRuleSet(hash, true)); err != nil {
		t.Fatal(err)
	}
}

func TestNativeCompilerResolvesAndBindsRuleSetResource(t *testing.T) {
	hash := strings.Repeat("a", 64)
	path := "/state/core/rule-sets/sha256/" + hash + ".json"
	resolver := &fakeRuleSetResolver{path: path}
	engine, err := NewNativeCompiler(NativeCompilerOptions{
		Inbounds:       domain.DefaultInboundSet(),
		ControlAddress: netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:  testSecret,
		RuleSets:       resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := engine.CompileDeclaration(context.Background(), declarationWithRuleSet(hash, true))
	if err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 || resolver.sha != hash || resolver.format != "source" {
		t.Fatalf("unexpected resolver call: %+v", resolver)
	}
	if len(artifact.Manifest.RuleSets) != 1 {
		t.Fatalf("manifest rule-set closure = %+v", artifact.Manifest.RuleSets)
	}
	got := artifact.Manifest.RuleSets[0]
	if got.Ref != "geosite:cn" || got.SHA256 != hash || got.Format != compiler.RuleSetFormatSource || got.RuntimePath != path {
		t.Fatalf("unexpected manifest rule-set: %+v", got)
	}
}

func TestNativeCompilerFailsClosedWhenRuleSetResolverIsUnavailable(t *testing.T) {
	hash := strings.Repeat("a", 64)
	engine, err := NewNativeCompiler(NativeCompilerOptions{
		Inbounds:       domain.DefaultInboundSet(),
		ControlAddress: netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:  testSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.CompileDeclaration(context.Background(), declarationWithRuleSet(hash, true)); !errors.Is(err, ErrRuleSetResourceUnavailable) {
		t.Fatalf("missing resolver error = %v", err)
	}
}

func TestValidateV1RoutingLayerSwitchDefaultsEnabled(t *testing.T) {
	model, err := ParseV1(minimalDeclaration())
	if err != nil {
		t.Fatal(err)
	}
	for _, layer := range []domain.RoutingLayer{
		domain.LayerCustom,
		domain.LayerGeoSite,
		domain.LayerGeoIP,
		domain.LayerACL,
		domain.LayerFinal,
	} {
		if !model.Routing.Layers.Enabled(layer) {
			t.Fatalf("omitted routing layer switch disabled %q", layer)
		}
	}
}

func TestValidateV1DisabledLayerDoesNotRequireRuleSetClosure(t *testing.T) {
	document := string(declarationWithRuleSet("", false))
	document = strings.Replace(
		document,
		`"routing":{`,
		`"routing":{
    "custom_enabled":false,`,
		1,
	)
	if err := ValidateV1([]byte(document)); err != nil {
		t.Fatalf("disabled custom layer unexpectedly required active rule-set closure: %v", err)
	}
	model, err := ParseV1([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	if model.Routing.Layers.Enabled(domain.LayerCustom) {
		t.Fatal("custom layer remained enabled after explicit false switch")
	}
	if !model.Routing.Custom[0].Binding.Enabled {
		t.Fatal("layer switch rewrote persisted group enabled state")
	}

	engine, err := NewNativeCompiler(NativeCompilerOptions{
		Inbounds:       domain.DefaultInboundSet(),
		ControlAddress: netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:  testSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := engine.CompileDeclaration(context.Background(), []byte(document))
	if err != nil {
		t.Fatal(err)
	}
	if len(artifact.Manifest.RuleSets) != 0 {
		t.Fatalf("disabled layer leaked rule-set closure: %+v", artifact.Manifest.RuleSets)
	}
	if len(artifact.SourceMap) != 1 || !artifact.SourceMap[0].Final {
		t.Fatalf("disabled layer leaked route source map entries: %+v", artifact.SourceMap)
	}
}

func TestValidateV1RejectsUnresolvedNodeReference(t *testing.T) {
	document := strings.Replace(string(minimalDeclaration()), `"node_id":"n1"`, `"node_id":"missing"`, 2)
	if err := ValidateV1([]byte(document)); !errors.Is(err, ErrInvalidDocument) {
		t.Fatalf("unresolved node error = %v", err)
	}
}

func declarationWithRuleSet(hash string, includeResource bool) []byte {
	document := string(minimalDeclaration())
	if includeResource {
		document = strings.Replace(
			document,
			`"log_level":"warn",`,
			`"log_level":"warn",
  "rule_sets":[{"ref":"geosite:cn","sha256":"`+hash+`","format":"source"}],`,
			1,
		)
	}
	document = strings.Replace(
		document,
		`"routing":{
    "custom":[]`,
		`"routing":{
    "custom":[{"id":"rs","order":1,"enabled":true,"target":{"kind":"direct"},"match":{"op":"atom","predicate":{"kind":"rule_set","value":"geosite:cn"}}}]`,
		1,
	)
	return []byte(document)
}

func minimalDeclaration() []byte {
	return []byte(`{
  "schema_version":1,
  "log_level":"warn",
  "nodes":[{
    "profile_id":"p1",
    "node_id":"n1",
    "type":"http",
    "server":"127.0.0.1",
    "port":9,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{"kind":"specific_node","profile_id":"p1","node_id":"n1"}],
      "default":{"kind":"specific_node","profile_id":"p1","node_id":"n1"}
    },
    "custom":[]
  },
  "routing":{
    "custom":[],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":{"kind":"direct"}
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
