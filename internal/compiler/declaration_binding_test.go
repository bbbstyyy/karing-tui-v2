package compiler

import (
	"errors"
	"strings"
	"testing"
)

func TestNativeArtifactDeclarationBindingIsExplicitAndImmutable(t *testing.T) {
	artifact := nativeTestInput(t, "127.0.0.1")
	compiled, err := CompileNativeConfig(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if err := compiled.ValidateDeclarationBinding(true); !errors.Is(err, ErrInvalidDeclarationBinding) {
		t.Fatalf("unbound artifact error = %v", err)
	}
	if err := compiled.ValidateDeclarationBinding(false); err != nil {
		t.Fatalf("unbound artifact should remain valid for compiler-only use: %v", err)
	}

	bound, err := compiled.BindDeclaration(7, strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	if err := bound.ValidateDeclarationBinding(true); err != nil {
		t.Fatal(err)
	}
	if bound.Manifest.DeclarationRevision != 7 ||
		bound.Manifest.DeclarationSHA256 != strings.Repeat("a", 64) {
		t.Fatalf("unexpected declaration provenance: %+v", bound.Manifest)
	}
	if compiled.Manifest.DeclarationRevision != 0 || compiled.Manifest.DeclarationSHA256 != "" {
		t.Fatal("binding mutated original compiler artifact")
	}
}

func TestNativeArtifactDeclarationBindingRejectsMalformedOrTamperedArtifact(t *testing.T) {
	input := nativeTestInput(t, "127.0.0.1")
	compiled, err := CompileNativeConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		revision uint64
		hash     string
	}{
		{revision: 0, hash: strings.Repeat("a", 64)},
		{revision: 1, hash: ""},
		{revision: 1, hash: "bad"},
	} {
		if _, err := compiled.BindDeclaration(tc.revision, tc.hash); !errors.Is(err, ErrInvalidDeclarationBinding) {
			t.Fatalf("binding (%d,%q) error = %v", tc.revision, tc.hash, err)
		}
	}

	tampered := compiled
	tampered.JSON = append([]byte(nil), compiled.JSON...)
	tampered.JSON[len(tampered.JSON)-1] ^= 1
	if _, err := tampered.BindDeclaration(1, strings.Repeat("b", 64)); !errors.Is(err, ErrInvalidDeclarationBinding) {
		t.Fatalf("tampered artifact error = %v", err)
	}
}

func TestNativeManifestDeclarationBindingAllowsLegacyButRejectsPartial(t *testing.T) {
	legacy := NativeManifest{}
	if err := legacy.ValidateDeclarationBinding(false); err != nil {
		t.Fatalf("legacy manifest rejected: %v", err)
	}
	if err := legacy.ValidateDeclarationBinding(true); !errors.Is(err, ErrInvalidDeclarationBinding) {
		t.Fatalf("strict legacy manifest error = %v", err)
	}

	partial := NativeManifest{DeclarationRevision: 3}
	if err := partial.ValidateDeclarationBinding(false); !errors.Is(err, ErrInvalidDeclarationBinding) {
		t.Fatalf("partial manifest error = %v", err)
	}
	valid := NativeManifest{
		DeclarationRevision: 3,
		DeclarationSHA256:   strings.Repeat("c", 64),
	}
	if err := valid.ValidateDeclarationBinding(false); err != nil {
		t.Fatal(err)
	}
}
