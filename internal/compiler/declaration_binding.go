package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrInvalidDeclarationBinding = errors.New("invalid declaration binding")

func (a NativeConfigArtifact) BindDeclaration(revision uint64, declarationSHA256 string) (NativeConfigArtifact, error) {
	if err := validateDeclarationBinding(revision, declarationSHA256, true); err != nil {
		return NativeConfigArtifact{}, err
	}
	sum := sha256.Sum256(a.JSON)
	actual := hex.EncodeToString(sum[:])
	if a.SHA256 == "" || actual != a.SHA256 {
		return NativeConfigArtifact{}, fmt.Errorf("%w: artifact config SHA-256 mismatch", ErrInvalidDeclarationBinding)
	}
	if a.Manifest.SchemaID != NativeSchemaID || a.Manifest.ConfigSHA256 != a.SHA256 {
		return NativeConfigArtifact{}, fmt.Errorf("%w: artifact manifest/config identity mismatch", ErrInvalidDeclarationBinding)
	}

	bound := a
	bound.JSON = append([]byte(nil), a.JSON...)
	bound.Manifest = cloneNativeManifest(a.Manifest)
	bound.SourceMap = append([]RouteSourceMapEntry(nil), a.SourceMap...)
	bound.Manifest.DeclarationRevision = revision
	bound.Manifest.DeclarationSHA256 = declarationSHA256
	return bound, nil
}

func (a NativeConfigArtifact) ValidateDeclarationBinding(required bool) error {
	if err := validateDeclarationBinding(
		a.Manifest.DeclarationRevision,
		a.Manifest.DeclarationSHA256,
		required,
	); err != nil {
		return err
	}
	if a.Manifest.DeclarationRevision == 0 {
		return nil
	}
	sum := sha256.Sum256(a.JSON)
	actual := hex.EncodeToString(sum[:])
	if actual != a.SHA256 {
		return fmt.Errorf("%w: config bytes do not match artifact SHA-256", ErrInvalidDeclarationBinding)
	}
	if a.Manifest.SchemaID != NativeSchemaID || a.Manifest.ConfigSHA256 != a.SHA256 {
		return fmt.Errorf("%w: manifest/config identity mismatch", ErrInvalidDeclarationBinding)
	}
	return nil
}

func (m NativeManifest) ValidateDeclarationBinding(required bool) error {
	return validateDeclarationBinding(m.DeclarationRevision, m.DeclarationSHA256, required)
}

func validateDeclarationBinding(revision uint64, declarationSHA256 string, required bool) error {
	if revision == 0 && declarationSHA256 == "" {
		if required {
			return fmt.Errorf("%w: declaration provenance is required", ErrInvalidDeclarationBinding)
		}
		return nil
	}
	if revision == 0 || declarationSHA256 == "" {
		return fmt.Errorf("%w: declaration revision and SHA-256 must be present together", ErrInvalidDeclarationBinding)
	}
	decoded, err := hex.DecodeString(declarationSHA256)
	if err != nil || len(decoded) != sha256.Size {
		return fmt.Errorf("%w: declaration SHA-256 must be 64 hexadecimal characters", ErrInvalidDeclarationBinding)
	}
	return nil
}

func cloneNativeManifest(manifest NativeManifest) NativeManifest {
	clone := manifest
	clone.InboundTags = append([]string(nil), manifest.InboundTags...)
	clone.OutboundTags = append([]string(nil), manifest.OutboundTags...)
	clone.DNSServerTags = append([]string(nil), manifest.DNSServerTags...)
	clone.RuleSets = append([]NativeRuleSetManifest(nil), manifest.RuleSets...)
	return clone
}
