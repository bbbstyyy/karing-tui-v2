package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

// historicalStoredArtifact is a bounded, original SQLite payload snapshot.
// No native payloads, paths or credentials are returned to API clients.
type historicalStoredArtifact struct {
	id        int64
	artifacts storage.GenerationArtifacts
}

func sameHistoricalPayload(a, b storage.GenerationArtifacts) bool {
	return a.ConfigSHA256 == b.ConfigSHA256 &&
		a.ManifestSHA256 == b.ManifestSHA256 &&
		a.SourceMapSHA256 == b.SourceMapSHA256 &&
		bytes.Equal(a.ConfigJSON, b.ConfigJSON) &&
		bytes.Equal(a.ManifestJSON, b.ManifestJSON) &&
		bytes.Equal(a.SourceMapJSON, b.SourceMapJSON)
}

func historicalPayloadsUnchanged(
	ctx context.Context, store *storage.Store, originals []historicalStoredArtifact,
) bool {
	for _, item := range originals {
		if ctx.Err() != nil {
			return false
		}
		fresh, err := store.GenerationArtifacts(ctx, item.id)
		if err != nil || !sameHistoricalPayload(item.artifacts, fresh) ||
			!auditDigest(fresh.ConfigJSON, fresh.ConfigSHA256, storage.MaxGenerationConfigBytes) ||
			!auditDigest(fresh.ManifestJSON, fresh.ManifestSHA256, storage.MaxGenerationMetadataBytes) ||
			!auditDigest(fresh.SourceMapJSON, fresh.SourceMapSHA256, storage.MaxGenerationMetadataBytes) {
			return false
		}
	}
	return true
}

type historicalRuleSetPins struct {
	files []*coreartifact.RuleSetPin
}

func (p *historicalRuleSetPins) Close() error {
	if p == nil {
		return nil
	}
	var errs []error
	for _, file := range p.files {
		if err := file.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	p.files = nil
	return errors.Join(errs...)
}

func (p *historicalRuleSetPins) Reverify(ctx context.Context) error {
	if p == nil {
		return ErrHistoricalCheckRejected
	}
	for _, file := range p.files {
		if err := file.Reverify(ctx); err != nil {
			return ErrHistoricalCheckChanged
		}
	}
	return nil
}

// pinHistoricalRuleSets holds no-follow descriptors for the union of the
// historical target, applied generation and LKG closures. All manifest paths
// must be exactly inside the private known content-addressed store; no
// caller-provided relative/arbitrary file paths are opened. The global byte
// and descriptor limits apply to the union, with duplicates counted once.
func pinHistoricalRuleSets(
	ctx context.Context, stateRoot string, artifacts []historicalStoredArtifact,
) (_ *historicalRuleSetPins, err error) {
	pins := &historicalRuleSetPins{}
	ok := false
	defer func() {
		if !ok {
			_ = pins.Close()
		}
	}()
	seen := map[string]bool{}
	remaining := maxRecoveryAuditRuleBytes
	for _, item := range artifacts {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var manifest compiler.NativeManifest
		if json.Unmarshal(item.artifacts.ManifestJSON, &manifest) != nil ||
			manifest.SchemaID != compiler.NativeSchemaID ||
			manifest.ConfigSHA256 != item.artifacts.ConfigSHA256 ||
			manifest.ValidateDeclarationBinding(true) != nil ||
			len(manifest.RuleSets) > maxRecoveryAuditedRuleSets {
			return nil, ErrHistoricalCheckRejected
		}
		for _, rule := range manifest.RuleSets {
			if !validRouteEditSHA(rule.SHA256) || rule.RuntimeTag == "" ||
				rule.Ref == "" || len(seen) >= maxRecoveryAuditedRuleSets && !seen[rule.RuntimePath] {
				return nil, ErrHistoricalCheckRejected
			}
			var ext string
			switch rule.Format {
			case compiler.RuleSetFormatSource:
				ext = ".json"
			case compiler.RuleSetFormatBinary:
				ext = ".srs"
			default:
				return nil, ErrHistoricalCheckRejected
			}
			if stateRoot == "" || !filepath.IsAbs(stateRoot) ||
				rule.RuntimePath != filepath.Join(stateRoot, "core", "rule-sets", "sha256", rule.SHA256+ext) {
				return nil, ErrHistoricalCheckRejected
			}
			if seen[rule.RuntimePath] {
				continue
			}
			pin, pinErr := coreartifact.PinRuleSet(rule.RuntimePath, rule.SHA256)
			if pinErr != nil {
				return nil, ErrHistoricalCheckRejected
			}
			pins.files = append(pins.files, pin)
			seen[rule.RuntimePath] = true
			if pin.Size() > remaining {
				return nil, ErrHistoricalCheckRejected
			}
			remaining -= pin.Size()
		}
	}
	ok = true
	return pins, nil
}
