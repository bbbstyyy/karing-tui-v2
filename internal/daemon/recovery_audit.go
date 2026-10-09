package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

const maxRecoveryAuditedGenerations = 12
const maxRecoveryAuditedRuleSets = 128
const maxRecoveryAuditRuleBytes = int64(128 << 20)

var ErrRecoveryAuditChanged = errors.New("recovery audit state changed")

// recoveryAudit is read-only evidence, NOT a pre-authorization for replaying
// an old native core config or user-initiated rollback. Confirmed history can
// outlive generation payloads under the disk retention policy.
func recoveryAudit(ctx context.Context, store *storage.Store, stateRoot string) (apiv1.RecoveryAuditResponse, error) {
	if store == nil {
		return apiv1.RecoveryAuditResponse{}, errors.New("state unavailable")
	}
	before, err := store.Snapshot(ctx)
	if err != nil {
		return apiv1.RecoveryAuditResponse{}, err
	}
	head, err := store.CurrentDeclaration(ctx)
	if err != nil {
		return apiv1.RecoveryAuditResponse{}, err
	}
	refs, truncated, err := store.ConfirmedGenerationRefs(ctx, maxRecoveryAuditedGenerations)
	if err != nil {
		return apiv1.RecoveryAuditResponse{}, err
	}
	result := apiv1.RecoveryAuditResponse{
		APIVersion:                 apiv1.Version,
		Evidence:                   "committed_generation_history_and_retained_storage",
		ConfigRevision:             before.Revision,
		CurrentDeclarationRevision: head.Revision,
		AppliedGenerationID:        before.AppliedGenerationID,
		LastKnownGoodGenerationID:  before.LastKnownGoodGenerationID,
		RecoveryRequired:           before.RecoveryRequired,
		ActiveApply:                before.ActiveAttemptID != nil,
		Truncated:                  truncated,
		RestoreSupported:           false,
		Generations:                make([]apiv1.RecoveryGenerationAudit, 0, len(refs)),
	}
	bytesRemaining := maxRecoveryAuditRuleBytes
	for _, ref := range refs {
		if err := ctx.Err(); err != nil {
			return apiv1.RecoveryAuditResponse{}, err
		}
		item := apiv1.RecoveryGenerationAudit{
			GenerationID:            ref.GenerationID,
			CommittedConfigRevision: ref.TargetConfigRevision,
			Applied:                 before.AppliedGenerationID != nil && *before.AppliedGenerationID == ref.GenerationID,
			LastKnownGood:           before.LastKnownGoodGenerationID != nil && *before.LastKnownGoodGenerationID == ref.GenerationID,
			PayloadRetained:         ref.PayloadRetained,
			Status:                  "payload_pruned",
			RestoreReady:            false,
		}
		if ref.PayloadRetained {
			item = inspectRetainedGeneration(ctx, store, stateRoot, item, &bytesRemaining)
		}
		result.Generations = append(result.Generations, item)
	}
	// This is still a point-in-time report, not a durable lease. Reject a
	// concurrent new apply or declaration head so the report is not a mix.
	after, err := store.Snapshot(ctx)
	if err != nil || after.Revision != before.Revision ||
		!sameGenerationID(after.AppliedGenerationID, before.AppliedGenerationID) ||
		!sameGenerationID(after.LastKnownGoodGenerationID, before.LastKnownGoodGenerationID) ||
		!sameGenerationID(after.ActiveAttemptID, before.ActiveAttemptID) ||
		after.RecoveryRequired != before.RecoveryRequired {
		return apiv1.RecoveryAuditResponse{}, ErrRecoveryAuditChanged
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil || current.Revision != head.Revision || current.SHA256 != head.SHA256 {
		return apiv1.RecoveryAuditResponse{}, ErrRecoveryAuditChanged
	}
	return result, nil
}

func auditDigest(data []byte, expected string, maxSize int) bool {
	if len(data) == 0 || len(data) > maxSize || !validRouteEditSHA(expected) {
		return false
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) == expected
}

func inspectRetainedGeneration(
	ctx context.Context, store *storage.Store, stateRoot string,
	item apiv1.RecoveryGenerationAudit, bytesRemaining *int64,
) apiv1.RecoveryGenerationAudit {
	item.Status = "payload_unavailable"
	artifacts, err := store.GenerationArtifacts(ctx, item.GenerationID)
	if err != nil {
		return item
	}
	if !auditDigest(artifacts.ConfigJSON, artifacts.ConfigSHA256, storage.MaxGenerationConfigBytes) ||
		!auditDigest(artifacts.ManifestJSON, artifacts.ManifestSHA256, storage.MaxGenerationMetadataBytes) ||
		!auditDigest(artifacts.SourceMapJSON, artifacts.SourceMapSHA256, storage.MaxGenerationMetadataBytes) ||
		!json.Valid(artifacts.ConfigJSON) || !json.Valid(artifacts.SourceMapJSON) {
		item.Status = "payload_hash_or_json_invalid"
		return item
	}
	var manifest compiler.NativeManifest
	if err := json.Unmarshal(artifacts.ManifestJSON, &manifest); err != nil ||
		manifest.SchemaID != compiler.NativeSchemaID ||
		manifest.ConfigSHA256 != artifacts.ConfigSHA256 ||
		manifest.ValidateDeclarationBinding(true) != nil ||
		len(manifest.RuleSets) > maxRecoveryAuditedRuleSets {
		item.Status = "manifest_or_provenance_invalid"
		return item
	}
	decl, err := store.Declaration(ctx, manifest.DeclarationRevision)
	if err != nil || !auditDigest(decl.DocumentJSON, decl.SHA256, storage.MaxDeclarationBytes) ||
		decl.SHA256 != manifest.DeclarationSHA256 {
		item.Status = "declaration_unavailable_or_invalid"
		return item
	}
	if _, err := declaration.ParseV1(decl.DocumentJSON); err != nil {
		item.Status = "declaration_unavailable_or_invalid"
		return item
	}
	item.StoredIntegrityVerified = true
	item.DeclarationRevision = manifest.DeclarationRevision
	item.RuleSetCount = len(manifest.RuleSets)
	item.Status = "rule_set_resources_unverified"
	if !auditRuleSetResources(ctx, stateRoot, manifest.RuleSets, bytesRemaining) {
		return item
	}
	item.RuleSetResourcesVerified = true
	item.Status = "stored_integrity_verified_only"
	// Intentionally false: stored bytes and resource checks are insufficient
	// to establish runtime compatibility, selector binding and restore CAS.
	return item
}

func auditRuleSetResources(ctx context.Context, stateRoot string, rules []compiler.NativeRuleSetManifest, bytesRemaining *int64) bool {
	if len(rules) == 0 {
		return true
	}
	if bytesRemaining == nil || *bytesRemaining <= 0 || stateRoot == "" || !filepath.IsAbs(stateRoot) {
		return false
	}
	root := filepath.Join(stateRoot, "core", "rule-sets", "sha256")
	seen := make(map[string]bool, len(rules))
	for _, rule := range rules {
		if err := ctx.Err(); err != nil {
			return false
		}
		if !validRouteEditSHA(rule.SHA256) || rule.Ref == "" || rule.RuntimeTag == "" ||
			seen[rule.RuntimeTag] {
			return false
		}
		seen[rule.RuntimeTag] = true
		extension := ""
		switch rule.Format {
		case compiler.RuleSetFormatSource:
			extension = ".json"
		case compiler.RuleSetFormatBinary:
			extension = ".srs"
		default:
			return false
		}
		// Only inspect the known private content-addressed store. Do not open
		// an arbitrary path supplied by stored manifest bytes.
		expected := filepath.Join(root, rule.SHA256+extension)
		if rule.RuntimePath != expected {
			return false
		}
		// A conservative total disk-I/O budget prevents an operator audit
		// of many retained generations from repeatedly hashing huge files.
		// The existing verifier independently enforces private ownership,
		// regular file, no final-symlink and the expected content digest.
		info, err := os.Lstat(expected)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 ||
			info.Size() > coreartifact.MaxRuleSetUploadBytes ||
			info.Size() > *bytesRemaining {
			return false
		}
		if coreartifact.VerifyRuleSet(expected, rule.SHA256) != nil {
			return false
		}
		*bytesRemaining -= info.Size()
	}
	return true
}

func registerRecoveryAuditRoutes(mux *http.ServeMux, store *storage.Store, stateRoot string) {
	mux.HandleFunc("GET /v1/config/recovery/audit", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		result, err := recoveryAudit(ctx, store, stateRoot)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, ErrRecoveryAuditChanged) {
				status = http.StatusConflict
			}
			// No raw SQLite, path, source, native JSON or rule-set error text.
			writeJSON(w, status, apiv1.ErrorResponse{
				Error: "recovery audit unavailable or state changed; retry read-only audit later",
			})
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
}
