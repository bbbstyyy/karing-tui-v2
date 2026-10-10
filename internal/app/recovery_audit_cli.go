package app

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
)

type recoveryAuditClient interface {
	RecoveryAudit(context.Context) (apiv1.RecoveryAuditResponse, error)
}

// No "restore" or "--confirm" variant exists. A successful metadata audit
// does not become a token authorizing a core replacement.
func runRecoveryAuditCLI(ctx context.Context, api recoveryAuditClient, args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: karing-tui config recovery-audit (read-only; no rollback)")
		return 2
	}
	bounded, cancel := context.WithTimeout(ctx, 29*time.Second)
	defer cancel()
	result, err := api.RecoveryAudit(bounded)
	if err != nil {
		fmt.Fprintln(stderr, "recovery audit unavailable or changed; inspect daemon status and retry the read")
		return 1
	}
	if !validRecoveryAudit(result) {
		fmt.Fprintln(stderr, "invalid or untrusted generation audit response")
		return 1
	}
	return printJSON(stdout, stderr, result)
}

func validRecoveryAudit(result apiv1.RecoveryAuditResponse) bool {
	if result.APIVersion != apiv1.Version ||
		result.Evidence != "committed_generation_history_and_retained_storage" ||
		result.RestoreSupported || len(result.Generations) > 12 ||
		(result.AppliedGenerationID != nil && *result.AppliedGenerationID <= 0) ||
		(result.LastKnownGoodGenerationID != nil && *result.LastKnownGoodGenerationID <= 0) {
		return false
	}
	seen := make(map[int64]bool, len(result.Generations))
	var previousRevision uint64
	for i, gen := range result.Generations {
		if gen.GenerationID <= 0 || gen.CommittedConfigRevision == 0 ||
			gen.RestoreReady || seen[gen.GenerationID] ||
			(gen.StoredIntegrityVerified && !gen.PayloadRetained) ||
			(gen.RuleSetResourcesVerified && !gen.StoredIntegrityVerified) ||
			(gen.DeclarationRevision != 0 && !gen.StoredIntegrityVerified) ||
			(gen.RuleSetCount < 0 || gen.RuleSetCount > 128) ||
			(i > 0 && gen.CommittedConfigRevision > previousRevision) {
			return false
		}
		switch gen.PreflightStatus {
		case "", "not_checked", "state_not_quiescent", "selector_incompatible", "runtime_policy_incompatible", "bound_state_consistent_only":
		default:
			return false
		}
		if gen.Status != "stored_integrity_verified_only" && gen.PreflightStatus != "" && gen.PreflightStatus != "not_checked" {
			return false
		}
		switch gen.Status {
		case "payload_pruned":
			if gen.PayloadRetained || gen.StoredIntegrityVerified {
				return false
			}
		case "payload_unavailable", "payload_hash_or_json_invalid",
			"manifest_or_provenance_invalid", "declaration_unavailable_or_invalid":
			if !gen.PayloadRetained || gen.StoredIntegrityVerified {
				return false
			}
		case "rule_set_resources_unverified":
			if !gen.StoredIntegrityVerified || gen.RuleSetResourcesVerified {
				return false
			}
		case "stored_integrity_verified_only":
			if !gen.StoredIntegrityVerified || !gen.RuleSetResourcesVerified {
				return false
			}
		default:
			return false
		}
		seen[gen.GenerationID] = true
		previousRevision = gen.CommittedConfigRevision
	}
	return true
}

var _ recoveryAuditClient = (*client.Client)(nil)
