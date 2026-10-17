package apiv1

// ValidRecoveryAudit validates non-authorizing recovery inventory responses.
// Neither a valid response nor a retained generation authorizes restoration.
func ValidRecoveryAudit(result RecoveryAuditResponse) bool {
	if result.APIVersion != Version ||
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
