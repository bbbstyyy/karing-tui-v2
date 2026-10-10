package daemon

import (
	"bytes"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

// These statuses describe bounded, read-only compatibility evidence. They are
// deliberately not restore authorizations, not a core check, and not a lease.
const (
	recoveryPreflightNotChecked        = "not_checked"
	recoveryPreflightStateNotQuiescent = "state_not_quiescent"
	recoveryPreflightSelectorMismatch  = "selector_incompatible"
	recoveryPreflightPolicyMismatch    = "runtime_policy_incompatible"
	recoveryPreflightConsistentOnly    = "bound_state_consistent_only"
)

// historicalGenerationPreflight tests the *current* selector intent against
// the *historical* declaration, not today's staged declaration. An explicit
// stale selector must never silently fall back to the old default. The fixed
// manifest tags are structural evidence only; they do not prove that a live
// core or another binary can run the stored configuration.
func historicalGenerationPreflight(
	document []byte, manifest compiler.NativeManifest, snapshot storage.Snapshot,
	intent storage.SelectionIntent, persisted bool,
) string {
	if snapshot.RecoveryRequired || snapshot.ActiveAttemptID != nil {
		return recoveryPreflightStateNotQuiescent
	}
	model, err := declaration.ParseV1(document)
	if err != nil {
		return recoveryPreflightSelectorMismatch
	}
	target := model.Selection.Current.Default
	if persisted {
		target, err = decodeSelectionTarget(intent.TargetJSON)
		if err != nil {
			return recoveryPreflightSelectorMismatch
		}
	}
	tag, err := declaration.CurrentSelectionRuntimeTag(document, target)
	if err != nil || !hasRecoveryTag(manifest.OutboundTags, tag) {
		return recoveryPreflightSelectorMismatch
	}
	if snapshot.RoutingMode.Validate() != nil ||
		(snapshot.CoreDesiredState != storage.CoreDesiredRunning &&
			snapshot.CoreDesiredState != storage.CoreDesiredStopped) ||
		!hasRecoveryTag(manifest.InboundTags, domain.InboundTagRule) ||
		!hasRecoveryTag(manifest.InboundTags, domain.InboundTagDirect) ||
		!hasRecoveryTag(manifest.InboundTags, domain.InboundTagSelected) ||
		!hasRecoveryTag(manifest.OutboundTags, compiler.DirectOutboundTag) ||
		!hasRecoveryTag(manifest.OutboundTags, compiler.CurrentSelectedOutboundTag) {
		return recoveryPreflightPolicyMismatch
	}
	return recoveryPreflightConsistentOnly
}

func hasRecoveryTag(tags []string, want string) bool {
	if want == "" {
		return false
	}
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

// Re-read all independently mutable bindings after hashing retained rule
// files. This rejects obvious apply, selector, mode and pruning races, but a
// successful read is *still* not a SQLite lock or a future restore lease.
func sameRecoveryAuditSnapshot(before, after storage.Snapshot) bool {
	return before.Revision == after.Revision &&
		sameGenerationID(before.AppliedGenerationID, after.AppliedGenerationID) &&
		sameGenerationID(before.LastKnownGoodGenerationID, after.LastKnownGoodGenerationID) &&
		sameGenerationID(before.ActiveAttemptID, after.ActiveAttemptID) &&
		before.RecoveryRequired == after.RecoveryRequired &&
		before.CoreDesiredState == after.CoreDesiredState &&
		before.RoutingMode == after.RoutingMode &&
		before.PrivateDirect == after.PrivateDirect
}

func sameRecoveryAuditIntent(a storage.SelectionIntent, aPersisted bool, b storage.SelectionIntent, bPersisted bool) bool {
	return aPersisted == bPersisted &&
		a.Revision == b.Revision &&
		a.UpdatedAt.Equal(b.UpdatedAt) &&
		bytes.Equal(a.TargetJSON, b.TargetJSON)
}

func sameRecoveryAuditRefs(a []storage.ConfirmedGenerationRef, aTruncated bool, b []storage.ConfirmedGenerationRef, bTruncated bool) bool {
	if aTruncated != bTruncated || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
