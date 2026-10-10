# ADR 0080: Compiler-previewed and confirmed route enabled toggles in the TUI

## Scope

M4 adds one intentionally narrow edit to the Routing inspection screen: choose a displayed existing Custom, GeoSite, GeoIP or ACL group and press \`e\` to preview toggling its \`enabled\` flag, then press \`y\` to stage the immutable declaration revision. \`Esc\` cancels without a write. This is **not core apply** and is not a generic routing/DNS editor.

The existing \`GET /v1/config/inspection\` snapshot is a reconstruction of the *applied declaration*, not packet observation. TUI therefore only offers selectable rows when the full route list is untruncated, \`current_declaration_revision == applied_declaration_revision\`, and no unapplied stage exists. FINAL and derived region-auto entries are never editable. Hostile, control-bearing or URL/credential-shaped group IDs are not saved as mutable UI choices. The configured five-layer routing order is not changed; subscription/ISP sources never become layers.

## Confirmation and consistency

The UI fetches a fresh, non-secret route-edit context and compares declaration revision, config revision and applied-generation identity with the inspection snapshot before sending a preview. It then sends only a single \`enabled\` pointer and the daemon's optimistic declaration SHA and selection revision. The daemon independently validates the existing group, recompiles the transient declaration with resource/DNS/target closure and rechecks authority. The TUI verifies the exact echoed proposal, before/after boolean, unchanged target and DNS binding, immutable preview digests, compiler validation and \`core_validated=false\` before offering confirmation.

A confirmed \`y\` sends one \`route-edit/stage\` request with the two preview digests. The daemon recompiles and performs its existing SQLite declaration CAS. No core restart or declaration apply is triggered. Successful or uncertain stage results both invalidate the old inspection and initiate a fresh inspection. An ambiguous response is never retried automatically; the operator must review the new declaration state. While staging, navigation cannot issue a second mutation. Quitting the TUI never kills or restarts the daemon/core.

## Deliberate limits

All target/DNS binding, rule matching, rule-set edits, multi-group transactions and explicit apply remain separate. Routes whose inspection is truncated or whose current declaration is already staged need the guarded CLI; no stale applied rows may be edited by inference. A compiler preview is not a core check and says nothing about live DNS request paths. Offline CN resource/license closure and the long-running reliability release gates remain outstanding.
