# MVP-1A: bounded snapshot-to-declaration node diff

Status: implementation candidate; not an MVP acceptance claim.

The existing profile declaration preview already computes the exact added,
removed and retained stable NodeID sets, but previously only returned counts.
The preview response now also returns the first 32 IDs per category, in
snapshot/old-declaration order, plus three explicit truncation booleans.
The total counts remain exact. Empty categories serialize as empty arrays.

The response intentionally excludes imported display names, source keys,
locations, credentials and candidate JSON. A node ID is a project-generated
identifier, not a human-readable label; operators can inspect the separately
guarded node page for display metadata. The digest acknowledgement and
source/snapshot/overlay/declaration CAS rules remain unchanged. The preview
does not commit a declaration or apply Core; stage still requires the exact
source revision, declaration revision, snapshot and both preview hashes.

This is only a review aid. It does not prove that subscription ingestion,
native Core Check, application, or MV-02 end-to-end proxy traffic works.
Refer to docs/mvp-plan.md MVP-1A and MV-02 for the remaining gates.
