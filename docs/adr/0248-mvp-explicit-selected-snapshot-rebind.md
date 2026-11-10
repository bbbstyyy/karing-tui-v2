# ADR 0248: explicit selected-node rebind in a simple first-run declaration

Status: MVP-1A / MV-02 / MV-05 **partial**, not MVP Beta.

If an accepted subscription snapshot removes the currently selected node, ordinary Preview and Stage continue to refuse it. An operator can supply an exact replacement-selected-node-id from that accepted snapshot on BOTH the protected profiles preview and stage API/CLI commands. The chosen stable ID, source and declaration revisions, snapshot ID, candidate digest and overlay digest bind the approval. Stage never applies the Core.

The explicit replacement is restricted to a **single-profile, proxy-only, CurrentSelected-only** declaration with no CN preset, no other route layer, no URLTest and no independent saved selection intent. The existing selection member list and default are replaced together with the snapshot node payloads only when the operator supplies an admitted node. Any other configuration must fail closed rather than invent an implicit migration. Saved live intent is checked again inside the SQLite staging transaction to prevent a race after preview. A rebind receipt is not Core validation; users must separately perform protected checked Apply and verify new generation traffic.

This is a CLI-first incremental feature, not a general migration UI or persisted CurrentSelected migration. CN 28-group parity, real Group/Proxy DNS, licensed assets, restore/#59, 72-hour stability and offline packages remain blockers. No TUN or subscription/ISP routing is added.

This PR also extends the pinned real Core Clash/Trojan TLS test with a second explicit selected default migration: ordinary removed-node staging fails, chosen-node Stage leaves the original Core serving real traffic, and an independent checked Apply activates the new authenticated peer before a later failed refresh/restart. Source URLs and authentication are never exposed by the API. Explicit node IDs are restricted to terminal-safe ASCII (letters, digits, underscore, hyphen, period, colon, at most 128 bytes); URL-shaped IDs are rejected.

The final exact commit must pass format/Vet/unit/build, Race 4/4, pinned managed Core, amd64/arm64 native provenance. Keep Draft until then.