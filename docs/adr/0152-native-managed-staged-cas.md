# ADR 0152 — T24 native managed Core: unapplied declaration versus applied-generation CAS

- **Status:** synthetic T24 **partial** network-none test; not a release/restore/GC authorization.
- **Depends on:** ADR 0149 actual Unix-socket declaration commit/compile/apply, ADR 0150 inbound route isolation, ADR 0151 Selected SOCKS5 refusal/recovery.
- **Constraints unchanged:** unprivileged native Linux amd64/arm64, no TUN/network takeover, only private 127.0.0.1 fixtures, original 28 CN groups and five routing layers unchanged, no subscription/ISP routing layer.

## Gap

Earlier native lab runs demonstrated an actual, durable Applied generation and controlled Selected failure recovery. They did not verify a common **operator staging** case while a healthy Core is running: an invalid/untrusted declaration rejected before storage, followed by a syntactically and semantically valid new declaration revision that has **not** been applied. In this state the current declaration revision must be newer than the applied config revision. A stale apply/CAS request must not replace the running generation, restart the Core, or silently alter data-plane behavior.

## Decision and test

Extend the already-approved **fourth** independent per-architecture `docker --network none --cap-drop ALL --security-opt no-new-privileges --user 10001:10001 --read-only` sandbox. Do not add an external network source, new image, CN SRS data or an extra container.

1. Start from the actual production V1 API-committed, compiler-generated, successfully applied **generation 1** and approved, running same-UID Core process. The first healthy→Selected-refusal→recovered sequence from ADR 0151 must pass.
2. Read `GET /v1/declaration/current` and verify the original immutable revision 1 digest. Attempt to POST a synthetic declaration with an unexpected top-level `tun` field using expected declaration revision 1. Demand **HTTP 400** with an error and prove the head SHA/revision did not advance.
3. Create a defensive-copy **revision 2 changing only `log_level: warn → error`**. All proxy servers, DNS, inbounds, routes, profile IDs and identifiers must remain exactly localhost-only. Commit this valid declaration through the actual Unix API, requiring HTTP 201, monotonic revision and a distinct SHA; GET current must read back the exact candidate.
4. Independently compile revision 2 over the real Unix API. Require source SHA/revision 2, no SRS, positive native config SHA distinct from generation 1. **Do not activate it.**
5. Submit `POST /v1/declaration/apply` for revision 2 with intentionally stale **`expected_config_revision=0`** although the real currently applied config revision is 1. Require **HTTP 409**, not a timeout or apparent success. Verify the actual managed status still reports the *same* Core PID, actual Applied and LKG generation 1, config revision 1, desired/running state, recovery false and no active operation.
6. Re-run all three real local SOCKS5 echo paths to prove no direct or selector bypass. Explicitly stop the Core. Restart the real Daemon using **the same private disposable SQLite** and require declaration head SHA/revision 2 is preserved but applied revision/generation 1 remains authoritative. Explicitly start **that** Core generation and repeat ADR 0151's route and failure/recovery probes, then stop cleanly. Do not apply revision 2 or automatically repair divergence.
7. Add fast no-network Python regressions: source stays immutable, staged candidate cannot change DNS/route/node/TUN, revision 2 does not confer Core authority, LKG/PID/revision/recovery/active-operation drifts reject, invalid 400 rejection and stale 409 conflict must be observed, and nothing opens an off-host socket.

This demonstrates only **normal staging and pre-activation stale CAS refusal** for a controlled synthetic declaration. It does not inject disk/power interruption during activation, genuine rollback, applied generation 2, CN SRS rule loading, real DNS/remote proxies, offline tar distribution, provider license clearance, HMAC/credential restore, 72h/7d/30d soak, T15/T23/T24/T25 acceptance or final release. Maintain `core_distribution=false`, `cn_preset_offline_bundle=false`, stable `main` and outer Draft PR #1.
