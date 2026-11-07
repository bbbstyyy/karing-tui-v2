# ADR 0223: MVP checked apply must read back durable provenance

Status: MVP-1B implementation candidate; **not** MV-02 acceptance.

The existing checked apply already binds a confirmed current declaration,
configuration revision, applied generation and selector revision to a native
compiler hash, then requests Check -> Activate -> Verify -> CommitApplied through
the bounded ApplyCoordinator. Its response previously trusted the coordinator
return without reading the persisted state back.

Before returning Applied=true, the handler now re-reads the daemon state's
config revision, applied and last-known-good generation pointers, recovery and
active-attempt status; the committed journal entry; and the exact persisted
generation config, manifest and source-map SHA-256 values. The manifest must
bind the declaration revision/SHA and the confirmed native config SHA. Failed
readback is **uncertain**, not success: return a sanitized HTTP 502, do not
auto-retry, do not initiate speculative rollback, and instruct the operator to
inspect status/recovery. Readback is bounded for five seconds independently of
the completed core transition and client disconnection.

Test scope:
- Existing checked apply tests still cover Check/Activate/Verify, stale receipt,
  conflict, rollback and secret-safe error responses.
- New tests exercise the full local accepted sing-box snapshot -> preview ->
  acknowledged declaration stage -> checked apply preview/confirm -> committed
  provenance path with a deterministic fake Core.
- Mutation tests reject changes to the applied/LKG pointers, config revision,
  pending journal, journal phase, persisted config/source-map and manifest
  declaration identity, including manifest data with a recomputed hash.

This does not prove native live SOCKS5/HTTP proxy traffic or the persisted Core
process identity. MVP-1C must still run local controlled traffic with the pinned
real Core, and MVP-2 must resolve the full CN rule-resource closure. No TUN,
no subscription/ISP route integration, no recovery authorization and no stable
main changes.
