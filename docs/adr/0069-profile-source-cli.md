# ADR 0069: Explicit, credential-safe profile source CLI

## Status

Accepted.

## Motivation

M3 already has a revisioned daemon API for source creation and manually triggered refresh. The initial terminal CLI only listed profiles and managed node overlays. Users still needed to handcraft Unix-socket HTTP requests to add subscriptions, and a straightforward command-line URL flag would leak token-bearing subscription locations through shell history, process arguments or output.

## Decision

Two new `profiles` subcommands use the daemon's existing guarded API without bypassing its validation or update lease:

- `profiles put <profile-id> --expected-revision=N --stdin`: require explicit source CAS revision (zero only for creation) and explicitly opt into standard-input JSON. Decode exactly one JSON object (maximum 16 KiB), rejecting trailing values and unknown fields. Do not accept source URLs or credentials as CLI flags. The successful response is a safe summary, not the unredacted daemon source specification.
- `profiles refresh <profile-id> --expected-revision=N [--allow-empty]`: require a positive source revision. Default to rejecting an empty update; accepting one must be explicitly requested. Return the accepted snapshot ID, count and up to 32 bounded diagnostic level/code pairs, but not diagnostic messages, source keys, URLs or payload JSON. Errors suppress arbitrary daemon/upstream text to avoid printing credentials.

Put uses a 20-second deadline, refresh a 75-second deadline, with daemon-side 60-second manual refresh and existing network budgets. Format/protocol validation, source revisions, fetch transport policy, update leases and node snapshot acceptance remain daemon-owned.

## Non-goals and fault semantics

These commands do **not** import subscription/ISP routing layers, materialize an unsupported protocol by guessing, implicitly promote accepted nodes into a declaration, modify DNS, restart core, or apply a new generation. Explicit refresh is an immutable profile snapshot operation only. Stale revisions and unsupported imports fail closed, leaving the effective generation unchanged.

## Tests

Fake Unix-socket-client regressions cover required source revisions and stdin confirmation, bounded strict JSON, rejection of trailing/unknown fields, preservation of server-side CAS requests, manual allow-empty confirmation, escaping/removal of untrusted diagnostics and URL-bearing error redaction. Existing daemon tests cover source CRUD and refresh persistence.

## Follow-up

Add a safe explicit snapshot-to-declaration candidate preview and runtime apply workflow. Complete subscription formats, audited CN rule resources and TUI separately before claiming full compatibility.
