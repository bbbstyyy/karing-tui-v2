# ADR 0249: explicit selected-node snapshot rebind from the TUI Nodes page

Status: **MVP-3 / MV-02 & MV-05 partial only**, not a user acceptance or MVP Beta claim.

## Operator path

A user selects an existing enabled profile on **Profiles [2]**, opens
**Nodes [3]**, moves to a desired, enabled node from the *current accepted*
snapshot, and presses `m` (explicit selected-node replacement). The TUI
validates current profile/snapshot identity, node page bounds, a safe canonical
selected ID, required terminal dimensions (68x16), source list completeness,
and available status. It then opens the existing read-only snapshot Stage
Preview modal with an explicit `replacement_selected_node_id`.

The preview must echo that exact ID and source/declaration revisions,
snapshot identity, 64-character candidate and overlay digests, bounded node
counts, and the fact that neither Core check nor Apply has happened. A
missing/forged ID echo or stale context is **not** permission to stage.
Only `y` on the reviewed preview sends one guarded CAS Stage request with the
same chosen ID. After a receipt, TUI re-reads the durable declaration; it
must observe unchanged ConfigRevision, Applied and LKG before claiming Stage
success. Staging alone never selects a live node or starts a Core transaction.

The operator must separately use **Dashboard [1] → `a`** for compiler
preview and a second explicit checked Core Apply. On the daemon side, the
selected-replacement API implemented in #132 remains limited to an actual
single-profile, first-run proxy-only declaration with no CN preset, custom
routing, URLTest, second profile, or persisted selection intent. This TUI
must not extend that authorization implicitly. A true complex CurrentSelected
migration needs a new separately specified and guarded transaction.

## Safety cases

A stale/different node page or source snapshot, incomplete profile list,
unavailable status, disabled node, ID containing URL syntax/controls,
oversized ID, malformed server preview or receipt, terminal resize,
`Esc`, source revision change or network uncertainty must never stage
implicitly. A late preview is ignored by sequence; a write that may have
reached the daemon is **never** auto-retried. The TUI retains no subscription
URL, imported password, source error or untrusted node display name in the
approval receipt. Selection comes from a validated node ID only.
Unsafe, URL-shaped or control-containing source IDs are masked as
`node-id-hidden` in the Nodes list instead of displaying a secret suffix.

The test suite includes positive TUI Preview → confirmation → readback
and negative stale/disabled/hostile-ID/forged response/resize/late reply
cases. This is TUI state-machine test evidence, **not a physical terminal
keystroke recording or production CN multi-layer rules**.

## Exit boundary

Final head Go format, Vet, test/build, Race 4/4, pinned Managed Core and
native amd64/arm64 Core Provenance must pass before integration. It does not
solve persisted CurrentSelected migration, CN 28-group Group/Proxy DNS
production parity, CN resource redistribution license/`geoip:bing`, #59
real restore, 72h durability or offline dual-arch installation. `main`
remains unchanged.
