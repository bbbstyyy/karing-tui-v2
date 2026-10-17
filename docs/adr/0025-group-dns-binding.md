# ADR 0025: Compile Group DNS as an explicit resolver and detour binding

- Status: Accepted
- Date: 2026-10-05

## Context

Karing stores an optional DNS-server selection beside an individual diversion group. The project plan requires this Group DNS behavior to remain independent from Direct, Proxy, Outbound, Bootstrap, and Fallback DNS.

The same plan also states that selecting a routing target such as US-Auto does not prove that DNS traffic itself should use US-Auto. The locked Karing repository exposes the saved `dns_servers` choice, but the config-builder implementation that would prove an implicit DNS detour is not present in that source snapshot.

Guessing the detour would make migration observably unsafe.

## Decision

A Group-role `DNSProfile` must declare an explicit `DetourTarget`.

- DIRECT means the DNS transport uses the approved core's native direct dial and therefore emits no `detour` field.
- CurrentSelected, Global URLTest, Custom URLTest, and Specific Node resolve through the stable `TargetCatalog` and become an explicit DNS-server `detour`.
- BLOCK is invalid as a DNS transport detour.
- Non-Group DNS roles may not carry this explicit detour field.

The route group's `DNSProfileID` and the Group profile's detour are separate pieces of state.

## Closure

`CompileRuntimeDNSForRouting` first compiles the existing Outbound/Bootstrap/Direct/Proxy closure, then walks active routing steps in fixed five-layer order.

Only Group profiles referenced by enabled route groups are added. Bootstrap dependencies are emitted first and de-duplicated.

For every active group binding it records:

- group ID;
- DNS profile ID;
- runtime resolver tag;
- explicit detour outbound tag, if any.

Unused Group profiles do not start DNS traffic.

DNS-only detour targets are added to a separate outbound dependency list. `RuntimeOutboundRequirements` merges those with routing outbound dependencies in deterministic first-use order, ensuring selectors, URLTest groups, or nodes needed only by DNS transport are still materialized.

## Route binding

`CompileRouting` preserves `DNSProfileID` in the source map instead of silently dropping it.

`BindGroupDNSRouting` inserts a non-final `resolve(server=<group-dns>)` rule immediately before the group's final route action. The resolve rule copies the original matcher and Rule-inbound scope, so only traffic selected by that group receives the override.

The source map contains both generated rules and keeps the original group/DNS identity.

Group DNS binding runs before Proxy DNS binding. Proxy DNS explicitly skips rules that already carry a Group DNS binding, preventing double resolution with two servers.

## Pre-resolution safety

A Group DNS override can only be selected before DNS when the group matcher itself is pre-resolution safe.

The current conservative gate rejects any matcher containing:

- destination IP CIDR;
- an opaque rule-set predicate.

Those predicates may need resolved destination addresses or may mix IP/domain behavior. Resolving them first with the Group resolver would create a circular classification dependency.

Domain, suffix, keyword, regex, port, network, process, and their explicit boolean combinations remain eligible.

This gate may be relaxed later only when rule-set type metadata and classification DNS are explicit.

## Native validation

The native emitter derives an allowed DNS-detour policy:

- Proxy resolver -> CurrentSelected;
- each Group resolver -> its declared detour.

Any other DNS server carrying a detour is rejected. A Group server whose emitted detour differs from its declared target is rejected.

Every non-empty DNS detour must reference a materialized outbound. Every Group binding must also have a matching source-map resolve/route pair before native JSON can be emitted.

The root DNS final remains the fail-closed REFUSED server.

## Migration consequence

Legacy Karing state that proves the group DNS server but cannot prove the DNS transport detour must not be silently imported as equivalent. The importer must require or derive an explicit policy from a documented preset; otherwise it reports a compatibility diagnostic.

## Still pending

Fallback DNS remains unsupported because its trigger/failover semantics have not yet been frozen. Classification DNS for IP-dependent route rules, encrypted DNS transports, cache policy, and controlled behavior fixtures also remain open.
