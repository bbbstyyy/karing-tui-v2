# ADR 0247: accepted Clash source is not permission to replace a removed selected node

Status: **MVP-1C/1D, MV-02/MV-05 partial**. This does not constitute MVP Beta acceptance.

## Safety boundary

An ordinary Clash YAML refresh can validly change its proxy inventory without
being eligible for application to the existing routing/selection declaration.
Clash source keys are semantic hashes of supported, normalized transport and
authentication fields (excluding the display name). Renaming a node preserves
its stable NodeID; changing a Trojan endpoint is a different NodeID even when
the display name is unchanged. The project must never infer a replacement
selection or fall back to DIRECT on such a change.

Extend `TestManagedCoreRealMVPImportedClashYAMLTrojanFlow` using one local
HTTP-served Clash source, two independent local authenticated Trojan/TLS peers,
and a pinned real Core. Start with an accepted, applied, TLS-verified selected
node. Then verify:

1. A harmless Clash display-name refresh is accepted as a new immutable
   snapshot, preserves NodeID, and returns a bounded retained-only preview.
2. A valid second refresh changes the endpoint and thus selected NodeID; the
   node list changes and the earlier accepted snapshot becomes stale.
3. The new snapshot cannot be staged against a declaration still selecting
   the removed ID. The guarded Preview and attempted Stage return a safe,
   non-secret incompatibility response; replay of a stale snapshot is refused.
4. Neither accepted snapshot alters the durable declaration, Applied/LKG
   generation, or the running Core. Observed SOCKS5 Rule and Selected traffic
   continues through the original TLS-authenticated peer and never reaches
   the unconfirmed replacement.
5. A later unsupported/insecure Clash refresh is rejected and preserves the
   latest *accepted* snapshot, independently of the still-running older LKG.
   A Core stop/restart continues using the original approved generation.

The test is a deliberate negative security case, not a solution to migration
of removed CurrentSelected references. Updating the explicit selection and
refreshed declaration requires its own guarded user workflow; do not secretly
choose a new node to make a source update apply. Subscription-provided rules,
proxy-groups and DNS remain ignored, and neither TUN nor ISP routing is added.

## Evidence and non-acceptance

Require final-head Go format/Vet/tests/build, all four race shards, actual
execution of `TestManagedCoreRealMVPImportedClashYAMLTrojanFlow` with pinned
Core, and Linux amd64/arm64 Provenance. No Internet or production CN resources
are used. CN Group/Proxy DNS parity, 68-ref license closure including
`geoip:bing`, real restore/#59, 72h stability and offline release remain
unresolved; never mark MV-02/MV-03/MV-04/MV-06/MV-07 or MVP Beta complete
from this test alone.
