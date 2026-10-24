# ADR 0044: Lower legacy CN processName to sing-box process_name on Linux

- Status: Accepted
- Date: 2026-10-06

## Context

ADR 0039 deliberately failed closed when an enabled CN preset group contained the legacy camelCase `processName` field. The fixed 2026 Karing tree imports builder/platform utility files that are absent from that public snapshot, so the exact Linux mapping was not initially provable.

The affected pinned CN groups are:

- `cn.whatsapp`;
- `cn.telegram`;
- `cn.github`.

All three are disabled by default.

Git history preserves the last publicly inspectable builder and platform utility implementation at commit `e3c19f1eb1225dbd48a4862f0983b82d0af8de69`.

## Evidence

The historical `PlatformUtils.isPC()` implementation is explicit:

`Platform.isLinux || Platform.isMacOS || Platform.isWindows`.

In the same historical implementation, the sing-box builder emits process conditions only inside `PlatformUtils.isPC()` and maps:

- `rg.processName` -> native `process_name`;
- `rg.processPath` -> native `process_path`;
- process directories -> native `process_path_regex`.

The builder retains process conditions as another child family of the same logical group used for domain, IP, rule-set, and other conditions.

Therefore the legacy CN `processName` field has an evidence-backed Linux mapping to sing-box `process_name`.

## Decision

The CN Linux lowerer preserves every legacy `processName` value as a `PredicateProcessName` atom.

These atoms remain children of the group's OR expression, matching the evidenced Karing custom-group behavior.

Android `package` values remain omitted on Linux because the same builder emits them only under `Platform.isAndroid`.

A process-only CN rule is valid on Linux. An Android-package-only rule still fails because Linux filtering would leave no matcher.

## Native compiler behavior

The routing compiler already lowers `PredicateProcessName` to sing-box `process_name` and marks the compiled route as requiring process lookup.

The native emitter therefore sets:

`route.find_process = true`

whenever an active CN process predicate exists.

No global process lookup is enabled when no active process predicate requires it.

## Real-core validation

Managed-core integration enables `cn.whatsapp` over the pinned default CN policy and requires the approved core to accept and activate the generated configuration.

The fixture asserts that the generated native configuration contains:

- `find_process: true`;
- `process_name: ["WhatsApp.exe"]`;
- `process_name: ["WhatsApp"]`.

It also verifies the active source-map order keeps WhatsApp at its original CN ordinal position between the earlier Google groups and later Bilibili/domestic/foreign groups.

The fixture proves the pinned core accepts the Linux process-name configuration. Actual process discovery remains subject to the operating system, permissions, and whether the proxied connection exposes a discoverable originating process; absence of runtime process metadata is not converted into a match.

## Consequences

The three process-bearing CN groups no longer fail merely because they contain `processName`.

This supersedes the unresolved-process boundary described in ADR 0039.

Full `cn_preset` capability is still gated by the distribution-ready offline resource/license package. Process-name compatibility is no longer a CN preset blocker.
