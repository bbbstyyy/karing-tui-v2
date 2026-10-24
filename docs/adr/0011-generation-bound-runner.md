# ADR 0011: Bind verified core execution to immutable generation paths

- Status: Accepted
- Date: 2026-10-05

## Context

The core artifact and each generated config are now independently verified, but those checks only become useful if process launch cannot silently switch to a different mutable path.

The supervisor also needs a runner whose configuration can change between immutable generations without changing the executable identity contract.

## Decision

`internal/core.GenerationRunner` holds one verified core executable and one currently bound generation config path.

A generation path may be bound only when it is:

- absolute;
- a regular non-symlink file;
- not readable or writable by group/others.

Every `Start` re-validates the bound config path, constructs the exact argv:

`run -c <generation-config-path>`

and delegates to `VerifiedExecRunner`, which re-verifies the locked core artifact immediately before process creation.

`CheckGenerationConfig` uses the same path validation and artifact verifier and invokes:

`check -c <generation-config-path>`

The check helper has no implicit fallback path and does not search `PATH`.

## Consequences

- A generation that was checked and later activated refers to the same immutable file path.
- Supervisor restart can use the same runner after rebinding it to the confirmed applied generation.
- Rollback can rebind to the immutable previous generation before a supervised restart.
- Artifact verification remains in the start/check hot path instead of being a one-time daemon startup check.
- The daemon still does not automatically launch the core; lifecycle and apply wiring remain separate M1 integration work.
