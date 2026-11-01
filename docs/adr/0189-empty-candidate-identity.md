# ADR 0189 — Revalidate empty encrypted candidate inventory identity

Status: draft implementation; CI and release gates remain pending.

## Context

An empty private candidate directory is permitted during incomplete-stage
cleanup. In `inspectInertCandidateFile`, that special case returned before
the final locked-directory pathname/inode check. A same-UID actor ignoring the
advisory flock could rename the scope after inventory inspection. While the
normal ciphertext path already revalidated identity, the empty path did not.

## Decision

For `allowAbsent` and exactly zero entries, re-run the locked directory
path/fd check and require it to match the identity originally leased before
returning success. Move the existing private after-inventory test checkpoint
before this early return so a deterministic rename can be injected. No
additional production callbacks or external API changes.

A Linux regression covers both replacement by a different owner-private
directory and by a symlink, and checks that the original leased inode and
the foreign sentinel remain intact. The unchanged intact empty directory
remains acceptable for the documented cleanup path.

## Limitations

This is a fail-closed additional observation, not an atomic compare-and-unlink
primitive; an uncooperative same-UID process can still race a later pathname
operation. It does not establish the intermittent Issue #59 root cause or
authorize live restore/GC, T15/T23, T20/T25, CN redistribution, or release.
It preserves the Linux no-TUN and no subscription/ISP routing boundaries.
Do not merge before exact-head ordinary CI, Go Race 4/4, Managed Core,
and native Linux amd64/arm64 approved-Core provenance all succeed.
