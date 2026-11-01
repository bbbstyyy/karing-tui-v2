# ADR 0188 — Anchor encrypted candidate directory inventory to leased fd

Status: draft implementation pending exact-head CI (M5 T15/T23 partial).

## Context

ADR 0186 anchored ciphertext creation and ADR 0187 anchored ciphertext
leaf reads to the locked candidate directory fd. One inventory operation
still reopened the directory by its absolute pathname before calling
ReadDir. It checked the reopened directory identity, which refused many
path substitutions, but unnecessarily depended on mutable pathname
resolution in a trust-sensitive operation.

Reusing ReadDir on the long-lived directory flock descriptor would be
incorrect: subsequent Verify/Discard calls can silently skip entries
because directory stream offsets are shared. A fresh pathname-based
reader avoids offset reuse but reintroduces the substitution boundary.

## Decision

Open an independent directory stream with
`openat(leased_dir_fd, ".", O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)`.
Require that the returned reader fd is a private 0700 directory with
the same inode as the leased directory. Each inspection owns/closes its
fresh reader; the flock fd's directory offset remains untouched.
Maintain the existing final directory path/fd checks, single encrypted
leaf allowlist, UID/0600/one-link checks, and fd-relative ciphertext open.

## Regression evidence

A Linux test obtains a real candidate directory flock, reads the same
single-leaf inventory twice via distinct readers, then renames the
candidate and replaces the canonical path with either another 0700
directory (containing only unrelated data) or a symlink to one.
The reader must still enumerate the **original** inode, while the full
inspection refuses the untrusted path change. Another test refuses a
nil/closed candidate reader.

No modification to user APIs, passwords, backup permissions, cryptography,
source files, backup restoration, TUN, subscription/ISP routing layers,
approved Core or stable main. The entire authenticated preflight remains
path-based; this PR does not claim to eliminate all same-UID races or
resolve Issue #59's intermittent create_scope refusal. All T15/T23 and
release gates stay blocked. Only merge after exact-head ordinary CI,
Go Race 4/4, Managed Core and Linux native amd64/arm64 checks pass.
