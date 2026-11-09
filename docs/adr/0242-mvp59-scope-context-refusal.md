# ADR 0242: private context-cause labels at inert restore scope admission

Status: MVP-4 / MV-06 diagnostic only; Issue #59 remains OPEN.

The observed intermittent `create_scope` refusal occurred after an expensive
authenticated preflight and private parent inventory. The previous shared
phase marker alone could not distinguish a true context deadline/cancellation
from a test-only injected checkpoint failure. The new narrow helper checks
the already-bounded Stage context both BEFORE and AFTER the `create_scope`
and `scope_before_mkdirat` checkpoints, emitting fixed private labels
`scope_admission_context_deadline`, `scope_admission_context_cancelled`,
or `scope_admission_context_unavailable` only through the existing test
probe. No paths, ciphertext, digests, key material, raw errors, or timestamps
are emitted. Production passes a nil probe and retains the public
`ErrUnsafeInertRestoreCandidate` and zero automatic retries.

Deterministic negative tests distinguish expired deadlines, explicit
cancellation, cancellation inside a checkpoint, and probe-only refusal;
the actual Stage cancellation fixture also checks fixed context evidence.
The helper must not allocate a child scope after the deadline.

This change is **not** a causal fix or proof of the unknown intermittent
`create_scope` failure. It does not authorize recovery, relax inode/lease
safety, or replace T15/T23 VM fault injection. The encrypted-only staging,
old Applied/LKG, and MVP Beta release gates remain unchanged.
