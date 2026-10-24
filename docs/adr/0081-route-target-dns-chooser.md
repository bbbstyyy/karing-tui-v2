# ADR 0081: Bounded Routing target and group DNS binding chooser

## Scope

The M4 Linux-only, unprivileged TUI can now use the existing compiler-backed route-edit protocol for one-field `enabled`, typed `target` or `dns_profile_id` changes. Routing page key `e` previews a toggle, `t` opens a target chooser, `g` opens a group DNS binding chooser. Use `j/k` and Enter to preview; `y` commits a guarded declaration stage, Esc cancels. Staging is **not** core check, apply or restart. FINAL, automatic region entries, matcher expressions, layer order, subscription/ISP routing and raw native core JSON remain uneditable by this UI.

## Candidate safety

Only fully enumerated, unchanged applied declaration inspections authorize edits; an already staged declaration, incomplete routing list, unsafe group IDs or missing applied generation disables edit choices. Target choices consist of DIRECT, BLOCK, CurrentSelected and Global URLTest plus safely validated specific-node/custom URLTest references **already used in the applied route list**. This does not claim a complete inventory of all nodes or groups. Group DNS IDs must be existing role=group profiles in an untruncated DNS list, or an explicit empty/clear binding. BLOCK is incompatible with a non-empty group DNS binding. Group, target and DNS identifiers that might contain secrets or terminal controls cannot be retained in the editable model.

Fresh edit context must still match declaration/config/applied generation, and strict preview must exactly echo the requested one-field change, unchanged adjacent fields and full SHA-256 digests. CN applied inspection origin `cn_preset` maps to the mutation result `cn_preset_override`; rejecting this legitimate rename had prevented earlier CN toggles from being confirmed. The daemon independently compiles and CAS-stages on explicit confirmation. Ambiguous stages are never automatically retried and invalidate the editable snapshot.

Full arbitrary node selection, DNS resolvers, matching AST, multi-group mutations, explicit apply/rollback UX, offline CN resource/license closure and long-duration reliability tests remain release work.
