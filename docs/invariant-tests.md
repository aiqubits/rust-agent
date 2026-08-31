# Architecture invariant to test map

This file is updated with each phase. A test name is listed only after its
implementation exists.

## Phase 0 / 1A

| Contract | Automated evidence |
|---|---|
| Core IDs and recovery keys have canonical, checked encodings | `rust_agent_core::tests::*` |
| Unknown metadata and profile fields fail closed | `metadata::tests::unknown_fields_fail_closed` |
| Lifecycle/provide effects are explicit and bounded by the Component ceiling | `catalog::tests::effects_must_be_accounted` |
| App coexistence is scope-correct and conservative | `catalog::tests::app_coexistence_is_scope_bound` |
| Target facts and predicates are canonical and closed | `target::tests::*` |
| Required closure, disable, security and bounded deterministic backtracking | `resolver::tests::*`, `resolver_properties::*` |
| Same semantic input produces the same composition identity | `generator::tests::regeneration_is_deterministic` |
| Generated source, Cargo and manifest snapshots remain fresh | `generator::tests::minimal_golden_is_fresh` |
| Optional filesystem Component is physically absent/present in real Cargo graph | `generator::tests::selected_packages_match_cargo_tree` |
| Small resolver graphs agree with a brute-force feasibility oracle | `resolver::tests::small_graph_matches_bruteforce_oracle` |
| Host boundary kind/cardinality/target and effect union fail closed | `resolver::tests::host_boundary_cardinality_kind_target_and_effect_union_are_closed`, `resolver::tests::native_host_entry_rejects_mobile_before_cargo` |
| Build requirement kind authorization cannot expand runtime effects | `controlled_policy::build_requirements_need_exact_policy_kind_but_never_expand_runtime_effects` |
| Host feature delta is unit-specific and never relaxes first-party/Host/generated units | `host_feature::tests::*` |
| Product-neutral library graph compiles on the installed target matrix | `target_matrix::product_neutral_library_compile_matrix` |
| Emitted composition compiles in an independent Host and rejects duplicate API identity | `e2e::compose_build_inspect_emit_verify_end_to_end` |
| Development output cannot claim deployability | `e2e::compose_build_inspect_emit_verify_end_to_end` |
| CLI compose/build/inspect/emit/verify workflow | `rust-agent-cli/tests/e2e.rs` |
| Reference repositories and product crates are absent from the dependency graph | `architecture::workspace_has_no_product_dependency` |
