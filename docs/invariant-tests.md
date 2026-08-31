# Architecture invariant to test map

This file is updated with each phase. A test name is listed only after its
implementation exists.

## Phase 0

| Contract | Automated evidence |
|---|---|
| Pinned formatting, compile, lint, test, documentation and dependency-policy gates | `.github/workflows/ci.yml::quality` |
| Reference repositories and product crates are absent from the dependency graph | `architecture::workspace_has_no_product_dependency` |
| Core/shared lifecycle APIs form an effect-free one-way dependency closure and do not import Agent/Session owners | `architecture::api_dependency_direction_is_acyclic`, `architecture::mandatory_api_crates_have_an_exact_effect_free_dependency_closure` |
| Phase 0 exposes no Session public API closure containing an Agent type/dependency; Phase 2 must replace the absence guard with a transitive closure check | `architecture::phase_zero_exposes_no_session_api_with_an_agent_dependency` |
| Core IDs, recovery keys and lifecycle/Session identities have canonical checked encodings | `rust_agent_core::tests::canonical_ids_accept_only_normalized_kebab_case`, `rust_agent_core::tests::capability_prefix_is_checked_once`, `rust_agent_core::tests::digest_hex_round_trip_is_canonical`, `rust_agent_core::tests::recovery_key_checks_version_and_zero_value`, `rust_agent_core::tests::lifecycle_identity_rejects_unknown_and_zero_fields`, `rust_agent_core::tests::only_persistent_operations_derive_durable_session_ids` |
| Lifecycle reservation drafts bind the exact projected request and cannot be forged | `rust_agent_runtime_api::tests::persistent_create_reservation_binds_all_projected_fields`, `rust_agent_runtime_api::tests::resume_keeps_exact_existing_session_and_volatile_paths_fail_closed`, `privacy::private_protocol_fields_cannot_be_forged` |
| Unknown metadata/framework fields fail closed | `catalog::tests::unknown_fields_fail_closed` |
| Lifecycle/provide effects are mandatory and bounded by the Component ceiling | `catalog::tests::lifecycle_and_provide_effect_fields_are_required`, `catalog::tests::effects_must_be_accounted` |
| App coexistence is scope-correct and conservative | `catalog::tests::app_coexistence_is_scope_bound` |
| Target facts and predicates are canonical and closed | `target::tests::*` |
| bin/library/wasm Host boundary cardinality, kind, target, support and security accounting fail closed | `resolver::tests::host_boundary_cardinality_kind_target_and_effect_union_are_closed` |
| Native Host entry accepts only its declared Linux/macOS/Windows set | `resolver::tests::native_host_entry_accepts_only_declared_desktop_operating_systems` |
| Required resource namespaces derive an exact, effect-accounted bootstrap graph and reject incomplete/unsafe metadata | `catalog::tests::required_resource_namespace_derives_an_exact_bootstrap_requirement`, `catalog::tests::resolver_selects_the_exact_namespace_bootstrap_before_the_consumer`, `catalog::tests::incomplete_or_unsafe_namespace_metadata_fails_closed` |
| Host Cargo unit graphs preserve exact source and Host/Target unit identity, canonical ordering, edge domains and planned/observed equality | `cargo_unit_graph::tests::host_and_target_units_remain_distinct_and_deterministic`, `cargo_unit_graph::tests::unknown_fields_unsorted_features_and_domain_confusion_fail_closed`, `cargo_unit_graph::tests::missing_nodes_duplicates_and_observation_drift_are_rejected` |
| Runtime effects cannot be expanded by build requirements or a mismatched policy kind | `controlled_policy::build_requirements_need_exact_policy_kind_but_never_expand_runtime_effects` |
| Metadata/schema versions, generated source and canonical encodings remain frozen | `generator::tests::minimal_golden_is_fresh`, `canonical::tests::*` |

## Phase 1A

| Contract | Automated evidence |
|---|---|
| Required closure, disable, security and bounded deterministic backtracking | `resolver::tests::*`, `resolver_properties::*` |
| Same semantic input produces the same composition identity | `generator::tests::regeneration_is_deterministic` |
| Transient Trybuild diagnostics cannot enter source snapshots or composition identity | `generator::tests::trybuild_wip_does_not_enter_the_source_snapshot` |
| Generated source, Cargo and manifest snapshots remain fresh | `generator::tests::minimal_golden_is_fresh` |
| Optional filesystem Component is physically absent/present in real Cargo graph | `generator::tests::selected_packages_match_cargo_tree` |
| Small resolver graphs agree with a brute-force feasibility oracle | `resolver::tests::small_graph_matches_bruteforce_oracle` |
| Host feature delta is unit-specific and never relaxes first-party/Host/generated units | `host_feature::tests::*` |
| Product-neutral library graph compiles on the installed target matrix | `target_matrix::product_neutral_library_compile_matrix` |
| Emitted composition compiles in an independent Host and rejects duplicate API identity | `e2e::compose_build_inspect_emit_verify_end_to_end` |
| Development output cannot claim deployability | `e2e::compose_build_inspect_emit_verify_end_to_end` |
| CLI compose/build/inspect/emit/verify workflow | `rust-agent-cli/tests/e2e.rs` |
