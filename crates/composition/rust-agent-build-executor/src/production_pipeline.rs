use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

use rust_agent_composition::{CompositionManifest, canonical, profile::BuildKind};
use thiserror::Error;

use crate::{
    BuildArtifactTarget, CargoFetchCacheLayout, CargoPlannerGraphRoot, CargoUnitSelector,
    DevelopmentHostFeatureVerification, HostFeaturePolicyError, HostFeaturePolicyStageDigests,
    HostFeatureUnitObservation, NormalizedCargoFetchRequest, NormalizedCargoPlannerRequest,
    NormalizedHostBuildInputClosure, NormalizedHostFeaturePolicy, NormalizedLockedSourceClosure,
    NormalizedProductionBuildPolicy, ProductBuildContribution, ProductionArtifactError,
    ProductionArtifactPublication, ProductionBuildAttestationInput, ProductionBuildOptionsIdentity,
    ProductionCompletionHandle, ProductionEnforcementResultIdentity, ProductionExecutionEvidence,
    ProductionIntegrationError, ProductionIntegrationPreReceipt, ProductionOperationKind,
    TrustedCargoBuildError, TrustedCargoBuildResult, TrustedCargoFetchError,
    TrustedCargoFetchResult, TrustedCargoPlannerError, TrustedCargoPlannerResult,
    TrustedHostBuildResult, TrustedProductionPreflightError, TrustedProductionPreflightEvidence,
    TrustedWasmPostprocessError, TrustedWasmPostprocessResult, VerifiedHostClosureSnapshot,
    VerifiedLinuxSandboxBackend, VerifiedProductionBuildAttestation,
    VerifiedProductionHostFeatureReceipt, VerifiedProductionInputs,
    create_production_artifact_staging, create_production_build_attestation_payload,
    create_production_integration_pre_receipt, execute_trusted_build_host,
    execute_trusted_cargo_build, execute_trusted_cargo_fetch, execute_trusted_cargo_planner,
    execute_trusted_production_preflight, execute_trusted_wasm_postprocessor,
    materialize_trusted_cargo_artifact, prepare_production_build_attestation_publication,
    publish_production_artifact, sign_production_build_attestation,
    verify_production_host_feature_union, write_production_build_manifest,
    write_production_integration_pre_receipt,
};

pub trait ProductionCompletionAuthority {
    fn authorize(
        &mut self,
        payload: &crate::ProductionBuildAttestationPayload,
    ) -> Result<ProductionCompletionHandle, String>;
}

impl<F> ProductionCompletionAuthority for F
where
    F: FnMut(
        &crate::ProductionBuildAttestationPayload,
    ) -> Result<ProductionCompletionHandle, String>,
{
    fn authorize(
        &mut self,
        payload: &crate::ProductionBuildAttestationPayload,
    ) -> Result<ProductionCompletionHandle, String> {
        self(payload)
    }
}

#[derive(Debug)]
pub struct ProductionBuildPipelineOptions<'a> {
    pub composition: &'a CompositionManifest,
    pub cargo_lock: &'a Path,
    pub policy: &'a NormalizedProductionBuildPolicy,
    pub backend: &'a VerifiedLinuxSandboxBackend,
    pub closure: &'a NormalizedHostBuildInputClosure,
    pub closure_snapshot: &'a VerifiedHostClosureSnapshot,
    pub locked_sources: &'a NormalizedLockedSourceClosure,
    pub fetch_request: &'a NormalizedCargoFetchRequest,
    pub fetch_inputs: &'a VerifiedProductionInputs,
    pub fetch_staging: &'a Path,
    pub fetch_cache_output: &'a Path,
    pub fetch_cache_layout: &'a CargoFetchCacheLayout,
    pub production_inputs: &'a VerifiedProductionInputs,
    pub planner_request: &'a NormalizedCargoPlannerRequest,
    pub target_root: &'a Path,
    pub temp_root: &'a Path,
    pub wasm_bundle_root: Option<&'a Path>,
    pub artifact_parent: &'a Path,
    pub attestation_root: &'a Path,
    pub completion_nonce_directory: &'a Path,
    pub executor_id: String,
    pub workload_identity: String,
    pub verifier_identity_digest: String,
    pub timestamp: String,
    pub transparency_proof: Option<String>,
}

#[derive(Debug)]
pub struct ProductionBuildPipelineResult {
    fetch: TrustedCargoFetchResult,
    preflight: TrustedProductionPreflightEvidence,
    planner: TrustedCargoPlannerResult,
    build: TrustedCargoBuildResult,
    wasm: Option<TrustedWasmPostprocessResult>,
    publication: ProductionArtifactPublication,
    attestation: VerifiedProductionBuildAttestation,
}

#[derive(Debug)]
pub struct ProductionHostBuildPipelineOptions<'a> {
    pub composition_build: &'a VerifiedProductionBuildAttestation,
    pub pre_receipt: &'a ProductionIntegrationPreReceipt,
    pub cargo_lock: &'a Path,
    pub policy: &'a NormalizedProductionBuildPolicy,
    pub backend: &'a VerifiedLinuxSandboxBackend,
    pub closure: &'a NormalizedHostBuildInputClosure,
    pub closure_snapshot: &'a VerifiedHostClosureSnapshot,
    pub locked_sources: &'a NormalizedLockedSourceClosure,
    pub fetch_request: &'a NormalizedCargoFetchRequest,
    pub fetch_inputs: &'a VerifiedProductionInputs,
    pub fetch_staging: &'a Path,
    pub fetch_cache_output: &'a Path,
    pub fetch_cache_layout: &'a CargoFetchCacheLayout,
    pub production_inputs: &'a VerifiedProductionInputs,
    pub standalone_planner_request: &'a NormalizedCargoPlannerRequest,
    pub final_planner_request: &'a NormalizedCargoPlannerRequest,
    pub first_party_units: &'a BTreeSet<CargoUnitSelector>,
    pub host_feature_policy: Option<&'a NormalizedHostFeaturePolicy>,
    pub host_feature_observations: &'a BTreeMap<CargoUnitSelector, HostFeatureUnitObservation>,
    pub host_root_runtime_effects: &'a BTreeSet<String>,
    pub product_build_contributions: &'a [ProductBuildContribution],
    pub target_root: &'a Path,
    pub temp_root: &'a Path,
    pub artifact_parent: &'a Path,
    pub attestation_root: &'a Path,
    pub completion_nonce_directory: &'a Path,
    pub executor_id: String,
    pub workload_identity: String,
    pub verifier_identity_digest: String,
    pub timestamp: String,
    pub transparency_proof: Option<String>,
}

#[derive(Debug)]
pub struct ProductionIntegrationPrePipelineOptions<'a> {
    pub composition_build: &'a VerifiedProductionBuildAttestation,
    pub receipt_output: &'a Path,
    pub policy: &'a NormalizedProductionBuildPolicy,
    pub backend: &'a VerifiedLinuxSandboxBackend,
    pub closure: &'a NormalizedHostBuildInputClosure,
    pub closure_snapshot: &'a VerifiedHostClosureSnapshot,
    pub locked_sources: &'a NormalizedLockedSourceClosure,
    pub fetch_request: &'a NormalizedCargoFetchRequest,
    pub fetch_inputs: &'a VerifiedProductionInputs,
    pub fetch_staging: &'a Path,
    pub fetch_cache_output: &'a Path,
    pub fetch_cache_layout: &'a CargoFetchCacheLayout,
    pub production_inputs: &'a VerifiedProductionInputs,
    pub standalone_planner_request: &'a NormalizedCargoPlannerRequest,
    pub final_planner_request: &'a NormalizedCargoPlannerRequest,
    pub first_party_units: &'a BTreeSet<CargoUnitSelector>,
    pub host_feature_policy: Option<&'a NormalizedHostFeaturePolicy>,
    pub host_feature_observations: &'a BTreeMap<CargoUnitSelector, HostFeatureUnitObservation>,
    pub host_root_runtime_effects: &'a BTreeSet<String>,
    pub product_build_contributions: &'a [ProductBuildContribution],
}

#[derive(Debug)]
pub struct ProductionIntegrationPrePipelineResult {
    fetch: TrustedCargoFetchResult,
    preflight: TrustedProductionPreflightEvidence,
    standalone_planner: TrustedCargoPlannerResult,
    final_planner: TrustedCargoPlannerResult,
    feature_verification: VerifiedProductionHostFeatureReceipt,
    receipt: ProductionIntegrationPreReceipt,
}

#[derive(Debug)]
pub struct ProductionHostBuildPipelineResult {
    fetch: TrustedCargoFetchResult,
    preflight: TrustedProductionPreflightEvidence,
    host_build: TrustedHostBuildResult,
    feature_verification: VerifiedProductionHostFeatureReceipt,
    publication: ProductionArtifactPublication,
    attestation: VerifiedProductionBuildAttestation,
}

#[derive(Debug, Error)]
pub enum ProductionBuildPipelineError {
    #[error("production build pipeline inputs are invalid: {0}")]
    InvalidInput(&'static str),
    #[error("production preflight failed: {0}")]
    Preflight(#[from] TrustedProductionPreflightError),
    #[error("production Cargo planner failed: {0}")]
    Planner(#[from] TrustedCargoPlannerError),
    #[error("production Cargo build failed: {0}")]
    Build(#[from] TrustedCargoBuildError),
    #[error("production Cargo fetch failed: {0}")]
    Fetch(#[from] TrustedCargoFetchError),
    #[error("production WASM postprocessing failed: {0}")]
    Wasm(#[from] TrustedWasmPostprocessError),
    #[error("production artifact processing failed: {0}")]
    Artifact(#[from] ProductionArtifactError),
    #[error("production build policy failed: {0}")]
    Policy(#[from] crate::ProductionBuildPolicyError),
    #[error("production Host integration failed: {0}")]
    Integration(#[source] Box<ProductionIntegrationError>),
    #[error("production Host feature accounting failed: {0}")]
    HostFeature(#[from] HostFeaturePolicyError),
    #[error("production attestation failed: {0}")]
    Attestation(#[from] crate::ProductionAttestationError),
    #[error("production evidence encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
    #[error("trusted completion authority rejected the build: {0}")]
    Completion(String),
}

impl From<ProductionIntegrationError> for ProductionBuildPipelineError {
    fn from(error: ProductionIntegrationError) -> Self {
        Self::Integration(Box::new(error))
    }
}

pub fn execute_trusted_production_build(
    options: ProductionBuildPipelineOptions<'_>,
    completion_authority: &mut impl ProductionCompletionAuthority,
) -> Result<ProductionBuildPipelineResult, ProductionBuildPipelineError> {
    validate_pipeline_inputs(&options)?;
    let fetch = execute_trusted_cargo_fetch(
        options.backend,
        options.fetch_request,
        options.locked_sources,
        options.closure_snapshot,
        options.fetch_inputs,
        options.fetch_staging,
        options.fetch_cache_output,
        options.fetch_cache_layout,
    )?;
    let preflight = execute_trusted_production_preflight(
        options.backend,
        options.production_inputs,
        options.closure,
        options.closure_snapshot,
    )?;
    let planner = execute_trusted_cargo_planner(
        options.backend,
        options.planner_request,
        options.closure,
        options.closure_snapshot,
        options.locked_sources,
        fetch.cache(),
        options.production_inputs,
    )?;
    if planner.graph() != options.closure.standalone_unit_graph() {
        return Err(ProductionBuildPipelineError::InvalidInput(
            "trusted planner graph differs from the standalone closure graph",
        ));
    }
    let build = execute_trusted_cargo_build(
        options.backend,
        options.policy,
        options.planner_request,
        options.closure,
        options.closure_snapshot,
        fetch.cache(),
        options.production_inputs,
        planner.graph(),
        options.target_root,
        options.temp_root,
    )?;

    let staging = create_production_artifact_staging(options.artifact_parent)?;
    let (artifacts, postprocessor, wasm) = if options.composition.build_kind == BuildKind::Wasm {
        let bundle_root =
            options
                .wasm_bundle_root
                .ok_or(ProductionBuildPipelineError::InvalidInput(
                    "missing WASM bundle output root",
                ))?;
        let result = execute_trusted_wasm_postprocessor(
            options.backend,
            options.production_inputs,
            &build,
            options.planner_request.artifact_selector(),
            options.cargo_lock,
            bundle_root,
            &staging,
            &options.composition.target,
        )?;
        (
            result.artifacts().to_vec(),
            Some(result.postprocessor().clone()),
            Some(result),
        )
    } else {
        if options.wasm_bundle_root.is_some() {
            return Err(ProductionBuildPipelineError::InvalidInput(
                "non-WASM build supplied a WASM bundle output root",
            ));
        }
        let artifact = materialize_trusted_cargo_artifact(
            &build,
            options.planner_request.artifact_selector(),
            &staging,
            "artifact/rust-agent-output",
            &options.composition.target,
        )?;
        (vec![artifact], None, None)
    };
    let entry_artifact = if options.composition.build_kind == BuildKind::Wasm {
        "bundle/rust_agent.js".into()
    } else {
        artifacts
            .first()
            .ok_or(ProductionBuildPipelineError::InvalidInput(
                "missing final artifact",
            ))?
            .path
            .clone()
    };
    let enforcement = options.policy.enforcement_identity(
        options.closure.build_requirements(),
        options.closure.build_context(),
    )?;
    let manifest = write_production_build_manifest(
        &staging,
        options.cargo_lock,
        crate::ProductionBuildManifestInput {
            composition: options.composition.clone(),
            build_requirements: options.closure.build_requirements().clone(),
            effective_compiled_runtime_effects: options
                .composition
                .compiled_runtime_effects
                .clone(),
            build_enforcement_identity: enforcement,
            enforcement_result: ProductionEnforcementResultIdentity {
                schema: 1,
                build_input_content_digest: options.closure.content_identity_digest().into(),
                planned_unit_graph_digest: planner.graph().digest().into(),
                observed_unit_graph_digest: build.observed_graph().digest().into(),
                cargo_messages_digest: build.cargo_messages_sha256().into(),
                filesystem_enforcement: "closed-world-read-write-exec".into(),
                network_enforcement: "isolated".into(),
                descendant_enforcement: "inherited".into(),
            },
            build_options: ProductionBuildOptionsIdentity {
                schema: 1,
                host_integration: false,
                build_kind: options.composition.build_kind,
                composition_profile: options.composition.profile.clone(),
                cargo_profile: options.closure.build_context().profile.clone(),
                target: options.composition.target.clone(),
                artifact_selector: options.planner_request.artifact_selector().clone(),
                panic_strategy: options.closure.build_context().panic_strategy,
                locked: true,
                offline: true,
                jobs: 1,
            },
            cargo_invocation: build.cargo_invocation().clone(),
            entry_artifact,
            artifacts,
            postprocessor,
            gates: production_gates(options.composition.build_kind),
        },
    )?;
    let evidence = build_evidence(&options, &preflight, &planner, &build, wasm.as_ref())?;
    let payload = create_production_build_attestation_payload(
        &manifest,
        options.policy,
        ProductionBuildAttestationInput {
            operation: ProductionOperationKind::Build,
            executor_id: options.executor_id,
            workload_identity: options.workload_identity,
            verifier_identity_digest: options.verifier_identity_digest,
            sandbox_backend_identity: options
                .backend
                .identity()
                .try_into()
                .map_err(crate::ProductionAttestationError::from)?,
            evidence,
            product_integration: None,
            host_feature_policy: None,
        },
    )?;
    let completion_handle = completion_authority
        .authorize(&payload)
        .map_err(ProductionBuildPipelineError::Completion)?;
    let signed = sign_production_build_attestation(
        &manifest,
        options.policy,
        payload,
        completion_handle,
        options.completion_nonce_directory,
        options.timestamp,
        options.transparency_proof,
    )?;
    let prepared_attestation = prepare_production_build_attestation_publication(
        &staging,
        options.attestation_root,
        options.policy,
        &signed,
    )?;
    let publication = publish_production_artifact(
        &staging,
        options.artifact_parent,
        &manifest,
        prepared_attestation.artifact_publication_permit(),
    )?;
    let attestation = prepared_attestation.finalize(&publication.path, options.policy)?;
    Ok(ProductionBuildPipelineResult {
        fetch,
        preflight,
        planner,
        build,
        wasm,
        publication,
        attestation,
    })
}

impl ProductionBuildPipelineResult {
    pub fn fetch(&self) -> &TrustedCargoFetchResult {
        &self.fetch
    }

    pub fn preflight(&self) -> &TrustedProductionPreflightEvidence {
        &self.preflight
    }

    pub fn planner(&self) -> &TrustedCargoPlannerResult {
        &self.planner
    }

    pub fn build(&self) -> &TrustedCargoBuildResult {
        &self.build
    }

    pub fn wasm(&self) -> Option<&TrustedWasmPostprocessResult> {
        self.wasm.as_ref()
    }

    pub fn publication(&self) -> &ProductionArtifactPublication {
        &self.publication
    }

    pub fn attestation(&self) -> &VerifiedProductionBuildAttestation {
        &self.attestation
    }
}

pub fn execute_trusted_production_integration_pre(
    options: &ProductionIntegrationPrePipelineOptions<'_>,
) -> Result<ProductionIntegrationPrePipelineResult, ProductionBuildPipelineError> {
    let result = reverify_trusted_production_integration_pre(options)?;
    write_production_integration_pre_receipt(
        options.receipt_output,
        result.receipt(),
        options.closure,
        options.policy,
        options.composition_build,
    )?;
    Ok(result)
}

pub fn reverify_trusted_production_integration_pre(
    options: &ProductionIntegrationPrePipelineOptions<'_>,
) -> Result<ProductionIntegrationPrePipelineResult, ProductionBuildPipelineError> {
    if options.standalone_planner_request.root() != CargoPlannerGraphRoot::EmittedStandalone
        || options.final_planner_request.root() != CargoPlannerGraphRoot::FinalHost
        || options
            .host_feature_policy
            .map(NormalizedHostFeaturePolicy::digest)
            != options.closure.host_feature_policy_digest()
    {
        return Err(ProductionBuildPipelineError::InvalidInput(
            "production integration pre planner or feature policy mismatch",
        ));
    }
    let fetch = execute_trusted_cargo_fetch(
        options.backend,
        options.fetch_request,
        options.locked_sources,
        options.closure_snapshot,
        options.fetch_inputs,
        options.fetch_staging,
        options.fetch_cache_output,
        options.fetch_cache_layout,
    )?;
    let preflight = execute_trusted_production_preflight(
        options.backend,
        options.production_inputs,
        options.closure,
        options.closure_snapshot,
    )?;
    let standalone_planner = execute_trusted_cargo_planner(
        options.backend,
        options.standalone_planner_request,
        options.closure,
        options.closure_snapshot,
        options.locked_sources,
        fetch.cache(),
        options.production_inputs,
    )?;
    let final_planner = execute_trusted_cargo_planner(
        options.backend,
        options.final_planner_request,
        options.closure,
        options.closure_snapshot,
        options.locked_sources,
        fetch.cache(),
        options.production_inputs,
    )?;
    let stage_policy_digests =
        HostFeaturePolicyStageDigests::for_policy(options.host_feature_policy);
    let feature_verification =
        verify_production_host_feature_union(&DevelopmentHostFeatureVerification {
            standalone_graph: standalone_planner.graph(),
            final_graph: final_planner.graph(),
            observed_graph: final_planner.graph(),
            first_party_units: options.first_party_units,
            policy: options.host_feature_policy,
            stage_policy_digests: &stage_policy_digests,
            observations: options.host_feature_observations,
            composition_compiled_runtime_effects: &options
                .composition_build
                .manifest()
                .composition
                .compiled_runtime_effects,
            host_root_runtime_effects: options.host_root_runtime_effects,
            product_build_contributions: options.product_build_contributions,
        })?;
    if feature_verification.receipt().digest != options.closure.unit_feature_delta_digest()
        || !feature_requirements_are_accounted(
            feature_verification.receipt(),
            options.closure.build_requirements(),
        )
    {
        return Err(ProductionBuildPipelineError::InvalidInput(
            "production integration pre feature accounting differs from closure",
        ));
    }
    let receipt = create_production_integration_pre_receipt(
        options.closure,
        options.policy,
        options.composition_build,
        &feature_verification,
    )?;
    Ok(ProductionIntegrationPrePipelineResult {
        fetch,
        preflight,
        standalone_planner,
        final_planner,
        feature_verification,
        receipt,
    })
}

impl ProductionIntegrationPrePipelineResult {
    pub fn fetch(&self) -> &TrustedCargoFetchResult {
        &self.fetch
    }

    pub fn preflight(&self) -> &TrustedProductionPreflightEvidence {
        &self.preflight
    }

    pub fn standalone_planner(&self) -> &TrustedCargoPlannerResult {
        &self.standalone_planner
    }

    pub fn final_planner(&self) -> &TrustedCargoPlannerResult {
        &self.final_planner
    }

    pub fn feature_verification(&self) -> &VerifiedProductionHostFeatureReceipt {
        &self.feature_verification
    }

    pub fn receipt(&self) -> &ProductionIntegrationPreReceipt {
        &self.receipt
    }
}

pub fn execute_trusted_production_host_build(
    options: ProductionHostBuildPipelineOptions<'_>,
    completion_authority: &mut impl ProductionCompletionAuthority,
) -> Result<ProductionHostBuildPipelineResult, ProductionBuildPipelineError> {
    options
        .pre_receipt
        .verify(options.closure, options.policy, options.composition_build)?;
    let selected_feature_policy_digest = options
        .host_feature_policy
        .map(NormalizedHostFeaturePolicy::digest);
    if options.closure.host_feature_policy_digest() != selected_feature_policy_digest {
        return Err(ProductionBuildPipelineError::InvalidInput(
            "Host feature policy differs from the pre closure",
        ));
    }
    let fetch = execute_trusted_cargo_fetch(
        options.backend,
        options.fetch_request,
        options.locked_sources,
        options.closure_snapshot,
        options.fetch_inputs,
        options.fetch_staging,
        options.fetch_cache_output,
        options.fetch_cache_layout,
    )?;
    let preflight = execute_trusted_production_preflight(
        options.backend,
        options.production_inputs,
        options.closure,
        options.closure_snapshot,
    )?;
    let host_build = execute_trusted_build_host(
        options.backend,
        options.policy,
        options.pre_receipt,
        options.composition_build,
        options.standalone_planner_request,
        options.final_planner_request,
        options.closure,
        options.closure_snapshot,
        options.locked_sources,
        fetch.cache(),
        options.production_inputs,
        options.target_root,
        options.temp_root,
    )?;
    let stage_policy_digests =
        HostFeaturePolicyStageDigests::for_policy(options.host_feature_policy);
    let feature_verification =
        verify_production_host_feature_union(&DevelopmentHostFeatureVerification {
            standalone_graph: host_build.standalone_planner().graph(),
            final_graph: host_build.final_planner().graph(),
            observed_graph: host_build.build().observed_graph(),
            first_party_units: options.first_party_units,
            policy: options.host_feature_policy,
            stage_policy_digests: &stage_policy_digests,
            observations: options.host_feature_observations,
            composition_compiled_runtime_effects: &options
                .composition_build
                .manifest()
                .composition
                .compiled_runtime_effects,
            host_root_runtime_effects: options.host_root_runtime_effects,
            product_build_contributions: options.product_build_contributions,
        })?;
    let feature_receipt = feature_verification.receipt();
    if feature_receipt.digest != options.closure.unit_feature_delta_digest()
        || feature_receipt.standalone_unit_graph_digest
            != options.closure.standalone_unit_graph_digest()
        || feature_receipt.final_unit_graph_digest != options.closure.final_unit_graph_digest()
        || !feature_requirements_are_accounted(
            feature_receipt,
            options.closure.build_requirements(),
        )
    {
        return Err(ProductionBuildPipelineError::InvalidInput(
            "Host feature accounting differs from the pre closure",
        ));
    }

    let staging = create_production_artifact_staging(options.artifact_parent)?;
    let artifact = materialize_trusted_cargo_artifact(
        host_build.build(),
        options.final_planner_request.artifact_selector(),
        &staging,
        "artifact/rust-agent-host-output",
        &options.closure.build_context().target,
    )?;
    let build_kind = match &options.final_planner_request.artifact_selector().target {
        BuildArtifactTarget::Library => BuildKind::Library,
        BuildArtifactTarget::Binary { .. }
        | BuildArtifactTarget::Example { .. }
        | BuildArtifactTarget::Test { .. }
        | BuildArtifactTarget::Bench { .. } => BuildKind::Bin,
    };
    let enforcement = options.policy.enforcement_identity(
        options.closure.build_requirements(),
        options.closure.build_context(),
    )?;
    let manifest = write_production_build_manifest(
        &staging,
        options.cargo_lock,
        crate::ProductionBuildManifestInput {
            composition: options.composition_build.manifest().composition.clone(),
            build_requirements: options.closure.build_requirements().clone(),
            effective_compiled_runtime_effects: feature_receipt
                .product_compiled_runtime_effects
                .clone(),
            build_enforcement_identity: enforcement,
            enforcement_result: ProductionEnforcementResultIdentity {
                schema: 1,
                build_input_content_digest: options.closure.content_identity_digest().into(),
                planned_unit_graph_digest: host_build.final_planner().graph().digest().into(),
                observed_unit_graph_digest: host_build.build().observed_graph().digest().into(),
                cargo_messages_digest: host_build.build().cargo_messages_sha256().into(),
                filesystem_enforcement: "closed-world-read-write-exec".into(),
                network_enforcement: "isolated".into(),
                descendant_enforcement: "inherited".into(),
            },
            build_options: ProductionBuildOptionsIdentity {
                schema: 1,
                host_integration: true,
                build_kind,
                composition_profile: options
                    .composition_build
                    .manifest()
                    .composition
                    .profile
                    .clone(),
                cargo_profile: options.closure.build_context().profile.clone(),
                target: options.closure.build_context().target.clone(),
                artifact_selector: options.final_planner_request.artifact_selector().clone(),
                panic_strategy: options.closure.build_context().panic_strategy,
                locked: true,
                offline: true,
                jobs: 1,
            },
            cargo_invocation: host_build.build().cargo_invocation().clone(),
            entry_artifact: artifact.path.clone(),
            artifacts: vec![artifact],
            postprocessor: None,
            gates: production_host_gates(),
        },
    )?;
    let evidence = host_build_evidence(&options, &preflight, &host_build)?;
    let payload = create_production_build_attestation_payload(
        &manifest,
        options.policy,
        ProductionBuildAttestationInput {
            operation: ProductionOperationKind::BuildHost,
            executor_id: options.executor_id,
            workload_identity: options.workload_identity,
            verifier_identity_digest: options.verifier_identity_digest,
            sandbox_backend_identity: options
                .backend
                .identity()
                .try_into()
                .map_err(crate::ProductionAttestationError::from)?,
            evidence,
            product_integration: Some(feature_verification.clone()),
            host_feature_policy: options
                .host_feature_policy
                .map(crate::NormalizedHostFeaturePolicy::attestation_policy),
        },
    )?;
    let completion_handle = completion_authority
        .authorize(&payload)
        .map_err(ProductionBuildPipelineError::Completion)?;
    let signed = sign_production_build_attestation(
        &manifest,
        options.policy,
        payload,
        completion_handle,
        options.completion_nonce_directory,
        options.timestamp,
        options.transparency_proof,
    )?;
    let prepared_attestation = prepare_production_build_attestation_publication(
        &staging,
        options.attestation_root,
        options.policy,
        &signed,
    )?;
    let publication = publish_production_artifact(
        &staging,
        options.artifact_parent,
        &manifest,
        prepared_attestation.artifact_publication_permit(),
    )?;
    let attestation = prepared_attestation.finalize(&publication.path, options.policy)?;
    Ok(ProductionHostBuildPipelineResult {
        fetch,
        preflight,
        host_build,
        feature_verification,
        publication,
        attestation,
    })
}

impl ProductionHostBuildPipelineResult {
    pub fn fetch(&self) -> &TrustedCargoFetchResult {
        &self.fetch
    }

    pub fn preflight(&self) -> &TrustedProductionPreflightEvidence {
        &self.preflight
    }

    pub fn host_build(&self) -> &TrustedHostBuildResult {
        &self.host_build
    }

    pub fn feature_verification(&self) -> &VerifiedProductionHostFeatureReceipt {
        &self.feature_verification
    }

    pub fn publication(&self) -> &ProductionArtifactPublication {
        &self.publication
    }

    pub fn attestation(&self) -> &VerifiedProductionBuildAttestation {
        &self.attestation
    }
}

fn validate_pipeline_inputs(
    options: &ProductionBuildPipelineOptions<'_>,
) -> Result<(), ProductionBuildPipelineError> {
    if options.planner_request.root() != CargoPlannerGraphRoot::EmittedStandalone
        || options.composition.composition_hash != options.closure.composition_hash()
        || options.composition.target != options.closure.build_context().target
        || options.closure.standalone_unit_graph() != options.closure.final_unit_graph()
        || options
            .production_inputs
            .request()
            .build_execution_policy_digest
            != options.policy.full_digest()
        || options.planner_request.build_execution_policy_digest() != options.policy.full_digest()
    {
        return Err(ProductionBuildPipelineError::InvalidInput(
            "composition, closure, policy, or standalone graph mismatch",
        ));
    }
    Ok(())
}

fn build_evidence(
    options: &ProductionBuildPipelineOptions<'_>,
    preflight: &TrustedProductionPreflightEvidence,
    planner: &TrustedCargoPlannerResult,
    build: &TrustedCargoBuildResult,
    wasm: Option<&TrustedWasmPostprocessResult>,
) -> Result<ProductionExecutionEvidence, ProductionBuildPipelineError> {
    let mut sandbox_observations = preflight
        .version_sandbox_observations()
        .iter()
        .map(|observation| observation.digest.as_str())
        .collect::<Vec<_>>();
    sandbox_observations.extend([
        preflight.target_facts_sandbox_observation().digest.as_str(),
        planner.unit_graph_sandbox_observation().digest.as_str(),
        planner.metadata_sandbox_observation().digest.as_str(),
        build.sandbox_observation().digest.as_str(),
    ]);
    if let Some(wasm) = wasm {
        sandbox_observations.push(wasm.sandbox_observation().digest.as_str());
    }
    let sandbox_digest = hex::encode(canonical::domain_hash(
        b"rust-agent-production-build-sandbox-observations-v1\0",
        &sandbox_observations,
    )?);
    Ok(ProductionExecutionEvidence {
        schema: 1,
        pre_receipt_digest: None,
        executor_attestation_payload_digest: None,
        host_build_input_closure_digest: options.closure.digest().into(),
        build_input_content_digest: options.closure.content_identity_digest().into(),
        production_input_request_digest: options.production_inputs.request().digest.clone(),
        production_input_observation_digest: preflight
            .validated_version_observation()
            .observation_digest()
            .into(),
        target_facts_request_digest: preflight
            .validated_target_facts_observation()
            .request_digest()
            .into(),
        target_facts_observation_digest: preflight
            .validated_target_facts_observation()
            .observation_digest()
            .into(),
        standalone_planner_request_digest: options.planner_request.digest().into(),
        final_planner_request_digest: options.planner_request.digest().into(),
        standalone_planned_unit_graph_digest: planner.graph().digest().into(),
        final_planned_unit_graph_digest: planner.graph().digest().into(),
        observed_unit_graph_digest: build.observed_graph().digest().into(),
        unit_feature_delta_digest: options.closure.unit_feature_delta_digest().into(),
        sandbox_observation_digest: sandbox_digest,
        cargo_messages_digest: build.cargo_messages_sha256().into(),
        wasm_postprocessor_observation_digest: wasm
            .map(|result| result.sandbox_observation().digest.clone()),
    })
}

fn host_build_evidence(
    options: &ProductionHostBuildPipelineOptions<'_>,
    preflight: &TrustedProductionPreflightEvidence,
    host_build: &TrustedHostBuildResult,
) -> Result<ProductionExecutionEvidence, ProductionBuildPipelineError> {
    let mut sandbox_observations = preflight
        .version_sandbox_observations()
        .iter()
        .map(|observation| observation.digest.as_str())
        .collect::<Vec<_>>();
    sandbox_observations.extend([
        preflight.target_facts_sandbox_observation().digest.as_str(),
        host_build
            .standalone_planner()
            .unit_graph_sandbox_observation()
            .digest
            .as_str(),
        host_build
            .standalone_planner()
            .metadata_sandbox_observation()
            .digest
            .as_str(),
        host_build
            .final_planner()
            .unit_graph_sandbox_observation()
            .digest
            .as_str(),
        host_build
            .final_planner()
            .metadata_sandbox_observation()
            .digest
            .as_str(),
        host_build.build().sandbox_observation().digest.as_str(),
    ]);
    let sandbox_digest = hex::encode(canonical::domain_hash(
        b"rust-agent-production-host-build-sandbox-observations-v1\0",
        &sandbox_observations,
    )?);
    Ok(ProductionExecutionEvidence {
        schema: 1,
        pre_receipt_digest: Some(options.pre_receipt.digest.clone()),
        executor_attestation_payload_digest: None,
        host_build_input_closure_digest: options.closure.digest().into(),
        build_input_content_digest: options.closure.content_identity_digest().into(),
        production_input_request_digest: options.production_inputs.request().digest.clone(),
        production_input_observation_digest: preflight
            .validated_version_observation()
            .observation_digest()
            .into(),
        target_facts_request_digest: preflight
            .validated_target_facts_observation()
            .request_digest()
            .into(),
        target_facts_observation_digest: preflight
            .validated_target_facts_observation()
            .observation_digest()
            .into(),
        standalone_planner_request_digest: options.standalone_planner_request.digest().into(),
        final_planner_request_digest: options.final_planner_request.digest().into(),
        standalone_planned_unit_graph_digest: host_build
            .standalone_planner()
            .graph()
            .digest()
            .into(),
        final_planned_unit_graph_digest: host_build.final_planner().graph().digest().into(),
        observed_unit_graph_digest: host_build.build().observed_graph().digest().into(),
        unit_feature_delta_digest: options.closure.unit_feature_delta_digest().into(),
        sandbox_observation_digest: sandbox_digest,
        cargo_messages_digest: host_build.build().cargo_messages_sha256().into(),
        wasm_postprocessor_observation_digest: None,
    })
}

fn feature_requirements_are_accounted(
    receipt: &crate::ProductionHostFeatureReceipt,
    requirements: &rust_agent_composition::metadata::BuildRequirements,
) -> bool {
    receipt.deltas.iter().all(|delta| {
        delta
            .build_requirements
            .executables
            .is_subset(&requirements.executables)
            && delta
                .build_requirements
                .read_inputs
                .is_subset(&requirements.read_inputs)
            && delta
                .build_requirements
                .environment
                .is_subset(&requirements.environment)
    }) && receipt
        .product_build_contributions
        .iter()
        .all(|contribution| {
            contribution
                .build_requirements
                .executables
                .is_subset(&requirements.executables)
                && contribution
                    .build_requirements
                    .read_inputs
                    .is_subset(&requirements.read_inputs)
                && contribution
                    .build_requirements
                    .environment
                    .is_subset(&requirements.environment)
        })
}

fn production_host_gates() -> Vec<String> {
    let mut gates = vec![
        "artifact-tree-accounted".into(),
        "build-requirements-authorized".into(),
        "cyclonedx-sbom-emitted".into(),
        "host-feature-accounting-verified".into(),
        "integration-pre-receipt-verified".into(),
        "locked-offline-cargo".into(),
        "planned-observed-unit-graph-exact".into(),
        "production-sandbox-verified".into(),
        "target-facts-reproduced".into(),
        "trusted-completion-handle-verified".into(),
    ];
    gates.sort();
    gates
}

fn production_gates(kind: BuildKind) -> Vec<String> {
    let mut gates = vec![
        "artifact-tree-accounted".into(),
        "build-requirements-authorized".into(),
        "cyclonedx-sbom-emitted".into(),
        "locked-offline-cargo".into(),
        "planned-observed-unit-graph-exact".into(),
        "production-sandbox-verified".into(),
        "target-facts-reproduced".into(),
        "trusted-completion-handle-verified".into(),
    ];
    if kind == BuildKind::Wasm {
        gates.extend([
            "wasm-bindgen-bytes-and-version-verified".into(),
            "wasm-bundle-closed-world-verified".into(),
            "wasm-postprocessor-sandbox-verified".into(),
        ]);
    }
    gates.sort();
    gates
}
