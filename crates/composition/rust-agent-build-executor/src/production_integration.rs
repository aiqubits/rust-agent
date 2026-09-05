use std::{fs, io, path::Path};

use rust_agent_composition::{canonical, profile::BuildKind};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CargoPlannerGraphRoot, HostBuildClosureItemRole, NormalizedCargoPlannerRequest,
    NormalizedHostBuildInputClosure, NormalizedLockedSourceClosure,
    NormalizedProductionBuildPolicy, TrustedCargoBuildError, TrustedCargoBuildResult,
    TrustedCargoPlannerError, TrustedCargoPlannerResult, VerifiedCargoFetchCache,
    VerifiedHostClosureSnapshot, VerifiedLinuxSandboxBackend, VerifiedProductionBuildAttestation,
    VerifiedProductionInputs, execute_trusted_cargo_build, execute_trusted_cargo_planner,
    production_attestation::sign_attestation,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionClosureItemIdentity {
    pub role: HostBuildClosureItemRole,
    pub id: String,
    #[serde(rename = "logical-path")]
    pub logical_path: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCompositionBuildEvidence {
    #[serde(rename = "build-manifest-digest")]
    pub build_manifest_digest: String,
    #[serde(rename = "build-output-digest")]
    pub build_output_digest: String,
    #[serde(rename = "attestation-payload-digest")]
    pub attestation_payload_digest: String,
    #[serde(rename = "build-execution-policy-digest")]
    pub build_execution_policy_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionIntegrationPreReceipt {
    pub schema: u32,
    pub deployable: bool,
    #[serde(rename = "composition-hash")]
    pub composition_hash: String,
    #[serde(rename = "host-dependency-alias")]
    pub host_dependency_alias: String,
    #[serde(rename = "composition-build-evidence")]
    pub composition_build_evidence: ProductionCompositionBuildEvidence,
    #[serde(rename = "host-build-input-closure-digest")]
    pub host_build_input_closure_digest: String,
    #[serde(rename = "build-input-content-digest")]
    pub build_input_content_digest: String,
    #[serde(rename = "closure-items")]
    pub closure_items: Vec<ProductionClosureItemIdentity>,
    #[serde(rename = "build-execution-policy-digest")]
    pub build_execution_policy_digest: String,
    #[serde(rename = "build-enforcement-identity-digest")]
    pub build_enforcement_identity_digest: String,
    #[serde(rename = "host-feature-policy-digest")]
    pub host_feature_policy_digest: Option<String>,
    #[serde(rename = "host-feature-accounting")]
    pub host_feature_accounting: crate::ProductionHostFeatureReceipt,
    #[serde(rename = "standalone-unit-graph-digest")]
    pub standalone_unit_graph_digest: String,
    #[serde(rename = "final-unit-graph-digest")]
    pub final_unit_graph_digest: String,
    #[serde(rename = "unit-feature-delta-digest")]
    pub unit_feature_delta_digest: String,
    pub digest: String,
}

#[derive(Debug)]
pub struct TrustedHostBuildResult {
    standalone_planner: TrustedCargoPlannerResult,
    final_planner: TrustedCargoPlannerResult,
    build: TrustedCargoBuildResult,
}

#[derive(Clone, Debug)]
pub struct ProductionIntegrationPostInput {
    pub executor_id: String,
    pub workload_identity: String,
    pub verifier_identity_digest: String,
}

#[derive(Debug)]
pub struct VerifiedProductionIntegrationPostAttestation {
    attestation: crate::ProductionBuildAttestation,
}

#[derive(Debug, Error)]
pub enum ProductionIntegrationError {
    #[error("production integration pre receipt is invalid: {0}")]
    InvalidReceipt(&'static str),
    #[error("production integration canonical encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
    #[error("production integration receipt JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("production integration I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("production integration Cargo planning failed: {0}")]
    Planner(#[from] TrustedCargoPlannerError),
    #[error("production integration Cargo build failed: {0}")]
    Build(#[from] TrustedCargoBuildError),
    #[error("production integration Host feature accounting failed: {0}")]
    HostFeature(#[from] crate::HostFeaturePolicyError),
    #[error("production integration attestation failed: {0}")]
    Attestation(#[from] crate::ProductionAttestationError),
    #[error("production integration snapshot/publication failed: {0}")]
    Snapshot(#[from] crate::SnapshotMaterializationError),
}

pub fn create_production_integration_pre_receipt(
    closure: &NormalizedHostBuildInputClosure,
    policy: &NormalizedProductionBuildPolicy,
    composition_build: &VerifiedProductionBuildAttestation,
    feature_verification: &crate::VerifiedProductionHostFeatureReceipt,
) -> Result<ProductionIntegrationPreReceipt, ProductionIntegrationError> {
    let manifest = composition_build.manifest();
    let attestation = composition_build.attestation();
    if manifest.composition.build_kind != BuildKind::Library
        || manifest.composition.composition_hash != closure.composition_hash()
        || attestation.payload.composition_hash != closure.composition_hash()
        || attestation.payload.operation != crate::ProductionOperationKind::Build
        || !attestation.payload.deployable
    {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "composition production evidence",
        ));
    }
    verify_feature_accounting(closure, composition_build, feature_verification.receipt())?;
    let closure_items = closure
        .items()
        .iter()
        .map(|item| ProductionClosureItemIdentity {
            role: item.role,
            id: item.id.clone(),
            logical_path: item.logical_path.clone(),
            digest: item.digest.clone(),
        })
        .collect();
    let mut receipt = ProductionIntegrationPreReceipt {
        schema: 1,
        deployable: true,
        composition_hash: closure.composition_hash().into(),
        host_dependency_alias: closure.host_dependency_alias().into(),
        composition_build_evidence: ProductionCompositionBuildEvidence {
            build_manifest_digest: manifest.build_manifest_digest.clone(),
            build_output_digest: manifest.build_output_digest.clone(),
            attestation_payload_digest: attestation.payload_digest.clone(),
            build_execution_policy_digest: attestation
                .payload
                .build_execution_policy_digest
                .clone(),
        },
        host_build_input_closure_digest: closure.digest().into(),
        build_input_content_digest: closure.content_identity_digest().into(),
        closure_items,
        build_execution_policy_digest: policy.full_digest().into(),
        build_enforcement_identity_digest: closure.build_enforcement_identity_digest().into(),
        host_feature_policy_digest: closure.host_feature_policy_digest().map(str::to_owned),
        host_feature_accounting: feature_verification.receipt().clone(),
        standalone_unit_graph_digest: closure.standalone_unit_graph_digest().into(),
        final_unit_graph_digest: closure.final_unit_graph_digest().into(),
        unit_feature_delta_digest: closure.unit_feature_delta_digest().into(),
        digest: String::new(),
    };
    receipt.digest = receipt.recompute_digest()?;
    receipt.verify(closure, policy, composition_build)?;
    Ok(receipt)
}

pub fn write_production_integration_pre_receipt(
    output: &Path,
    receipt: &ProductionIntegrationPreReceipt,
    closure: &NormalizedHostBuildInputClosure,
    policy: &NormalizedProductionBuildPolicy,
    composition_build: &VerifiedProductionBuildAttestation,
) -> Result<(), ProductionIntegrationError> {
    receipt.verify(closure, policy, composition_build)?;
    write_new_json_atomic(output, receipt)
}

pub fn read_production_integration_pre_receipt(
    path: &Path,
    closure: &NormalizedHostBuildInputClosure,
    policy: &NormalizedProductionBuildPolicy,
    composition_build: &VerifiedProductionBuildAttestation,
) -> Result<ProductionIntegrationPreReceipt, ProductionIntegrationError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > 16 * 1024 * 1024 {
        return Err(ProductionIntegrationError::InvalidReceipt("receipt file"));
    }
    let receipt: ProductionIntegrationPreReceipt = serde_json::from_slice(&fs::read(path)?)?;
    receipt.verify(closure, policy, composition_build)?;
    Ok(receipt)
}

impl ProductionIntegrationPreReceipt {
    pub fn verify(
        &self,
        closure: &NormalizedHostBuildInputClosure,
        policy: &NormalizedProductionBuildPolicy,
        composition_build: &VerifiedProductionBuildAttestation,
    ) -> Result<(), ProductionIntegrationError> {
        let expected = create_receipt_projection(
            closure,
            policy,
            composition_build,
            &self.host_feature_accounting,
        )?;
        if self.schema != 1
            || !self.deployable
            || self.digest != self.recompute_digest()?
            || self.without_digest() != expected
        {
            return Err(ProductionIntegrationError::InvalidReceipt(
                "receipt projection or digest",
            ));
        }
        Ok(())
    }

    fn recompute_digest(&self) -> Result<String, ProductionIntegrationError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-production-integration-pre-receipt-v1\0",
            &self.without_digest(),
        )?))
    }

    fn without_digest(&self) -> PreReceiptProjection {
        PreReceiptProjection {
            schema: self.schema,
            deployable: self.deployable,
            composition_hash: self.composition_hash.clone(),
            host_dependency_alias: self.host_dependency_alias.clone(),
            composition_build_evidence: self.composition_build_evidence.clone(),
            host_build_input_closure_digest: self.host_build_input_closure_digest.clone(),
            build_input_content_digest: self.build_input_content_digest.clone(),
            closure_items: self.closure_items.clone(),
            build_execution_policy_digest: self.build_execution_policy_digest.clone(),
            build_enforcement_identity_digest: self.build_enforcement_identity_digest.clone(),
            host_feature_policy_digest: self.host_feature_policy_digest.clone(),
            host_feature_accounting: self.host_feature_accounting.clone(),
            standalone_unit_graph_digest: self.standalone_unit_graph_digest.clone(),
            final_unit_graph_digest: self.final_unit_graph_digest.clone(),
            unit_feature_delta_digest: self.unit_feature_delta_digest.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct PreReceiptProjection {
    schema: u32,
    deployable: bool,
    composition_hash: String,
    host_dependency_alias: String,
    composition_build_evidence: ProductionCompositionBuildEvidence,
    host_build_input_closure_digest: String,
    build_input_content_digest: String,
    closure_items: Vec<ProductionClosureItemIdentity>,
    build_execution_policy_digest: String,
    build_enforcement_identity_digest: String,
    host_feature_policy_digest: Option<String>,
    host_feature_accounting: crate::ProductionHostFeatureReceipt,
    standalone_unit_graph_digest: String,
    final_unit_graph_digest: String,
    unit_feature_delta_digest: String,
}

fn create_receipt_projection(
    closure: &NormalizedHostBuildInputClosure,
    policy: &NormalizedProductionBuildPolicy,
    composition_build: &VerifiedProductionBuildAttestation,
    feature_accounting: &crate::ProductionHostFeatureReceipt,
) -> Result<PreReceiptProjection, ProductionIntegrationError> {
    verify_feature_accounting(closure, composition_build, feature_accounting)?;
    let created = create_production_integration_pre_receipt_unverified(
        closure,
        policy,
        composition_build,
        feature_accounting,
    )?;
    Ok(created.without_digest())
}

fn create_production_integration_pre_receipt_unverified(
    closure: &NormalizedHostBuildInputClosure,
    policy: &NormalizedProductionBuildPolicy,
    composition_build: &VerifiedProductionBuildAttestation,
    feature_accounting: &crate::ProductionHostFeatureReceipt,
) -> Result<ProductionIntegrationPreReceipt, ProductionIntegrationError> {
    let manifest = composition_build.manifest();
    let attestation = composition_build.attestation();
    if manifest.composition.build_kind != BuildKind::Library
        || manifest.composition.composition_hash != closure.composition_hash()
        || attestation.payload.composition_hash != closure.composition_hash()
        || attestation.payload.operation != crate::ProductionOperationKind::Build
        || !attestation.payload.deployable
    {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "composition production evidence",
        ));
    }
    Ok(ProductionIntegrationPreReceipt {
        schema: 1,
        deployable: true,
        composition_hash: closure.composition_hash().into(),
        host_dependency_alias: closure.host_dependency_alias().into(),
        composition_build_evidence: ProductionCompositionBuildEvidence {
            build_manifest_digest: manifest.build_manifest_digest.clone(),
            build_output_digest: manifest.build_output_digest.clone(),
            attestation_payload_digest: attestation.payload_digest.clone(),
            build_execution_policy_digest: attestation
                .payload
                .build_execution_policy_digest
                .clone(),
        },
        host_build_input_closure_digest: closure.digest().into(),
        build_input_content_digest: closure.content_identity_digest().into(),
        closure_items: closure
            .items()
            .iter()
            .map(|item| ProductionClosureItemIdentity {
                role: item.role,
                id: item.id.clone(),
                logical_path: item.logical_path.clone(),
                digest: item.digest.clone(),
            })
            .collect(),
        build_execution_policy_digest: policy.full_digest().into(),
        build_enforcement_identity_digest: closure.build_enforcement_identity_digest().into(),
        host_feature_policy_digest: closure.host_feature_policy_digest().map(str::to_owned),
        host_feature_accounting: feature_accounting.clone(),
        standalone_unit_graph_digest: closure.standalone_unit_graph_digest().into(),
        final_unit_graph_digest: closure.final_unit_graph_digest().into(),
        unit_feature_delta_digest: closure.unit_feature_delta_digest().into(),
        digest: String::new(),
    })
}

fn verify_feature_accounting(
    closure: &NormalizedHostBuildInputClosure,
    composition_build: &VerifiedProductionBuildAttestation,
    feature: &crate::ProductionHostFeatureReceipt,
) -> Result<(), ProductionIntegrationError> {
    feature.verify_identity()?;
    if !feature.deployable
        || feature.digest != closure.unit_feature_delta_digest()
        || feature.policy_digest.as_deref() != closure.host_feature_policy_digest()
        || feature.standalone_unit_graph_digest != closure.standalone_unit_graph_digest()
        || feature.final_unit_graph_digest != closure.final_unit_graph_digest()
        || feature.observed_unit_graph_digest != closure.final_unit_graph_digest()
        || feature.composition_compiled_runtime_effects
            != composition_build
                .manifest()
                .composition
                .compiled_runtime_effects
    {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "Host feature accounting",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn execute_trusted_build_host(
    backend: &VerifiedLinuxSandboxBackend,
    policy: &NormalizedProductionBuildPolicy,
    receipt: &ProductionIntegrationPreReceipt,
    composition_build: &VerifiedProductionBuildAttestation,
    standalone_request: &NormalizedCargoPlannerRequest,
    final_request: &NormalizedCargoPlannerRequest,
    closure: &NormalizedHostBuildInputClosure,
    closure_snapshot: &VerifiedHostClosureSnapshot,
    locked_sources: &NormalizedLockedSourceClosure,
    cache: &VerifiedCargoFetchCache,
    production_inputs: &VerifiedProductionInputs,
    target_root: &Path,
    temp_root: &Path,
) -> Result<TrustedHostBuildResult, ProductionIntegrationError> {
    receipt.verify(closure, policy, composition_build)?;
    if standalone_request.root() != CargoPlannerGraphRoot::EmittedStandalone
        || final_request.root() != CargoPlannerGraphRoot::FinalHost
    {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "planner root selection",
        ));
    }
    let standalone_planner = execute_trusted_cargo_planner(
        backend,
        standalone_request,
        closure,
        closure_snapshot,
        locked_sources,
        cache,
        production_inputs,
    )?;
    let final_planner = execute_trusted_cargo_planner(
        backend,
        final_request,
        closure,
        closure_snapshot,
        locked_sources,
        cache,
        production_inputs,
    )?;
    if standalone_planner.graph() != closure.standalone_unit_graph()
        || final_planner.graph() != closure.final_unit_graph()
    {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "trusted planner graph differs from the pre receipt",
        ));
    }
    let build = execute_trusted_cargo_build(
        backend,
        policy,
        final_request,
        closure,
        closure_snapshot,
        cache,
        production_inputs,
        final_planner.graph(),
        target_root,
        temp_root,
    )?;
    receipt.verify(closure, policy, composition_build)?;
    Ok(TrustedHostBuildResult {
        standalone_planner,
        final_planner,
        build,
    })
}

impl TrustedHostBuildResult {
    pub fn standalone_planner(&self) -> &TrustedCargoPlannerResult {
        &self.standalone_planner
    }

    pub fn final_planner(&self) -> &TrustedCargoPlannerResult {
        &self.final_planner
    }

    pub fn build(&self) -> &TrustedCargoBuildResult {
        &self.build
    }
}

pub fn create_production_integration_post_payload(
    receipt: &ProductionIntegrationPreReceipt,
    closure: &NormalizedHostBuildInputClosure,
    policy: &NormalizedProductionBuildPolicy,
    composition_build: &VerifiedProductionBuildAttestation,
    executor: &VerifiedProductionBuildAttestation,
    input: ProductionIntegrationPostInput,
) -> Result<crate::ProductionBuildAttestationPayload, ProductionIntegrationError> {
    verify_executor_against_pre(receipt, closure, policy, composition_build, executor)?;
    let mut evidence = executor.attestation().payload.evidence.clone();
    evidence.executor_attestation_payload_digest =
        Some(executor.attestation().payload_digest.clone());
    let payload = crate::create_production_build_attestation_payload(
        executor.manifest(),
        policy,
        crate::ProductionBuildAttestationInput {
            operation: crate::ProductionOperationKind::IntegrationPost,
            executor_id: input.executor_id,
            workload_identity: input.workload_identity,
            verifier_identity_digest: input.verifier_identity_digest,
            sandbox_backend_identity: executor
                .attestation()
                .payload
                .sandbox_backend_identity
                .clone(),
            evidence,
            product_integration: executor.product_integration().cloned(),
            host_feature_policy: executor.attestation().payload.host_feature_policy.clone(),
        },
    )?;
    verify_post_payload(receipt, executor, &payload)?;
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
pub fn write_production_integration_post_attestation(
    output: &Path,
    executor_artifact_dir: &Path,
    receipt_path: &Path,
    receipt: &ProductionIntegrationPreReceipt,
    closure: &NormalizedHostBuildInputClosure,
    policy: &NormalizedProductionBuildPolicy,
    composition_build: &VerifiedProductionBuildAttestation,
    executor: &VerifiedProductionBuildAttestation,
    payload: crate::ProductionBuildAttestationPayload,
    completion_handle: crate::ProductionCompletionHandle,
    completion_nonce_directory: &Path,
    timestamp: String,
    transparency_proof: Option<String>,
) -> Result<VerifiedProductionIntegrationPostAttestation, ProductionIntegrationError> {
    validate_distinct_post_paths(output, executor.path(), receipt_path)?;
    verify_executor_against_pre(receipt, closure, policy, composition_build, executor)?;
    verify_post_payload(receipt, executor, &payload)?;
    let attestation = sign_attestation(
        executor.manifest(),
        policy,
        payload,
        completion_handle,
        completion_nonce_directory,
        timestamp,
        transparency_proof,
    )?;
    write_new_json_atomic(output, &attestation)?;
    verify_production_integration_post_attestation(
        output,
        executor_artifact_dir,
        receipt,
        closure,
        policy,
        composition_build,
        executor,
        &attestation.payload.workload_identity,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn verify_production_integration_post_attestation(
    path: &Path,
    executor_artifact_dir: &Path,
    receipt: &ProductionIntegrationPreReceipt,
    closure: &NormalizedHostBuildInputClosure,
    policy: &NormalizedProductionBuildPolicy,
    composition_build: &VerifiedProductionBuildAttestation,
    executor: &VerifiedProductionBuildAttestation,
    expected_workload_identity: &str,
) -> Result<VerifiedProductionIntegrationPostAttestation, ProductionIntegrationError> {
    verify_executor_against_pre(receipt, closure, policy, composition_build, executor)?;
    if executor_artifact_dir
        .file_name()
        .and_then(|value| value.to_str())
        != Some(executor.manifest().build_output_digest.as_str())
    {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "executor artifact root",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > 32 * 1024 * 1024 {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "post attestation file",
        ));
    }
    let attestation: crate::ProductionBuildAttestation = serde_json::from_slice(&fs::read(path)?)?;
    attestation.validate(executor.manifest(), policy)?;
    if attestation.payload.workload_identity != expected_workload_identity {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "post workload identity",
        ));
    }
    verify_post_payload(receipt, executor, &attestation.payload)?;
    Ok(VerifiedProductionIntegrationPostAttestation { attestation })
}

impl VerifiedProductionIntegrationPostAttestation {
    pub fn attestation(&self) -> &crate::ProductionBuildAttestation {
        &self.attestation
    }
}

fn verify_executor_against_pre(
    receipt: &ProductionIntegrationPreReceipt,
    closure: &NormalizedHostBuildInputClosure,
    policy: &NormalizedProductionBuildPolicy,
    composition_build: &VerifiedProductionBuildAttestation,
    executor: &VerifiedProductionBuildAttestation,
) -> Result<(), ProductionIntegrationError> {
    receipt.verify(closure, policy, composition_build)?;
    let payload = &executor.attestation().payload;
    let evidence = &payload.evidence;
    if payload.operation != crate::ProductionOperationKind::BuildHost
        || payload.build_execution_policy_digest != policy.full_digest()
        || payload.composition_hash != receipt.composition_hash
        || evidence.pre_receipt_digest.as_deref() != Some(receipt.digest.as_str())
        || evidence.executor_attestation_payload_digest.is_some()
        || evidence.host_build_input_closure_digest != receipt.host_build_input_closure_digest
        || evidence.build_input_content_digest != receipt.build_input_content_digest
        || evidence.standalone_planned_unit_graph_digest != receipt.standalone_unit_graph_digest
        || evidence.final_planned_unit_graph_digest != receipt.final_unit_graph_digest
        || evidence.observed_unit_graph_digest != receipt.final_unit_graph_digest
        || evidence.unit_feature_delta_digest != receipt.unit_feature_delta_digest
        || executor.manifest().build_requirements != *closure.build_requirements()
        || payload.product_integration.as_ref() != Some(&receipt.host_feature_accounting)
        || executor.manifest().effective_compiled_runtime_effects
            != receipt
                .host_feature_accounting
                .product_compiled_runtime_effects
    {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "executor attestation differs from pre receipt",
        ));
    }
    Ok(())
}

fn verify_post_payload(
    receipt: &ProductionIntegrationPreReceipt,
    executor: &VerifiedProductionBuildAttestation,
    payload: &crate::ProductionBuildAttestationPayload,
) -> Result<(), ProductionIntegrationError> {
    if payload.operation != crate::ProductionOperationKind::IntegrationPost
        || payload.evidence.pre_receipt_digest.as_deref() != Some(receipt.digest.as_str())
        || payload
            .evidence
            .executor_attestation_payload_digest
            .as_deref()
            != Some(executor.attestation().payload_digest.as_str())
        || payload.build_manifest_digest != executor.manifest().build_manifest_digest
        || payload.build_output_digest != executor.manifest().build_output_digest
        || payload.artifacts != executor.manifest().artifacts
        || payload.product_integration.as_ref() != Some(&receipt.host_feature_accounting)
        || payload.effective_compiled_runtime_effects
            != executor.manifest().effective_compiled_runtime_effects
    {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "post attestation does not bind executor output",
        ));
    }
    Ok(())
}

fn validate_distinct_post_paths(
    output: &Path,
    executor_attestation: &Path,
    receipt_path: &Path,
) -> Result<(), ProductionIntegrationError> {
    if !output.is_absolute()
        || output.exists()
        || output == receipt_path
        || output == executor_attestation
    {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "pre, executor, and post paths must be distinct and new",
        ));
    }
    Ok(())
}

fn write_new_json_atomic<T: Serialize>(
    output: &Path,
    value: &T,
) -> Result<(), ProductionIntegrationError> {
    if !output.is_absolute() || output.file_name().is_none() || output.exists() {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "receipt output path",
        ));
    }
    let parent = output
        .parent()
        .ok_or(ProductionIntegrationError::InvalidReceipt("receipt parent"))?;
    if !parent.is_dir() || fs::canonicalize(parent)? != parent {
        return Err(ProductionIntegrationError::InvalidReceipt("receipt parent"));
    }
    let parent = crate::snapshot_materializer::anchor_writable_directory(parent)?;
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    let name = output.file_name().and_then(|value| value.to_str()).ok_or(
        ProductionIntegrationError::InvalidReceipt("receipt output name"),
    )?;
    if !parent.write_new_file_atomic(name, &bytes, 0o444)? {
        return Err(ProductionIntegrationError::InvalidReceipt(
            "receipt output already exists",
        ));
    }
    Ok(())
}
