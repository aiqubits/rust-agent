use std::{
    collections::BTreeSet,
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rust_agent_composition::canonical;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BuildEnforcementIdentity, DerivedExecutablePolicy, LinuxSandboxBackendIdentity,
    LinuxSandboxRuntimeIdentity, LinuxSandboxRuntimeSymlink, NormalizedProductionBuildPolicy,
    ProductionArtifactError, ProductionArtifactRecord, ProductionBuildManifest,
    ProductionCargoInvocationIdentity, ProductionEnvironment, ProductionFetchRedirectPolicy,
    ProductionSandboxBackend, SnapshotMaterializationError, TrustedReviewerPolicy, TrustedSigner,
    artifact::sha256_hex,
    production_artifact::{
        ProductionArtifactPublicationPermit, inspect_production_build_manifest,
        read_staged_production_manifest,
    },
    snapshot_materializer::{anchor_file_identity, anchor_writable_directory},
};

const MAX_ATTESTATION_BYTES: usize = 32 * 1024 * 1024;
const MAX_SIGNING_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_PUBLIC_KEY_BYTES: usize = 4 * 1024;
const SIGNING_TIMEOUT: Duration = Duration::from_secs(30);
const POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionOperationKind {
    Build,
    BuildHost,
    IntegrationPost,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionExecutionEvidence {
    pub schema: u32,
    #[serde(rename = "pre-receipt-digest", skip_serializing_if = "Option::is_none")]
    pub pre_receipt_digest: Option<String>,
    #[serde(
        rename = "executor-attestation-payload-digest",
        skip_serializing_if = "Option::is_none"
    )]
    pub executor_attestation_payload_digest: Option<String>,
    #[serde(rename = "host-build-input-closure-digest")]
    pub host_build_input_closure_digest: String,
    #[serde(rename = "build-input-content-digest")]
    pub build_input_content_digest: String,
    #[serde(rename = "production-input-request-digest")]
    pub production_input_request_digest: String,
    #[serde(rename = "production-input-observation-digest")]
    pub production_input_observation_digest: String,
    #[serde(rename = "target-facts-request-digest")]
    pub target_facts_request_digest: String,
    #[serde(rename = "target-facts-observation-digest")]
    pub target_facts_observation_digest: String,
    #[serde(rename = "standalone-planner-request-digest")]
    pub standalone_planner_request_digest: String,
    #[serde(rename = "final-planner-request-digest")]
    pub final_planner_request_digest: String,
    #[serde(rename = "standalone-planned-unit-graph-digest")]
    pub standalone_planned_unit_graph_digest: String,
    #[serde(rename = "final-planned-unit-graph-digest")]
    pub final_planned_unit_graph_digest: String,
    #[serde(rename = "observed-unit-graph-digest")]
    pub observed_unit_graph_digest: String,
    #[serde(rename = "unit-feature-delta-digest")]
    pub unit_feature_delta_digest: String,
    #[serde(rename = "sandbox-observation-digest")]
    pub sandbox_observation_digest: String,
    #[serde(rename = "cargo-messages-digest")]
    pub cargo_messages_digest: String,
    #[serde(
        rename = "wasm-postprocessor-observation-digest",
        skip_serializing_if = "Option::is_none"
    )]
    pub wasm_postprocessor_observation_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionBuildAttestationPayload {
    pub schema: u32,
    pub operation: ProductionOperationKind,
    #[serde(rename = "executor-id")]
    pub executor_id: String,
    #[serde(rename = "workload-identity")]
    pub workload_identity: String,
    #[serde(rename = "verifier-identity-digest")]
    pub verifier_identity_digest: String,
    #[serde(rename = "build-execution-policy")]
    pub build_execution_policy: ProductionBuildPolicyAttestation,
    #[serde(rename = "build-execution-policy-digest")]
    pub build_execution_policy_digest: String,
    #[serde(rename = "sandbox-backend")]
    pub sandbox_backend: ProductionSandboxBackend,
    #[serde(rename = "sandbox-backend-identity")]
    pub sandbox_backend_identity: LinuxSandboxBackendAttestation,
    #[serde(rename = "sandbox-backend-identity-digest")]
    pub sandbox_backend_identity_digest: String,
    #[serde(rename = "composition-hash")]
    pub composition_hash: String,
    #[serde(rename = "build-manifest-digest")]
    pub build_manifest_digest: String,
    #[serde(rename = "build-output-digest")]
    pub build_output_digest: String,
    #[serde(rename = "build-enforcement-identity")]
    pub build_enforcement_identity: BuildEnforcementIdentity,
    #[serde(rename = "build-enforcement-identity-digest")]
    pub build_enforcement_identity_digest: String,
    pub evidence: ProductionExecutionEvidence,
    #[serde(rename = "evidence-digest")]
    pub evidence_digest: String,
    #[serde(rename = "cargo-invocation")]
    pub cargo_invocation: ProductionCargoInvocationIdentity,
    pub artifacts: Vec<ProductionArtifactRecord>,
    #[serde(rename = "product-integration")]
    pub product_integration: Option<crate::ProductionHostFeatureReceipt>,
    #[serde(rename = "host-feature-policy")]
    pub host_feature_policy: Option<crate::HostFeatureUnionPolicy>,
    #[serde(rename = "effective-compiled-runtime-effects")]
    pub effective_compiled_runtime_effects: BTreeSet<String>,
    pub deployable: bool,
}

#[derive(Clone, Debug)]
pub struct ProductionBuildAttestationInput {
    pub operation: ProductionOperationKind,
    pub executor_id: String,
    pub workload_identity: String,
    pub verifier_identity_digest: String,
    pub sandbox_backend_identity: LinuxSandboxBackendAttestation,
    pub evidence: ProductionExecutionEvidence,
    pub product_integration: Option<crate::VerifiedProductionHostFeatureReceipt>,
    pub host_feature_policy: Option<crate::HostFeatureUnionPolicy>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionBuildPolicyAttestation {
    pub schema: u32,
    pub id: String,
    pub host: String,
    pub backend: ProductionSandboxBackend,
    pub fetch: ProductionFetchPolicyAttestation,
    pub attestation: ProductionTrustPolicyAttestation,
    pub toolchain: ProductionToolchainAttestation,
    #[serde(rename = "read-input", default)]
    pub read_inputs: Vec<ProductionReadInputAttestation>,
    #[serde(rename = "executable", default)]
    pub executables: Vec<ProductionExecutableAttestation>,
    #[serde(rename = "environment", default)]
    pub environment: Vec<ProductionEnvironment>,
    #[serde(rename = "derived-executable")]
    pub derived_executable: DerivedExecutablePolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionFetchPolicyAttestation {
    #[serde(rename = "network-endpoints")]
    pub network_endpoints: Vec<String>,
    #[serde(rename = "credential-helper", default)]
    pub credential_helper: Option<ProductionFileAttestation>,
    #[serde(rename = "tls-ca-bundle", default)]
    pub tls_ca_bundle: Option<ProductionFileAttestation>,
    #[serde(rename = "redirect-policy")]
    pub redirect_policy: ProductionFetchRedirectPolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionTrustPolicyAttestation {
    #[serde(rename = "allowed-executors")]
    pub allowed_executors: Vec<String>,
    #[serde(rename = "trusted-signers")]
    pub trusted_signers: Vec<TrustedSignerAttestation>,
    #[serde(rename = "trusted-reviewer-policies", default)]
    pub trusted_reviewer_policies: Vec<TrustedReviewerPolicy>,
    #[serde(rename = "signing-helper")]
    pub signing_helper: SigningHelperAttestation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedSignerAttestation {
    pub id: String,
    pub algorithm: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningHelperAttestation {
    #[serde(rename = "signer-id")]
    pub signer_id: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionToolchainAttestation {
    pub cargo: ProductionToolAttestation,
    pub rustc: ProductionToolAttestation,
    pub sysroot: ProductionTreeAttestation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionToolAttestation {
    pub sha256: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionFileAttestation {
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionTreeAttestation {
    #[serde(rename = "tree-digest")]
    pub tree_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionReadInputAttestation {
    pub id: String,
    #[serde(rename = "tree-digest")]
    pub tree_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionExecutableAttestation {
    pub id: String,
    pub sha256: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxSandboxBackendAttestation {
    pub schema: u32,
    pub executable: ProductionToolAttestation,
    #[serde(rename = "launcher-executable")]
    pub launcher_executable: ProductionToolAttestation,
    pub runtime: LinuxSandboxRuntimeAttestation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxSandboxRuntimeAttestation {
    pub tree: ProductionTreeAttestation,
    #[serde(rename = "logical-path")]
    pub logical_path: String,
    #[serde(rename = "interpreter-paths")]
    pub interpreter_paths: Vec<String>,
    #[serde(rename = "library-paths")]
    pub library_paths: Vec<String>,
    #[serde(rename = "null-input-path")]
    pub null_input_path: String,
    pub symlinks: Vec<LinuxSandboxRuntimeSymlink>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCompletionHandlePayload {
    pub schema: u32,
    pub operation: ProductionOperationKind,
    #[serde(rename = "executor-id")]
    pub executor_id: String,
    #[serde(rename = "workload-identity")]
    pub workload_identity: String,
    #[serde(rename = "verifier-identity-digest")]
    pub verifier_identity_digest: String,
    #[serde(rename = "backend-identity-digest")]
    pub backend_identity_digest: String,
    #[serde(rename = "upstream-evidence-digest")]
    pub upstream_evidence_digest: String,
    #[serde(rename = "attestation-payload-digest")]
    pub attestation_payload_digest: String,
    pub nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCompletionHandle {
    pub payload: ProductionCompletionHandlePayload,
    #[serde(rename = "signer-id")]
    pub signer_id: String,
    pub algorithm: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionBuildAttestation {
    pub schema: u32,
    pub payload: ProductionBuildAttestationPayload,
    #[serde(rename = "payload-digest")]
    pub payload_digest: String,
    #[serde(rename = "completion-handle")]
    pub completion_handle: ProductionCompletionHandle,
    #[serde(rename = "signer-id")]
    pub signer_id: String,
    pub algorithm: String,
    pub signature: String,
    pub nonce: String,
    pub timestamp: String,
    #[serde(rename = "transparency-proof", skip_serializing_if = "Option::is_none")]
    pub transparency_proof: Option<String>,
}

#[derive(Debug)]
pub struct VerifiedProductionBuildAttestation {
    attestation: ProductionBuildAttestation,
    manifest: ProductionBuildManifest,
    path: PathBuf,
    product_integration: Option<crate::VerifiedProductionHostFeatureReceipt>,
}

/// A signed append-only attestation that has been published and rechecked
/// against a still-private production artifact staging directory.
#[derive(Debug)]
pub struct PreparedProductionBuildAttestationPublication {
    path: PathBuf,
    permit: ProductionArtifactPublicationPermit,
    workload_identity: String,
}

#[derive(Debug, Error)]
pub enum ProductionAttestationError {
    #[error("production attestation I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("production attestation JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("production attestation canonical encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
    #[error("production artifact verification failed: {0}")]
    Artifact(#[from] ProductionArtifactError),
    #[error("production attestation input snapshot failed: {0}")]
    Snapshot(#[from] SnapshotMaterializationError),
    #[error("production attestation policy failed: {0}")]
    Policy(#[from] crate::ProductionBuildPolicyError),
    #[error("production Host feature accounting failed: {0}")]
    HostFeature(#[from] crate::HostFeaturePolicyError),
    #[error("production attestation sandbox identity failed: {0}")]
    Sandbox(#[from] crate::LinuxSandboxError),
    #[error("production attestation is invalid: {0}")]
    Invalid(&'static str),
    #[error("production signing helper failed: {0}")]
    SigningHelper(String),
    #[error("production completion handle nonce was already consumed")]
    CompletionReplay,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SigningHelperRequest<'a> {
    schema: u32,
    protocol: &'static str,
    operation: ProductionOperationKind,
    #[serde(rename = "payload-digest")]
    payload_digest: &'a str,
    #[serde(rename = "workload-identity")]
    workload_identity: &'a str,
    #[serde(rename = "completion-handle")]
    completion_handle: &'a ProductionCompletionHandle,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningHelperResponse {
    schema: u32,
    #[serde(rename = "signer-id")]
    signer_id: String,
    algorithm: String,
    signature: String,
}

impl ProductionBuildPolicyAttestation {
    fn from_normalized(policy: &NormalizedProductionBuildPolicy) -> Self {
        let policy = policy.policy();
        Self {
            schema: policy.schema,
            id: policy.id.clone(),
            host: policy.host.clone(),
            backend: policy.backend,
            fetch: ProductionFetchPolicyAttestation {
                network_endpoints: policy.fetch.network_endpoints.clone(),
                credential_helper: policy.fetch.credential_helper.as_ref().map(|file| {
                    ProductionFileAttestation {
                        sha256: file.sha256.clone(),
                    }
                }),
                tls_ca_bundle: policy.fetch.tls_ca_bundle.as_ref().map(|file| {
                    ProductionFileAttestation {
                        sha256: file.sha256.clone(),
                    }
                }),
                redirect_policy: policy.fetch.redirect_policy,
            },
            attestation: ProductionTrustPolicyAttestation {
                allowed_executors: policy.attestation.allowed_executors.clone(),
                trusted_signers: policy
                    .attestation
                    .trusted_signers
                    .iter()
                    .map(|signer| TrustedSignerAttestation {
                        id: signer.id.clone(),
                        algorithm: signer.algorithm.clone(),
                        sha256: signer.sha256.clone(),
                    })
                    .collect(),
                trusted_reviewer_policies: policy.attestation.trusted_reviewer_policies.clone(),
                signing_helper: SigningHelperAttestation {
                    signer_id: policy.attestation.signing_helper.signer_id.clone(),
                    sha256: policy.attestation.signing_helper.sha256.clone(),
                },
            },
            toolchain: ProductionToolchainAttestation {
                cargo: ProductionToolAttestation {
                    sha256: policy.toolchain.cargo.sha256.clone(),
                    version: policy.toolchain.cargo.version.clone(),
                },
                rustc: ProductionToolAttestation {
                    sha256: policy.toolchain.rustc.sha256.clone(),
                    version: policy.toolchain.rustc.version.clone(),
                },
                sysroot: ProductionTreeAttestation {
                    tree_digest: policy.toolchain.sysroot.tree_digest.clone(),
                },
            },
            read_inputs: policy
                .read_inputs
                .iter()
                .map(|input| ProductionReadInputAttestation {
                    id: input.id.clone(),
                    tree_digest: input.tree_digest.clone(),
                })
                .collect(),
            executables: policy
                .executables
                .iter()
                .map(|executable| ProductionExecutableAttestation {
                    id: executable.id.clone(),
                    sha256: executable.sha256.clone(),
                    version: executable.version.clone(),
                })
                .collect(),
            environment: policy.environment.clone(),
            derived_executable: policy.derived_executable.clone(),
        }
    }
}

impl TryFrom<&LinuxSandboxBackendIdentity> for LinuxSandboxBackendAttestation {
    type Error = crate::LinuxSandboxError;

    fn try_from(identity: &LinuxSandboxBackendIdentity) -> Result<Self, Self::Error> {
        identity.validate_declaration()?;
        Ok(Self {
            schema: identity.schema,
            executable: ProductionToolAttestation {
                sha256: identity.executable.sha256.clone(),
                version: identity.executable.version.clone(),
            },
            launcher_executable: ProductionToolAttestation {
                sha256: identity.launcher_executable.sha256.clone(),
                version: identity.launcher_executable.version.clone(),
            },
            runtime: LinuxSandboxRuntimeAttestation {
                tree: ProductionTreeAttestation {
                    tree_digest: identity.runtime.tree.tree_digest.clone(),
                },
                logical_path: identity.runtime.logical_path.clone(),
                interpreter_paths: identity.runtime.interpreter_paths.clone(),
                library_paths: identity.runtime.library_paths.clone(),
                null_input_path: identity.runtime.null_input_path.clone(),
                symlinks: identity.runtime.symlinks.clone(),
            },
        })
    }
}

impl LinuxSandboxBackendAttestation {
    fn validate_declaration(&self) -> Result<(), crate::LinuxSandboxError> {
        LinuxSandboxBackendIdentity {
            schema: self.schema,
            executable: crate::ProductionToolIdentity {
                path: PathBuf::from("/redacted/backend"),
                sha256: self.executable.sha256.clone(),
                version: self.executable.version.clone(),
            },
            launcher_executable: crate::ProductionToolIdentity {
                path: PathBuf::from("/redacted/launcher"),
                sha256: self.launcher_executable.sha256.clone(),
                version: self.launcher_executable.version.clone(),
            },
            runtime: LinuxSandboxRuntimeIdentity {
                tree: crate::ProductionTreeIdentity {
                    path: PathBuf::from("/redacted/runtime"),
                    tree_digest: self.runtime.tree.tree_digest.clone(),
                },
                logical_path: self.runtime.logical_path.clone(),
                interpreter_paths: self.runtime.interpreter_paths.clone(),
                library_paths: self.runtime.library_paths.clone(),
                null_input_path: self.runtime.null_input_path.clone(),
                symlinks: self.runtime.symlinks.clone(),
            },
        }
        .validate_declaration()
    }
}

pub fn create_production_build_attestation_payload(
    manifest: &ProductionBuildManifest,
    policy: &NormalizedProductionBuildPolicy,
    input: ProductionBuildAttestationInput,
) -> Result<ProductionBuildAttestationPayload, ProductionAttestationError> {
    let enforcement = policy.enforcement_identity(
        &manifest.build_requirements,
        &manifest.build_enforcement_identity.context,
    )?;
    if enforcement != manifest.build_enforcement_identity {
        return Err(ProductionAttestationError::Invalid(
            "manifest enforcement identity differs from policy projection",
        ));
    }
    let evidence_digest = input.evidence.digest()?;
    let backend_identity_digest = backend_identity_digest(&input.sandbox_backend_identity)?;
    let payload = ProductionBuildAttestationPayload {
        schema: 1,
        operation: input.operation,
        executor_id: input.executor_id,
        workload_identity: input.workload_identity,
        verifier_identity_digest: input.verifier_identity_digest,
        build_execution_policy: ProductionBuildPolicyAttestation::from_normalized(policy),
        build_execution_policy_digest: policy.full_digest().into(),
        sandbox_backend: policy.policy().backend,
        sandbox_backend_identity: input.sandbox_backend_identity,
        sandbox_backend_identity_digest: backend_identity_digest,
        composition_hash: manifest.composition.composition_hash.clone(),
        build_manifest_digest: manifest.build_manifest_digest.clone(),
        build_output_digest: manifest.build_output_digest.clone(),
        build_enforcement_identity: manifest.build_enforcement_identity.clone(),
        build_enforcement_identity_digest: manifest.build_enforcement_identity_digest.clone(),
        evidence: input.evidence,
        evidence_digest,
        cargo_invocation: manifest.cargo_invocation.clone(),
        artifacts: manifest.artifacts.clone(),
        product_integration: input
            .product_integration
            .map(|verified| verified.receipt().clone()),
        host_feature_policy: input.host_feature_policy,
        effective_compiled_runtime_effects: manifest.effective_compiled_runtime_effects.clone(),
        deployable: true,
    };
    payload.validate(manifest, policy)?;
    Ok(payload)
}

#[expect(
    clippy::too_many_arguments,
    reason = "artifact, append-only attestation and nonce roots are distinct security boundaries"
)]
pub fn write_production_build_attestation(
    artifact_dir: &Path,
    attestation_root: &Path,
    policy: &NormalizedProductionBuildPolicy,
    payload: ProductionBuildAttestationPayload,
    completion_handle: ProductionCompletionHandle,
    completion_nonce_directory: &Path,
    timestamp: String,
    transparency_proof: Option<String>,
) -> Result<VerifiedProductionBuildAttestation, ProductionAttestationError> {
    let manifest = inspect_production_build_manifest(artifact_dir, None, None)?;
    let attestation = sign_production_build_attestation(
        &manifest,
        policy,
        payload,
        completion_handle,
        completion_nonce_directory,
        timestamp,
        transparency_proof,
    )?;
    publish_production_build_attestation(artifact_dir, attestation_root, policy, &attestation)
}

pub fn sign_production_build_attestation(
    manifest: &ProductionBuildManifest,
    policy: &NormalizedProductionBuildPolicy,
    payload: ProductionBuildAttestationPayload,
    completion_handle: ProductionCompletionHandle,
    completion_nonce_directory: &Path,
    timestamp: String,
    transparency_proof: Option<String>,
) -> Result<ProductionBuildAttestation, ProductionAttestationError> {
    sign_attestation(
        manifest,
        policy,
        payload,
        completion_handle,
        completion_nonce_directory,
        timestamp,
        transparency_proof,
    )
}

pub fn publish_production_build_attestation(
    artifact_dir: &Path,
    attestation_root: &Path,
    policy: &NormalizedProductionBuildPolicy,
    attestation: &ProductionBuildAttestation,
) -> Result<VerifiedProductionBuildAttestation, ProductionAttestationError> {
    let manifest = inspect_production_build_manifest(artifact_dir, None, None)?;
    let path = publish_attestation_file(
        artifact_dir,
        attestation_root,
        policy,
        &manifest,
        attestation,
    )?;
    verify_production_build_attestation(
        artifact_dir,
        &path,
        policy,
        &attestation.payload.workload_identity,
    )
}

/// Publishes and verifies the append-only attestation before a deployable
/// artifact directory is made visible. The opaque permit is required by
/// `publish_production_artifact`, preventing callers from reversing this order.
pub fn prepare_production_build_attestation_publication(
    staging: &Path,
    attestation_root: &Path,
    policy: &NormalizedProductionBuildPolicy,
    attestation: &ProductionBuildAttestation,
) -> Result<PreparedProductionBuildAttestationPublication, ProductionAttestationError> {
    let manifest = read_staged_production_manifest(staging)?;
    let path = publish_attestation_file(staging, attestation_root, policy, &manifest, attestation)?;
    let bytes = read_bounded(&path, MAX_ATTESTATION_BYTES)?;
    let published: ProductionBuildAttestation = serde_json::from_slice(&bytes)?;
    if published != *attestation {
        return Err(ProductionAttestationError::Invalid(
            "published attestation differs from the signed staging attestation",
        ));
    }
    published.validate(&manifest, policy)?;
    validate_attestation_address(&path, &manifest, &published)?;
    Ok(PreparedProductionBuildAttestationPublication {
        permit: ProductionArtifactPublicationPermit::new(
            &manifest,
            path.clone(),
            sha256_hex(&bytes),
        ),
        path,
        workload_identity: published.payload.workload_identity,
    })
}

impl PreparedProductionBuildAttestationPublication {
    pub fn artifact_publication_permit(&self) -> &ProductionArtifactPublicationPermit {
        &self.permit
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn finalize(
        self,
        artifact_dir: &Path,
        policy: &NormalizedProductionBuildPolicy,
    ) -> Result<VerifiedProductionBuildAttestation, ProductionAttestationError> {
        verify_production_build_attestation(
            artifact_dir,
            &self.path,
            policy,
            &self.workload_identity,
        )
    }
}

fn publish_attestation_file(
    artifact_dir: &Path,
    attestation_root: &Path,
    policy: &NormalizedProductionBuildPolicy,
    manifest: &ProductionBuildManifest,
    attestation: &ProductionBuildAttestation,
) -> Result<PathBuf, ProductionAttestationError> {
    let canonical_artifact = fs::canonicalize(artifact_dir)?;
    if !attestation_root.is_absolute()
        || !attestation_root.is_dir()
        || fs::symlink_metadata(attestation_root)?
            .file_type()
            .is_symlink()
        || fs::canonicalize(attestation_root)? != attestation_root
        || attestation_root.starts_with(&canonical_artifact)
        || canonical_artifact.starts_with(attestation_root)
    {
        return Err(ProductionAttestationError::Invalid(
            "attestation root must be absolute and separate from the artifact root",
        ));
    }
    attestation.validate(manifest, policy)?;
    let root = anchor_writable_directory(attestation_root)?;
    let composition_directory =
        root.create_or_open_child_directory(&manifest.composition.composition_hash)?;
    let output_directory =
        composition_directory.create_or_open_child_directory(&manifest.build_output_digest)?;
    let manifest_directory =
        output_directory.create_or_open_child_directory(&manifest.build_manifest_digest)?;
    let attestation_parent = attestation_parent(attestation_root, manifest);
    let mut bytes = serde_json::to_vec_pretty(attestation)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_ATTESTATION_BYTES {
        return Err(ProductionAttestationError::Invalid(
            "attestation exceeds size bound",
        ));
    }
    let attestation_digest = attestation.digest()?;
    let path = attestation_parent.join(format!("{attestation_digest}.json"));
    let file_name = format!("{attestation_digest}.json");
    if !manifest_directory.write_new_file_atomic(&file_name, &bytes, 0o444)? {
        let existing = manifest_directory.anchor_file(&file_name)?;
        if existing.read_bytes(MAX_ATTESTATION_BYTES)? != bytes {
            return Err(ProductionAttestationError::Invalid(
                "append-only attestation address already contains different bytes",
            ));
        }
    }
    Ok(path)
}

pub(crate) fn sign_attestation(
    manifest: &ProductionBuildManifest,
    policy: &NormalizedProductionBuildPolicy,
    payload: ProductionBuildAttestationPayload,
    completion_handle: ProductionCompletionHandle,
    completion_nonce_directory: &Path,
    timestamp: String,
    transparency_proof: Option<String>,
) -> Result<ProductionBuildAttestation, ProductionAttestationError> {
    payload.validate(manifest, policy)?;
    let payload_digest = payload.digest()?;
    verify_completion_handle(&completion_handle, policy, &payload, &payload_digest)?;
    validate_outer_fields(
        &completion_handle.payload.nonce,
        &timestamp,
        transparency_proof.as_deref(),
    )?;
    consume_completion_nonce(completion_nonce_directory, &completion_handle)?;
    let response = invoke_signing_helper(policy, &payload, &payload_digest, &completion_handle)?;
    let signer = trusted_signer(policy, &response.signer_id)?;
    if response.schema != 1
        || response.signer_id != policy.policy().attestation.signing_helper.signer_id
        || response.algorithm != "ed25519"
    {
        return Err(ProductionAttestationError::Invalid(
            "signing helper response identity mismatch",
        ));
    }
    verify_digest_signature(signer, &payload_digest, &response.signature)?;
    let nonce = completion_handle.payload.nonce.clone();
    let attestation = ProductionBuildAttestation {
        schema: 1,
        payload,
        payload_digest,
        completion_handle,
        signer_id: response.signer_id,
        algorithm: response.algorithm,
        signature: response.signature,
        nonce,
        timestamp,
        transparency_proof,
    };
    attestation.validate(manifest, policy)?;
    Ok(attestation)
}

pub fn verify_production_build_attestation(
    artifact_dir: &Path,
    attestation_path: &Path,
    policy: &NormalizedProductionBuildPolicy,
    expected_workload_identity: &str,
) -> Result<VerifiedProductionBuildAttestation, ProductionAttestationError> {
    let manifest = inspect_production_build_manifest(artifact_dir, None, None)?;
    let bytes = read_bounded(attestation_path, MAX_ATTESTATION_BYTES)?;
    let attestation: ProductionBuildAttestation = serde_json::from_slice(&bytes)?;
    if attestation.payload.workload_identity != expected_workload_identity {
        return Err(ProductionAttestationError::Invalid(
            "workload identity mismatch",
        ));
    }
    attestation.validate(&manifest, policy)?;
    validate_attestation_address(attestation_path, &manifest, &attestation)?;
    let product_integration = attestation
        .payload
        .product_integration
        .clone()
        .map(crate::VerifiedProductionHostFeatureReceipt::from_attested)
        .transpose()?;
    Ok(VerifiedProductionBuildAttestation {
        attestation,
        manifest,
        path: attestation_path.to_owned(),
        product_integration,
    })
}

impl VerifiedProductionBuildAttestation {
    pub fn attestation(&self) -> &ProductionBuildAttestation {
        &self.attestation
    }

    pub fn manifest(&self) -> &ProductionBuildManifest {
        &self.manifest
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn product_integration(&self) -> Option<&crate::VerifiedProductionHostFeatureReceipt> {
        self.product_integration.as_ref()
    }
}

impl ProductionExecutionEvidence {
    pub fn digest(&self) -> Result<String, ProductionAttestationError> {
        self.validate_common()?;
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-production-execution-evidence-v1\0",
            self,
        )?))
    }

    fn validate(
        &self,
        operation: ProductionOperationKind,
        is_wasm: bool,
    ) -> Result<(), ProductionAttestationError> {
        self.validate_common()?;
        let requires_pre = matches!(
            operation,
            ProductionOperationKind::BuildHost | ProductionOperationKind::IntegrationPost
        );
        let requires_executor = operation == ProductionOperationKind::IntegrationPost;
        if requires_pre != self.pre_receipt_digest.is_some()
            || requires_executor != self.executor_attestation_payload_digest.is_some()
            || is_wasm != self.wasm_postprocessor_observation_digest.is_some()
        {
            return Err(ProductionAttestationError::Invalid(
                "execution evidence operation shape is invalid",
            ));
        }
        Ok(())
    }

    fn validate_common(&self) -> Result<(), ProductionAttestationError> {
        let required = [
            &self.host_build_input_closure_digest,
            &self.build_input_content_digest,
            &self.production_input_request_digest,
            &self.production_input_observation_digest,
            &self.target_facts_request_digest,
            &self.target_facts_observation_digest,
            &self.standalone_planner_request_digest,
            &self.final_planner_request_digest,
            &self.standalone_planned_unit_graph_digest,
            &self.final_planned_unit_graph_digest,
            &self.observed_unit_graph_digest,
            &self.unit_feature_delta_digest,
            &self.sandbox_observation_digest,
            &self.cargo_messages_digest,
        ];
        if self.schema != 1
            || required.into_iter().any(|digest| !is_digest(digest))
            || self
                .pre_receipt_digest
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
            || self
                .executor_attestation_payload_digest
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
            || self
                .wasm_postprocessor_observation_digest
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
            || self.final_planned_unit_graph_digest != self.observed_unit_graph_digest
        {
            return Err(ProductionAttestationError::Invalid(
                "execution evidence shape or graph equality is invalid",
            ));
        }
        Ok(())
    }
}

impl ProductionBuildAttestationPayload {
    pub fn digest(&self) -> Result<String, ProductionAttestationError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-production-build-attestation-payload-v1\0",
            self,
        )?))
    }

    fn validate(
        &self,
        manifest: &ProductionBuildManifest,
        expected_policy: &NormalizedProductionBuildPolicy,
    ) -> Result<(), ProductionAttestationError> {
        self.sandbox_backend_identity.validate_declaration()?;
        let expected_policy_attestation =
            ProductionBuildPolicyAttestation::from_normalized(expected_policy);
        let expected_enforcement = expected_policy.enforcement_identity(
            &manifest.build_requirements,
            &manifest.build_enforcement_identity.context,
        )?;
        self.evidence.validate(
            self.operation,
            manifest.build_options.build_kind == rust_agent_composition::profile::BuildKind::Wasm,
        )?;
        if let Some(integration) = &self.product_integration {
            integration.verify_identity()?;
        }
        let normalized_feature_policy = self
            .host_feature_policy
            .as_ref()
            .map(crate::HostFeatureUnionPolicy::normalize)
            .transpose()?;
        let embedded_feature_policy_digest = normalized_feature_policy
            .as_ref()
            .map(crate::NormalizedHostFeaturePolicy::digest);
        let requires_product_integration = matches!(
            self.operation,
            ProductionOperationKind::BuildHost | ProductionOperationKind::IntegrationPost
        );
        if self.schema != 1
            || !self.deployable
            || manifest.build_options.host_integration != requires_product_integration
            || self.product_integration.is_some() != requires_product_integration
            || self.host_feature_policy.is_some()
                != self
                    .product_integration
                    .as_ref()
                    .and_then(|integration| integration.policy_digest.as_ref())
                    .is_some()
            || self
                .product_integration
                .as_ref()
                .is_some_and(|integration| {
                    !integration.deployable
                        || integration.standalone_unit_graph_digest
                            != self.evidence.standalone_planned_unit_graph_digest
                        || integration.final_unit_graph_digest
                            != self.evidence.final_planned_unit_graph_digest
                        || integration.observed_unit_graph_digest
                            != self.evidence.observed_unit_graph_digest
                        || integration.digest != self.evidence.unit_feature_delta_digest
                        || integration.product_compiled_runtime_effects
                            != self.effective_compiled_runtime_effects
                        || integration.policy_digest.as_deref() != embedded_feature_policy_digest
                })
            || !valid_identity(&self.executor_id)
            || !valid_text(&self.workload_identity, 4096)
            || !is_digest(&self.verifier_identity_digest)
            || !expected_policy
                .policy()
                .attestation
                .allowed_executors
                .contains(&self.executor_id)
            || self.build_execution_policy != expected_policy_attestation
            || self.build_execution_policy_digest != expected_policy.full_digest()
            || self.sandbox_backend != expected_policy.policy().backend
            || self.sandbox_backend_identity_digest
                != backend_identity_digest(&self.sandbox_backend_identity)?
            || self.composition_hash != manifest.composition.composition_hash
            || self.build_manifest_digest != manifest.build_manifest_digest
            || self.build_output_digest != manifest.build_output_digest
            || self.build_enforcement_identity != expected_enforcement
            || self.build_enforcement_identity != manifest.build_enforcement_identity
            || self.build_enforcement_identity_digest != manifest.build_enforcement_identity_digest
            || self.evidence_digest != self.evidence.digest_unchecked()?
            || self.evidence.build_input_content_digest
                != manifest.enforcement_result.build_input_content_digest
            || self.evidence.final_planned_unit_graph_digest
                != manifest.enforcement_result.planned_unit_graph_digest
            || self.evidence.observed_unit_graph_digest
                != manifest.enforcement_result.observed_unit_graph_digest
            || self.evidence.cargo_messages_digest
                != manifest.enforcement_result.cargo_messages_digest
            || self.cargo_invocation != manifest.cargo_invocation
            || self.artifacts != manifest.artifacts
            || self.effective_compiled_runtime_effects
                != manifest.effective_compiled_runtime_effects
        {
            return Err(ProductionAttestationError::Invalid(
                "attestation payload does not match verified build state",
            ));
        }
        Ok(())
    }
}

impl ProductionExecutionEvidence {
    fn digest_unchecked(&self) -> Result<String, ProductionAttestationError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-production-execution-evidence-v1\0",
            self,
        )?))
    }
}

impl ProductionCompletionHandlePayload {
    pub fn digest(&self) -> Result<String, ProductionAttestationError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-supervisor-completion-handle-v1\0",
            self,
        )?))
    }
}

impl ProductionBuildAttestation {
    pub fn digest(&self) -> Result<String, ProductionAttestationError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-production-build-attestation-v1\0",
            self,
        )?))
    }

    pub(crate) fn validate(
        &self,
        manifest: &ProductionBuildManifest,
        policy: &NormalizedProductionBuildPolicy,
    ) -> Result<(), ProductionAttestationError> {
        self.payload.validate(manifest, policy)?;
        if self.schema != 1
            || self.payload_digest != self.payload.digest()?
            || self.signer_id != policy.policy().attestation.signing_helper.signer_id
            || self.algorithm != "ed25519"
            || self.nonce != self.completion_handle.payload.nonce
        {
            return Err(ProductionAttestationError::Invalid(
                "attestation envelope identity mismatch",
            ));
        }
        verify_completion_handle(
            &self.completion_handle,
            policy,
            &self.payload,
            &self.payload_digest,
        )?;
        validate_outer_fields(
            &self.nonce,
            &self.timestamp,
            self.transparency_proof.as_deref(),
        )?;
        verify_digest_signature(
            trusted_signer(policy, &self.signer_id)?,
            &self.payload_digest,
            &self.signature,
        )
    }
}

fn verify_completion_handle(
    handle: &ProductionCompletionHandle,
    policy: &NormalizedProductionBuildPolicy,
    payload: &ProductionBuildAttestationPayload,
    payload_digest: &str,
) -> Result<(), ProductionAttestationError> {
    let expected = ProductionCompletionHandlePayload {
        schema: 1,
        operation: payload.operation,
        executor_id: payload.executor_id.clone(),
        workload_identity: payload.workload_identity.clone(),
        verifier_identity_digest: payload.verifier_identity_digest.clone(),
        backend_identity_digest: payload.sandbox_backend_identity_digest.clone(),
        upstream_evidence_digest: payload.evidence_digest.clone(),
        attestation_payload_digest: payload_digest.into(),
        nonce: handle.payload.nonce.clone(),
    };
    if handle.payload != expected || handle.algorithm != "ed25519" {
        return Err(ProductionAttestationError::Invalid(
            "completion handle binding mismatch",
        ));
    }
    verify_digest_signature(
        trusted_signer(policy, &handle.signer_id)?,
        &handle.payload.digest()?,
        &handle.signature,
    )
}

fn invoke_signing_helper(
    policy: &NormalizedProductionBuildPolicy,
    payload: &ProductionBuildAttestationPayload,
    payload_digest: &str,
    completion_handle: &ProductionCompletionHandle,
) -> Result<SigningHelperResponse, ProductionAttestationError> {
    let declared = &policy.policy().attestation.signing_helper;
    let helper = anchor_file_identity(&declared.path)?;
    if helper.sha256() != declared.sha256 || !helper.is_executable() || !helper.is_linux_elf() {
        return Err(ProductionAttestationError::Invalid(
            "signing helper bytes or executable format mismatch",
        ));
    }
    let request = SigningHelperRequest {
        schema: 1,
        protocol: "rust-agent-signing-helper-v1",
        operation: payload.operation,
        payload_digest,
        workload_identity: &payload.workload_identity,
        completion_handle,
    };
    let request = canonical::jcs_bytes(&request)?;
    let mut child = Command::new(helper.descriptor_execution_path())
        .arg("rust-agent-signing-helper-v1")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or(ProductionAttestationError::Invalid("missing helper stdin"))?
        .write_all(&request)?;
    let output = wait_bounded_output(&mut child, SIGNING_TIMEOUT)?;
    helper.reverify()?;
    if !output.status.success() {
        return Err(ProductionAttestationError::SigningHelper(format!(
            "exit={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    serde_json::from_slice(&output.stdout).map_err(Into::into)
}

struct BoundedOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn wait_bounded_output(
    child: &mut Child,
    timeout: Duration,
) -> Result<BoundedOutput, ProductionAttestationError> {
    let stdout = child
        .stdout
        .take()
        .ok_or(ProductionAttestationError::Invalid("missing helper stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or(ProductionAttestationError::Invalid("missing helper stderr"))?;
    let stdout_reader = thread::spawn(move || read_stream_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_stream_bounded(stderr));
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProductionAttestationError::SigningHelper(
                "timed out".into(),
            ));
        }
        thread::sleep(POLL_INTERVAL);
    };
    let stdout = stdout_reader.join().map_err(|_| {
        ProductionAttestationError::SigningHelper("stdout reader panicked".into())
    })??;
    let stderr = stderr_reader.join().map_err(|_| {
        ProductionAttestationError::SigningHelper("stderr reader panicked".into())
    })??;
    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
    })
}

fn read_stream_bounded(mut stream: impl Read) -> Result<Vec<u8>, io::Error> {
    let mut bytes = Vec::new();
    stream
        .by_ref()
        .take((MAX_SIGNING_OUTPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_SIGNING_OUTPUT_BYTES {
        Err(io::Error::other("signing helper output exceeds bound"))
    } else {
        Ok(bytes)
    }
}

fn consume_completion_nonce(
    directory: &Path,
    handle: &ProductionCompletionHandle,
) -> Result<(), ProductionAttestationError> {
    if !directory.is_absolute()
        || !directory.is_dir()
        || fs::canonicalize(directory)? != directory
        || !is_nonce(&handle.payload.nonce)
    {
        return Err(ProductionAttestationError::Invalid(
            "completion nonce ledger is invalid",
        ));
    }
    let ledger = anchor_writable_directory(directory)?;
    let mut file = match ledger.create_new_file(&handle.payload.nonce) {
        Ok(file) => file,
        Err(SnapshotMaterializationError::Io(error))
            if error.kind() == io::ErrorKind::AlreadyExists =>
        {
            return Err(ProductionAttestationError::CompletionReplay);
        }
        Err(error) => return Err(error.into()),
    };
    file.write_all(handle.payload.digest()?.as_bytes())?;
    file.sync_all()?;
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
    }
    file.sync_all()?;
    ledger.sync()?;
    Ok(())
}

fn attestation_parent(root: &Path, manifest: &ProductionBuildManifest) -> PathBuf {
    root.join(&manifest.composition.composition_hash)
        .join(&manifest.build_output_digest)
        .join(&manifest.build_manifest_digest)
}

fn validate_attestation_address(
    path: &Path,
    manifest: &ProductionBuildManifest,
    attestation: &ProductionBuildAttestation,
) -> Result<(), ProductionAttestationError> {
    let expected_file = format!("{}.json", attestation.digest()?);
    let manifest_directory = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|v| v.to_str());
    let output_directory = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|v| v.to_str());
    let composition_directory = path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .and_then(Path::file_name)
        .and_then(|v| v.to_str());
    if !path.is_absolute()
        || path.file_name().and_then(|value| value.to_str()) != Some(expected_file.as_str())
        || manifest_directory != Some(manifest.build_manifest_digest.as_str())
        || output_directory != Some(manifest.build_output_digest.as_str())
        || composition_directory != Some(manifest.composition.composition_hash.as_str())
    {
        return Err(ProductionAttestationError::Invalid(
            "attestation path is not addressed by composition/output/manifest/attestation digest",
        ));
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, ProductionAttestationError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || usize::try_from(metadata.len()).map_or(true, |n| n > maximum)
    {
        return Err(ProductionAttestationError::Invalid(
            "attestation input file kind or size is invalid",
        ));
    }
    Ok(fs::read(path)?)
}

fn backend_identity_digest(
    identity: &LinuxSandboxBackendAttestation,
) -> Result<String, ProductionAttestationError> {
    Ok(hex::encode(canonical::domain_hash(
        b"rust-agent-linux-sandbox-backend-attestation-v1\0",
        identity,
    )?))
}

fn trusted_signer<'a>(
    policy: &'a NormalizedProductionBuildPolicy,
    id: &str,
) -> Result<&'a TrustedSigner, ProductionAttestationError> {
    policy
        .policy()
        .attestation
        .trusted_signers
        .iter()
        .find(|signer| signer.id == id)
        .ok_or(ProductionAttestationError::Invalid("untrusted signer"))
}

fn verify_digest_signature(
    signer: &TrustedSigner,
    digest: &str,
    signature: &str,
) -> Result<(), ProductionAttestationError> {
    let key = anchor_file_identity(&signer.public_key)?;
    if key.sha256() != signer.sha256 {
        return Err(ProductionAttestationError::Invalid(
            "trusted public key digest mismatch",
        ));
    }
    let bytes = key.read_bytes(MAX_PUBLIC_KEY_BYTES)?;
    let key_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ProductionAttestationError::Invalid("Ed25519 public key length"))?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| ProductionAttestationError::Invalid("Ed25519 public key encoding"))?;
    let signature_bytes = hex::decode(signature)
        .map_err(|_| ProductionAttestationError::Invalid("Ed25519 signature encoding"))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| ProductionAttestationError::Invalid("Ed25519 signature length"))?;
    let message = hex::decode(digest)
        .map_err(|_| ProductionAttestationError::Invalid("signed digest encoding"))?;
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| ProductionAttestationError::Invalid("Ed25519 signature verification"))?;
    key.reverify()?;
    Ok(())
}

fn validate_outer_fields(
    nonce: &str,
    timestamp: &str,
    transparency_proof: Option<&str>,
) -> Result<(), ProductionAttestationError> {
    if !is_nonce(nonce)
        || !valid_text(timestamp, 64)
        || !timestamp.contains('T')
        || !timestamp.ends_with('Z')
        || transparency_proof.is_some_and(|value| !valid_text(value, 64 * 1024))
    {
        return Err(ProductionAttestationError::Invalid(
            "nonce, timestamp, or transparency proof is invalid",
        ));
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_nonce(value: &str) -> bool {
    is_digest(value) && value != "00".repeat(32)
}

fn valid_identity(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && !bytes.windows(2).any(|pair| pair == b"--")
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.bytes().any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
}
