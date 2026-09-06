use std::{
    collections::{BTreeMap, BTreeSet},
    net::Ipv6Addr,
    path::{Path, PathBuf},
};

use rust_agent_composition::{canonical, metadata::BuildRequirements};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::policy::BuildPolicyError;

const LINUX_HOST_SELECTOR: &str = "cfg(target_os = \"linux\")";

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionSandboxBackend {
    LinuxLandlockSeccomp,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionBuildExecutionPolicy {
    pub schema: u32,
    pub id: String,
    pub host: String,
    pub backend: ProductionSandboxBackend,
    pub fetch: ProductionFetchPolicy,
    pub attestation: ProductionAttestationPolicy,
    pub toolchain: ProductionToolchain,
    #[serde(rename = "read-input", default)]
    pub read_inputs: Vec<ProductionReadInput>,
    #[serde(rename = "executable", default)]
    pub executables: Vec<ProductionExecutable>,
    #[serde(rename = "host-linker", default)]
    pub host_linker: Option<ProductionHostLinker>,
    #[serde(rename = "environment", default)]
    pub environment: Vec<ProductionEnvironment>,
    #[serde(rename = "derived-executable")]
    pub derived_executable: DerivedExecutablePolicy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionFetchPolicy {
    #[serde(rename = "network-endpoints")]
    pub network_endpoints: Vec<String>,
    #[serde(rename = "credential-helper", default)]
    pub credential_helper: Option<ProductionFileIdentity>,
    #[serde(rename = "tls-ca-bundle", default)]
    pub tls_ca_bundle: Option<ProductionFileIdentity>,
    #[serde(rename = "redirect-policy")]
    pub redirect_policy: ProductionFetchRedirectPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionFetchRedirectPolicy {
    DenyUnlistedOrigin,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionAttestationPolicy {
    #[serde(rename = "allowed-executors")]
    pub allowed_executors: Vec<String>,
    #[serde(rename = "trusted-signers")]
    pub trusted_signers: Vec<TrustedSigner>,
    #[serde(rename = "trusted-reviewer-policies", default)]
    pub trusted_reviewer_policies: Vec<TrustedReviewerPolicy>,
    #[serde(rename = "signing-helper")]
    pub signing_helper: SigningHelper,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedSigner {
    pub id: String,
    pub algorithm: String,
    #[serde(rename = "public-key")]
    pub public_key: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedReviewerPolicy {
    pub id: String,
    #[serde(rename = "signer-ids")]
    pub signer_ids: Vec<String>,
    #[serde(rename = "min-signatures")]
    pub min_signatures: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SigningHelper {
    #[serde(rename = "signer-id")]
    pub signer_id: String,
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionToolchain {
    pub cargo: ProductionToolIdentity,
    pub rustc: ProductionToolIdentity,
    pub sysroot: ProductionTreeIdentity,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionToolIdentity {
    pub path: PathBuf,
    pub sha256: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionFileIdentity {
    pub path: PathBuf,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionTreeIdentity {
    pub path: PathBuf,
    #[serde(rename = "tree-digest")]
    pub tree_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionReadInput {
    pub id: String,
    pub path: PathBuf,
    #[serde(rename = "tree-digest")]
    pub tree_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionExecutable {
    pub id: String,
    pub path: PathBuf,
    pub sha256: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionHostLinker {
    pub executable: String,
    #[serde(default)]
    pub helpers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionEnvironment {
    pub id: String,
    pub variable: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedExecutablePolicy {
    pub roots: Vec<String>,
    #[serde(rename = "inherit-sandbox")]
    pub inherit_sandbox: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedProductionBuildPolicy {
    policy: ProductionBuildExecutionPolicy,
    executable_ids: BTreeSet<String>,
    read_input_ids: BTreeSet<String>,
    environment_ids: BTreeSet<String>,
    full_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildEnforcementIdentity {
    pub schema: u32,
    pub backend: ProductionSandboxBackend,
    #[serde(rename = "backend-semantic-version")]
    pub backend_semantic_version: u32,
    pub context: BuildEnforcementContext,
    pub toolchain: BuildEnforcementToolchain,
    pub executables: Vec<BuildEnforcementExecutable>,
    #[serde(rename = "host-linker", skip_serializing_if = "Option::is_none")]
    pub host_linker: Option<BuildEnforcementHostLinker>,
    #[serde(rename = "read-inputs")]
    pub read_inputs: Vec<BuildEnforcementReadInput>,
    pub environment: Vec<BuildEnforcementEnvironment>,
    #[serde(rename = "cargo-driver-environment")]
    pub cargo_driver_environment: BTreeMap<String, String>,
    #[serde(rename = "derived-executable")]
    pub derived_executable: DerivedExecutablePolicy,
    #[serde(rename = "deterministic-environment")]
    pub deterministic_environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildEnforcementHostLinker {
    pub executable: BuildEnforcementExecutable,
    pub helpers: Vec<BuildEnforcementExecutable>,
    #[serde(rename = "cargo-config")]
    pub cargo_config: String,
    #[serde(rename = "compiler-path")]
    pub compiler_path: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuildPanicStrategy {
    Abort,
    Unwind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildArtifactSelector {
    pub package: String,
    pub target: BuildArtifactTarget,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum BuildArtifactTarget {
    Library,
    Binary { name: String },
    Example { name: String },
    Test { name: String },
    Bench { name: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildEnforcementContext {
    pub schema: u32,
    #[serde(rename = "build-triple")]
    pub build_triple: String,
    pub target: String,
    #[serde(rename = "target-facts-digest")]
    pub target_facts_digest: String,
    #[serde(rename = "custom-target-spec-digest")]
    pub custom_target_spec_digest: Option<String>,
    #[serde(rename = "cargo-resolution-digest")]
    pub cargo_resolution_digest: String,
    #[serde(rename = "cargo-config-digest")]
    pub cargo_config_digest: String,
    pub profile: String,
    #[serde(rename = "artifact-selector")]
    pub artifact_selector: BuildArtifactSelector,
    #[serde(rename = "panic-strategy")]
    pub panic_strategy: BuildPanicStrategy,
    #[serde(rename = "rustc-settings-digest")]
    pub rustc_settings_digest: String,
    #[serde(rename = "prefix-remap-schema")]
    pub prefix_remap_schema: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildEnforcementToolchain {
    pub cargo: BuildEnforcementExecutable,
    pub rustc: BuildEnforcementExecutable,
    pub sysroot: BuildEnforcementReadInput,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildEnforcementExecutable {
    pub id: String,
    pub sha256: String,
    pub version: String,
    #[serde(rename = "logical-mount")]
    pub logical_mount: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildEnforcementReadInput {
    pub id: String,
    #[serde(rename = "tree-digest")]
    pub tree_digest: String,
    #[serde(rename = "logical-mount")]
    pub logical_mount: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuildEnforcementEnvironment {
    pub id: String,
    pub variable: String,
    pub value: String,
}

#[derive(Debug, Error)]
pub enum ProductionBuildPolicyError {
    #[error("production build policy TOML is invalid: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("unsupported production build policy schema {0}; expected 3")]
    UnsupportedSchema(u32),
    #[error("invalid production policy id `{0}`")]
    InvalidPolicyId(String),
    #[error("production policy Host selector must be `{LINUX_HOST_SELECTOR}`")]
    UnsupportedHost,
    #[error("fetch network endpoint is not a canonical HTTPS origin: {0}")]
    InvalidFetchEndpoint(String),
    #[error("fetch endpoints contain a duplicate canonical origin")]
    DuplicateFetchEndpoint,
    #[error("networked fetch endpoints require one exact TLS CA bundle")]
    MissingFetchTlsCaBundle,
    #[error("a fetch credential helper requires at least one network endpoint")]
    CredentialHelperWithoutEndpoint,
    #[error("invalid {kind} logical id `{id}`")]
    InvalidId { kind: &'static str, id: String },
    #[error("duplicate {kind} logical id `{id}`")]
    Duplicate { kind: &'static str, id: String },
    #[error("logical id `{0}` is declared in more than one production input kind")]
    CrossKindDuplicate(String),
    #[error("production policy path must be absolute and lexically normalized: {0}")]
    InvalidPath(String),
    #[error("invalid canonical SHA-256 digest for `{0}`")]
    InvalidDigest(String),
    #[error("invalid or unsupported declared version for `{0}`")]
    InvalidVersion(String),
    #[error("production toolchain must declare exact Rust/Cargo 1.97.1 identities")]
    UnpinnedRustToolchain,
    #[error("environment mapping `{id}` uses forbidden variable `{variable}`")]
    ForbiddenEnvironment { id: String, variable: String },
    #[error("environment mapping `{id}` contains an invalid or Host-path value")]
    InvalidEnvironmentValue { id: String },
    #[error("allowed executors must be non-empty and unique")]
    InvalidExecutorSet,
    #[error("trusted signers must be non-empty with unique ids")]
    InvalidSignerSet,
    #[error("trusted signer `{id}` uses unsupported algorithm `{algorithm}`")]
    UnsupportedSignerAlgorithm { id: String, algorithm: String },
    #[error("signing helper references unknown trusted signer `{0}`")]
    UnknownSigningHelperSigner(String),
    #[error("reviewer policy `{id}` has an invalid signer threshold")]
    InvalidReviewerThreshold { id: String },
    #[error("reviewer policy `{policy}` references unknown signer `{signer}`")]
    UnknownReviewerSigner { policy: String, signer: String },
    #[error("trusted reviewer policies and their signer ids must be unique and non-empty")]
    InvalidReviewerSet,
    #[error("derived executables must use exactly root `target` and inherit the sandbox")]
    InvalidDerivedExecutablePolicy,
    #[error("host linker bundle is invalid: {0}")]
    InvalidHostLinker(&'static str),
    #[error("host linker executable bundle must be selected atomically")]
    PartialHostLinkerSelection,
    #[error("unsupported build enforcement context schema {0}; expected 1")]
    UnsupportedEnforcementContextSchema(u32),
    #[error("invalid build enforcement context field `{0}`")]
    InvalidEnforcementContext(&'static str),
    #[error("unsupported prefix-remap schema {0}; expected 1")]
    UnsupportedPrefixRemapSchema(u32),
    #[error("production build requirement authorization failed: {0}")]
    Requirement(#[from] BuildPolicyError),
    #[error("canonical production build policy encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

impl ProductionBuildExecutionPolicy {
    pub fn from_toml(input: &str) -> Result<Self, ProductionBuildPolicyError> {
        Ok(toml::from_str(input)?)
    }

    pub fn normalize(&self) -> Result<NormalizedProductionBuildPolicy, ProductionBuildPolicyError> {
        if self.schema != 3 {
            return Err(ProductionBuildPolicyError::UnsupportedSchema(self.schema));
        }
        validate_id("policy", &self.id)
            .map_err(|_| ProductionBuildPolicyError::InvalidPolicyId(self.id.clone()))?;
        if self.host != LINUX_HOST_SELECTOR {
            return Err(ProductionBuildPolicyError::UnsupportedHost);
        }
        let mut policy = self.clone();
        policy.fetch.network_endpoints.sort();
        policy.attestation.allowed_executors.sort();
        policy
            .attestation
            .trusted_signers
            .sort_by(|left, right| left.id.cmp(&right.id));
        policy
            .attestation
            .trusted_reviewer_policies
            .sort_by(|left, right| left.id.cmp(&right.id));
        for reviewer in &mut policy.attestation.trusted_reviewer_policies {
            reviewer.signer_ids.sort();
        }
        policy
            .executables
            .sort_by(|left, right| left.id.cmp(&right.id));
        if let Some(host_linker) = &mut policy.host_linker {
            host_linker.helpers.sort();
        }
        policy
            .read_inputs
            .sort_by(|left, right| left.id.cmp(&right.id));
        policy
            .environment
            .sort_by(|left, right| left.id.cmp(&right.id));

        validate_fetch(&policy.fetch)?;
        validate_tool("cargo", &policy.toolchain.cargo)?;
        validate_tool("rustc", &policy.toolchain.rustc)?;
        validate_pinned_rust_toolchain(&policy.toolchain)?;
        validate_tree("sysroot", &policy.toolchain.sysroot)?;
        validate_attestation(&policy.attestation)?;
        if policy.derived_executable.roots != ["target"]
            || !policy.derived_executable.inherit_sandbox
        {
            return Err(ProductionBuildPolicyError::InvalidDerivedExecutablePolicy);
        }

        let mut executable_ids = BTreeSet::new();
        for item in &policy.executables {
            validate_id("executable", &item.id)?;
            validate_path(&item.path)?;
            validate_digest(&item.id, &item.sha256)?;
            validate_version(&item.id, &item.version)?;
            if !executable_ids.insert(item.id.clone()) {
                return Err(ProductionBuildPolicyError::Duplicate {
                    kind: "executable",
                    id: item.id.clone(),
                });
            }
        }
        validate_host_linker(policy.host_linker.as_ref(), &executable_ids)?;
        let mut read_input_ids = BTreeSet::new();
        for item in &policy.read_inputs {
            validate_id("read-input", &item.id)?;
            validate_path(&item.path)?;
            validate_digest(&item.id, &item.tree_digest)?;
            if !read_input_ids.insert(item.id.clone()) {
                return Err(ProductionBuildPolicyError::Duplicate {
                    kind: "read-input",
                    id: item.id.clone(),
                });
            }
        }
        let mut environment_ids = BTreeSet::new();
        let mut environment_variables = BTreeSet::new();
        for item in &policy.environment {
            validate_id("environment", &item.id)?;
            if !valid_environment_name(&item.variable) || forbidden_environment(&item.variable) {
                return Err(ProductionBuildPolicyError::ForbiddenEnvironment {
                    id: item.id.clone(),
                    variable: item.variable.clone(),
                });
            }
            if item.value.is_empty()
                || item.value.len() > 4096
                || item.value.contains('\0')
                || Path::new(&item.value).is_absolute()
                || looks_like_windows_absolute_path(&item.value)
            {
                return Err(ProductionBuildPolicyError::InvalidEnvironmentValue {
                    id: item.id.clone(),
                });
            }
            if !environment_ids.insert(item.id.clone()) {
                return Err(ProductionBuildPolicyError::Duplicate {
                    kind: "environment",
                    id: item.id.clone(),
                });
            }
            if !environment_variables.insert(item.variable.clone()) {
                return Err(ProductionBuildPolicyError::Duplicate {
                    kind: "environment variable",
                    id: item.variable.clone(),
                });
            }
        }
        reject_cross_kind_duplicates(&executable_ids, &read_input_ids, &environment_ids)?;

        let full_digest = hex::encode(canonical::domain_hash(
            b"rust-agent-build-execution-policy-v3\0",
            &policy,
        )?);
        Ok(NormalizedProductionBuildPolicy {
            policy,
            executable_ids,
            read_input_ids,
            environment_ids,
            full_digest,
        })
    }
}

impl NormalizedProductionBuildPolicy {
    pub fn full_digest(&self) -> &str {
        &self.full_digest
    }

    pub fn policy(&self) -> &ProductionBuildExecutionPolicy {
        &self.policy
    }

    pub fn reviewer_policy_digest(
        &self,
        id: &str,
    ) -> Result<Option<String>, ProductionBuildPolicyError> {
        self.policy
            .attestation
            .trusted_reviewer_policies
            .iter()
            .find(|policy| policy.id == id)
            .map(|policy| {
                Ok(hex::encode(canonical::domain_hash(
                    b"rust-agent-trusted-reviewer-policy-v1\0",
                    policy,
                )?))
            })
            .transpose()
    }

    pub fn enforcement_identity(
        &self,
        requirements: &BuildRequirements,
        context: &BuildEnforcementContext,
    ) -> Result<BuildEnforcementIdentity, ProductionBuildPolicyError> {
        self.authorize(requirements)?;
        context.validate()?;
        let executables: Vec<_> = self
            .policy
            .executables
            .iter()
            .filter(|item| requirements.executables.contains(&item.id))
            .map(executable_enforcement_identity)
            .collect();
        let selected_host_linker = self.selected_host_linker(requirements)?;
        let host_linker = selected_host_linker.map(|bundle| {
            let executable = self
                .policy
                .executables
                .iter()
                .find(|item| item.id == bundle.executable)
                .expect("normalized host linker executable exists");
            BuildEnforcementHostLinker {
                executable: executable_enforcement_identity(executable),
                helpers: bundle
                    .helpers
                    .iter()
                    .map(|id| {
                        self.policy
                            .executables
                            .iter()
                            .find(|item| item.id == *id)
                            .map(executable_enforcement_identity)
                            .expect("normalized host linker helper exists")
                    })
                    .collect(),
                cargo_config: format!(
                    "host.{}.linker=\"/rust-agent/tools/{}\"",
                    context.build_triple, bundle.executable
                ),
                compiler_path: "/rust-agent/tools".into(),
            }
        });
        let read_inputs = self
            .policy
            .read_inputs
            .iter()
            .filter(|item| requirements.read_inputs.contains(&item.id))
            .map(|item| BuildEnforcementReadInput {
                id: item.id.clone(),
                tree_digest: item.tree_digest.clone(),
                logical_mount: format!("/rust-agent/inputs/{}", item.id),
            })
            .collect();
        let environment = self
            .policy
            .environment
            .iter()
            .filter(|item| requirements.environment.contains(&item.id))
            .map(|item| BuildEnforcementEnvironment {
                id: item.id.clone(),
                variable: item.variable.clone(),
                value: item.value.clone(),
            })
            .collect();
        let host_linker_selected = selected_host_linker.is_some();
        Ok(BuildEnforcementIdentity {
            schema: 2,
            backend: self.policy.backend,
            backend_semantic_version: 5,
            context: context.clone(),
            toolchain: BuildEnforcementToolchain {
                cargo: tool_enforcement_identity("cargo", &self.policy.toolchain.cargo),
                rustc: tool_enforcement_identity("rustc", &self.policy.toolchain.rustc),
                sysroot: BuildEnforcementReadInput {
                    id: "rust-sysroot".into(),
                    tree_digest: self.policy.toolchain.sysroot.tree_digest.clone(),
                    logical_mount: "/rust-agent/toolchain".into(),
                },
            },
            executables,
            host_linker,
            read_inputs,
            environment,
            cargo_driver_environment: cargo_driver_environment(host_linker_selected, true),
            derived_executable: self.policy.derived_executable.clone(),
            deterministic_environment: [
                ("LANG".into(), "C.UTF-8".into()),
                ("LC_ALL".into(), "C.UTF-8".into()),
                ("SOURCE_DATE_EPOCH".into(), "0".into()),
            ]
            .into_iter()
            .chain(
                selected_host_linker.map(|_| ("COMPILER_PATH".into(), "/rust-agent/tools".into())),
            )
            .collect(),
        })
    }

    pub fn enforcement_identity_digest(
        &self,
        requirements: &BuildRequirements,
        context: &BuildEnforcementContext,
    ) -> Result<String, ProductionBuildPolicyError> {
        self.enforcement_identity(requirements, context)?.digest()
    }

    fn authorize(
        &self,
        requirements: &BuildRequirements,
    ) -> Result<(), ProductionBuildPolicyError> {
        for id in &requirements.executables {
            require_kind(
                id,
                "executable",
                &self.executable_ids,
                &self.read_input_ids,
                &self.environment_ids,
            )?;
        }
        for id in &requirements.read_inputs {
            require_kind(
                id,
                "read-input",
                &self.read_input_ids,
                &self.executable_ids,
                &self.environment_ids,
            )?;
        }
        for id in &requirements.environment {
            require_kind(
                id,
                "environment",
                &self.environment_ids,
                &self.executable_ids,
                &self.read_input_ids,
            )?;
        }
        self.selected_host_linker(requirements)?;
        Ok(())
    }

    pub fn selected_host_linker(
        &self,
        requirements: &BuildRequirements,
    ) -> Result<Option<&ProductionHostLinker>, ProductionBuildPolicyError> {
        let Some(bundle) = self.policy.host_linker.as_ref() else {
            return Ok(None);
        };
        let selected = std::iter::once(&bundle.executable)
            .chain(&bundle.helpers)
            .filter(|id| requirements.executables.contains(*id))
            .count();
        let total = 1 + bundle.helpers.len();
        match selected {
            0 => Ok(None),
            count if count == total => Ok(Some(bundle)),
            _ => Err(ProductionBuildPolicyError::PartialHostLinkerSelection),
        }
    }
}

pub(crate) fn cargo_driver_environment(
    host_linker_selected: bool,
    build_invocation: bool,
) -> BTreeMap<String, String> {
    let mut environment = BTreeMap::from([
        (
            "__CARGO_TEST_CHANNEL_OVERRIDE_DO_NOT_USE_THIS".into(),
            "nightly".into(),
        ),
        ("CARGO_CACHE_RUSTC_INFO".into(), "0".into()),
        ("CARGO_HOME".into(), "/rust-agent/cargo-home".into()),
        ("CARGO_INCREMENTAL".into(), "0".into()),
        ("CARGO_NET_OFFLINE".into(), "true".into()),
        ("CARGO_TARGET_DIR".into(), "/rust-agent/target".into()),
        ("LANG".into(), "C.UTF-8".into()),
        ("LC_ALL".into(), "C.UTF-8".into()),
        ("PATH".into(), "/rust-agent/toolchain/bin".into()),
        ("RUSTC".into(), "/rust-agent/toolchain/bin/rustc".into()),
        ("SOURCE_DATE_EPOCH".into(), "0".into()),
    ]);
    if host_linker_selected {
        environment.insert("COMPILER_PATH".into(), "/rust-agent/tools".into());
    }
    if build_invocation {
        environment.insert(
            "CARGO_ENCODED_RUSTFLAGS".into(),
            "--sysroot=/rust-agent/toolchain".into(),
        );
        environment.insert("TMPDIR".into(), "/rust-agent/tmp".into());
    }
    environment
}

impl BuildEnforcementIdentity {
    pub fn digest(&self) -> Result<String, ProductionBuildPolicyError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-build-enforcement-identity-v2\0",
            self,
        )?))
    }
}

impl BuildEnforcementContext {
    pub fn validate(&self) -> Result<(), ProductionBuildPolicyError> {
        if self.schema != 1 {
            return Err(
                ProductionBuildPolicyError::UnsupportedEnforcementContextSchema(self.schema),
            );
        }
        for (field, value) in [
            ("build-triple", self.build_triple.as_str()),
            ("target", self.target.as_str()),
        ] {
            if !is_canonical_target_name(value) {
                return Err(ProductionBuildPolicyError::InvalidEnforcementContext(field));
            }
        }
        for (field, value) in [("profile", self.profile.as_str())] {
            if validate_id("build enforcement context", value).is_err() {
                return Err(ProductionBuildPolicyError::InvalidEnforcementContext(field));
            }
        }
        self.artifact_selector.validate()?;
        for (field, digest) in [
            ("target-facts-digest", self.target_facts_digest.as_str()),
            (
                "cargo-resolution-digest",
                self.cargo_resolution_digest.as_str(),
            ),
            ("cargo-config-digest", self.cargo_config_digest.as_str()),
            ("rustc-settings-digest", self.rustc_settings_digest.as_str()),
        ] {
            if validate_digest(field, digest).is_err() {
                return Err(ProductionBuildPolicyError::InvalidEnforcementContext(field));
            }
        }
        if self
            .custom_target_spec_digest
            .as_deref()
            .is_some_and(|digest| validate_digest("custom-target-spec-digest", digest).is_err())
        {
            return Err(ProductionBuildPolicyError::InvalidEnforcementContext(
                "custom-target-spec-digest",
            ));
        }
        if self.prefix_remap_schema != 1 {
            return Err(ProductionBuildPolicyError::UnsupportedPrefixRemapSchema(
                self.prefix_remap_schema,
            ));
        }
        Ok(())
    }
}

impl BuildArtifactSelector {
    pub fn digest(&self) -> Result<String, ProductionBuildPolicyError> {
        self.validate()?;
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-build-artifact-selector-v1\0",
            self,
        )?))
    }

    pub fn cargo_arguments(&self) -> Vec<String> {
        let mut arguments = vec!["--package".into(), self.package.clone()];
        match &self.target {
            BuildArtifactTarget::Library => arguments.push("--lib".into()),
            BuildArtifactTarget::Binary { name } => {
                arguments.extend(["--bin".into(), name.clone()]);
            }
            BuildArtifactTarget::Example { name } => {
                arguments.extend(["--example".into(), name.clone()]);
            }
            BuildArtifactTarget::Test { name } => {
                arguments.extend(["--test".into(), name.clone()]);
            }
            BuildArtifactTarget::Bench { name } => {
                arguments.extend(["--bench".into(), name.clone()]);
            }
        }
        arguments
    }

    fn validate(&self) -> Result<(), ProductionBuildPolicyError> {
        if !is_cargo_name(&self.package) {
            return Err(ProductionBuildPolicyError::InvalidEnforcementContext(
                "artifact-selector.package",
            ));
        }
        let target_name = match &self.target {
            BuildArtifactTarget::Library => return Ok(()),
            BuildArtifactTarget::Binary { name }
            | BuildArtifactTarget::Example { name }
            | BuildArtifactTarget::Test { name }
            | BuildArtifactTarget::Bench { name } => name,
        };
        if is_cargo_name(target_name) {
            Ok(())
        } else {
            Err(ProductionBuildPolicyError::InvalidEnforcementContext(
                "artifact-selector.target.name",
            ))
        }
    }
}

fn validate_fetch(fetch: &ProductionFetchPolicy) -> Result<(), ProductionBuildPolicyError> {
    if fetch
        .network_endpoints
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ProductionBuildPolicyError::DuplicateFetchEndpoint);
    }
    for endpoint in &fetch.network_endpoints {
        if !is_canonical_https_origin(endpoint) {
            return Err(ProductionBuildPolicyError::InvalidFetchEndpoint(
                endpoint.clone(),
            ));
        }
    }
    if let Some(helper) = &fetch.credential_helper {
        if fetch.network_endpoints.is_empty() {
            return Err(ProductionBuildPolicyError::CredentialHelperWithoutEndpoint);
        }
        validate_file("fetch-credential-helper", helper)?;
    }
    match (&fetch.tls_ca_bundle, fetch.network_endpoints.is_empty()) {
        (Some(ca), false) => validate_file("fetch-tls-ca-bundle", ca)?,
        (None, false) | (Some(_), true) => {
            return Err(ProductionBuildPolicyError::MissingFetchTlsCaBundle);
        }
        (None, true) => {}
    }
    Ok(())
}

fn validate_attestation(
    attestation: &ProductionAttestationPolicy,
) -> Result<(), ProductionBuildPolicyError> {
    if attestation.allowed_executors.is_empty()
        || attestation
            .allowed_executors
            .windows(2)
            .any(|pair| pair[0] == pair[1])
    {
        return Err(ProductionBuildPolicyError::InvalidExecutorSet);
    }
    for executor in &attestation.allowed_executors {
        validate_id("allowed executor", executor)?;
    }
    if attestation.trusted_signers.is_empty()
        || attestation
            .trusted_signers
            .windows(2)
            .any(|pair| pair[0].id == pair[1].id)
    {
        return Err(ProductionBuildPolicyError::InvalidSignerSet);
    }
    let mut signer_ids = BTreeSet::new();
    for signer in &attestation.trusted_signers {
        validate_id("trusted signer", &signer.id)?;
        if signer.algorithm != "ed25519" {
            return Err(ProductionBuildPolicyError::UnsupportedSignerAlgorithm {
                id: signer.id.clone(),
                algorithm: signer.algorithm.clone(),
            });
        }
        validate_path(&signer.public_key)?;
        validate_digest(&signer.id, &signer.sha256)?;
        signer_ids.insert(signer.id.clone());
    }
    validate_id(
        "signing helper signer",
        &attestation.signing_helper.signer_id,
    )?;
    validate_path(&attestation.signing_helper.path)?;
    validate_digest("signing-helper", &attestation.signing_helper.sha256)?;
    if !signer_ids.contains(&attestation.signing_helper.signer_id) {
        return Err(ProductionBuildPolicyError::UnknownSigningHelperSigner(
            attestation.signing_helper.signer_id.clone(),
        ));
    }
    if attestation
        .trusted_reviewer_policies
        .windows(2)
        .any(|pair| pair[0].id == pair[1].id)
    {
        return Err(ProductionBuildPolicyError::InvalidReviewerSet);
    }
    for policy in &attestation.trusted_reviewer_policies {
        validate_id("reviewer policy", &policy.id)?;
        if policy.signer_ids.is_empty()
            || policy.signer_ids.windows(2).any(|pair| pair[0] == pair[1])
        {
            return Err(ProductionBuildPolicyError::InvalidReviewerSet);
        }
        if policy.min_signatures == 0
            || usize::try_from(policy.min_signatures)
                .map_or(true, |threshold| threshold > policy.signer_ids.len())
        {
            return Err(ProductionBuildPolicyError::InvalidReviewerThreshold {
                id: policy.id.clone(),
            });
        }
        for signer in &policy.signer_ids {
            if !signer_ids.contains(signer) {
                return Err(ProductionBuildPolicyError::UnknownReviewerSigner {
                    policy: policy.id.clone(),
                    signer: signer.clone(),
                });
            }
        }
    }
    Ok(())
}

fn reject_cross_kind_duplicates(
    executables: &BTreeSet<String>,
    read_inputs: &BTreeSet<String>,
    environment: &BTreeSet<String>,
) -> Result<(), ProductionBuildPolicyError> {
    let mut kinds = BTreeMap::new();
    for (kind, ids) in [
        ("executable", executables),
        ("read-input", read_inputs),
        ("environment", environment),
    ] {
        for id in ids {
            if kinds.insert(id, kind).is_some() {
                return Err(ProductionBuildPolicyError::CrossKindDuplicate(id.clone()));
            }
        }
    }
    Ok(())
}

fn validate_host_linker(
    host_linker: Option<&ProductionHostLinker>,
    executable_ids: &BTreeSet<String>,
) -> Result<(), ProductionBuildPolicyError> {
    let Some(host_linker) = host_linker else {
        return Ok(());
    };
    validate_id("host linker executable", &host_linker.executable)?;
    if !executable_ids.contains(&host_linker.executable) {
        return Err(ProductionBuildPolicyError::InvalidHostLinker(
            "linker executable is not declared",
        ));
    }
    if host_linker
        .helpers
        .windows(2)
        .any(|pair| pair[0] == pair[1])
    {
        return Err(ProductionBuildPolicyError::InvalidHostLinker(
            "helper executable ids are not unique",
        ));
    }
    for helper in &host_linker.helpers {
        validate_id("host linker helper", helper)?;
        if helper == &host_linker.executable {
            return Err(ProductionBuildPolicyError::InvalidHostLinker(
                "linker executable is also listed as a helper",
            ));
        }
        if !executable_ids.contains(helper) {
            return Err(ProductionBuildPolicyError::InvalidHostLinker(
                "helper executable is not declared",
            ));
        }
    }
    Ok(())
}

fn require_kind(
    id: &str,
    expected: &'static str,
    expected_ids: &BTreeSet<String>,
    other_a: &BTreeSet<String>,
    other_b: &BTreeSet<String>,
) -> Result<(), BuildPolicyError> {
    if expected_ids.contains(id) {
        return Ok(());
    }
    let actual = if other_a.contains(id) {
        Some(match expected {
            "executable" => "read-input",
            "read-input" | "environment" => "executable",
            _ => unreachable!(),
        })
    } else if other_b.contains(id) {
        Some(match expected {
            "executable" | "read-input" => "environment",
            "environment" => "read-input",
            _ => unreachable!(),
        })
    } else {
        None
    };
    actual.map_or_else(
        || {
            Err(BuildPolicyError::MissingMapping {
                kind: expected,
                id: id.to_owned(),
            })
        },
        |actual| {
            Err(BuildPolicyError::KindMismatch {
                id: id.to_owned(),
                expected,
                actual,
            })
        },
    )
}

fn tool_enforcement_identity(
    id: &str,
    tool: &ProductionToolIdentity,
) -> BuildEnforcementExecutable {
    BuildEnforcementExecutable {
        id: id.into(),
        sha256: tool.sha256.clone(),
        version: tool.version.clone(),
        logical_mount: format!("/rust-agent/toolchain/bin/{id}"),
    }
}

fn executable_enforcement_identity(
    executable: &ProductionExecutable,
) -> BuildEnforcementExecutable {
    BuildEnforcementExecutable {
        id: executable.id.clone(),
        sha256: executable.sha256.clone(),
        version: executable.version.clone(),
        logical_mount: format!("/rust-agent/tools/{}", executable.id),
    }
}

fn validate_tool(
    id: &str,
    tool: &ProductionToolIdentity,
) -> Result<(), ProductionBuildPolicyError> {
    validate_path(&tool.path)?;
    validate_digest(id, &tool.sha256)?;
    validate_version(id, &tool.version)
}

fn validate_pinned_rust_toolchain(
    toolchain: &ProductionToolchain,
) -> Result<(), ProductionBuildPolicyError> {
    if !is_pinned_tool_version(&toolchain.cargo.version, "cargo")
        || !is_pinned_tool_version(&toolchain.rustc.version, "rustc")
    {
        Err(ProductionBuildPolicyError::UnpinnedRustToolchain)
    } else {
        Ok(())
    }
}

fn is_pinned_tool_version(version: &str, tool: &str) -> bool {
    version == format!("{tool} 1.97.1") || version.starts_with(&format!("{tool} 1.97.1 ("))
}

fn validate_file(
    id: &str,
    file: &ProductionFileIdentity,
) -> Result<(), ProductionBuildPolicyError> {
    validate_path(&file.path)?;
    validate_digest(id, &file.sha256)
}

fn validate_tree(
    id: &str,
    tree: &ProductionTreeIdentity,
) -> Result<(), ProductionBuildPolicyError> {
    validate_path(&tree.path)?;
    validate_digest(id, &tree.tree_digest)
}

fn validate_id(kind: &'static str, value: &str) -> Result<(), ProductionBuildPolicyError> {
    let bytes = value.as_bytes();
    let valid = !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && !bytes.windows(2).any(|pair| pair == b"--")
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-');
    if valid {
        Ok(())
    } else {
        Err(ProductionBuildPolicyError::InvalidId {
            kind,
            id: value.to_owned(),
        })
    }
}

fn validate_path(path: &Path) -> Result<(), ProductionBuildPolicyError> {
    let normalized = path.to_str().is_some_and(|value| {
        value.starts_with('/')
            && (value == "/" || !value.ends_with('/'))
            && value
                .split('/')
                .skip(1)
                .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
    });
    if !path.is_absolute() || !normalized {
        Err(ProductionBuildPolicyError::InvalidPath(
            path.display().to_string(),
        ))
    } else {
        Ok(())
    }
}

fn validate_digest(id: &str, digest: &str) -> Result<(), ProductionBuildPolicyError> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(ProductionBuildPolicyError::InvalidDigest(id.to_owned()))
    }
}

fn validate_version(id: &str, version: &str) -> Result<(), ProductionBuildPolicyError> {
    if version.is_empty()
        || version.len() > 256
        || version.contains(['\0', '\n', '\r'])
        || version.trim() != version
    {
        Err(ProductionBuildPolicyError::InvalidVersion(id.to_owned()))
    } else {
        Ok(())
    }
}

fn valid_environment_name(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes()[0].is_ascii_uppercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_canonical_target_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn is_cargo_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn forbidden_environment(value: &str) -> bool {
    matches!(
        value,
        "PATH"
            | "HOME"
            | "CARGO_HOME"
            | "RUSTFLAGS"
            | "RUSTDOCFLAGS"
            | "CARGO_ENCODED_RUSTFLAGS"
            | "RUSTC_WRAPPER"
            | "RUSTC_WORKSPACE_WRAPPER"
            | "LANG"
            | "LC_ALL"
            | "SOURCE_DATE_EPOCH"
    ) || value.contains("TOKEN")
        || value.contains("SECRET")
        || value.contains("PASSWORD")
        || value.contains("PROXY")
        || value.contains("CREDENTIAL")
}

fn is_canonical_https_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
        return false;
    }
    let port = if let Some(ipv6) = authority.strip_prefix('[') {
        let Some((host, port)) = ipv6.split_once("]:") else {
            return false;
        };
        if !matches!(host.parse::<Ipv6Addr>(), Ok(address) if address.to_string() == host) {
            return false;
        }
        port
    } else {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return false;
        };
        if host.contains(':') || !valid_dns_name(host) {
            return false;
        }
        port
    };
    valid_canonical_port(port)
}

fn valid_dns_name(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label.as_bytes()[0] != b'-'
                && label.as_bytes()[label.len() - 1] != b'-'
        })
}

fn valid_canonical_port(port: &str) -> bool {
    !port.is_empty() && !port.starts_with('0') && port.parse::<u16>().is_ok_and(|value| value != 0)
}

fn looks_like_windows_absolute_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\')
}
