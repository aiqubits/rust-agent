use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use rust_agent_composition::{
    canonical,
    metadata::{BuildRequirements, MAX_BUILD_REQUIREMENT_ENTRIES_PER_KIND},
    target::{
        MAX_RUSTC_CFG_OUTPUT_BYTES, MAX_RUSTC_DIAGNOSTIC_BYTES, TargetError, TargetFactsRecord,
        parse_facts, validate_target_triple,
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CargoFetchMode, NormalizedHostBuildInputClosure, NormalizedProductionBuildPolicy,
    ProductionBuildPolicyError, SnapshotMaterializationError,
    snapshot_materializer::{
        AnchoredFileIdentity, AnchoredTreeIdentity, anchor_file_identity, anchor_tree_identity,
    },
};

const MAX_IDENTITY_JSON_BYTES: usize = 32 * 1024 * 1024;
const MAX_VERSION_PROBE_OUTPUT_BYTES: usize = 16 * 1024;
const MAX_TARGET_FACTS_PROBE_JSON_BYTES: usize = 1024 * 1024;
const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(30);
const VERSION_PROBE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const VERSION_PROBE_TERMINATION_GRACE: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionInputPreflightScope {
    NetworkedFetch,
    PreprovisionedFetch,
    Build,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionInputFileRole {
    Cargo,
    Rustc,
    CredentialHelper,
    FetchTlsCaBundle,
    BuildExecutable,
    HostLinker,
    HostLinkerHelper,
    TargetLinker,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProductionInputTreeRole {
    RustSysroot,
    BuildReadInput,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionVersionProbe {
    pub arguments: Vec<String>,
    #[serde(rename = "expected-first-stdout-line")]
    pub expected_first_stdout_line: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionInputFile {
    pub role: ProductionInputFileRole,
    pub id: String,
    pub path: PathBuf,
    pub sha256: String,
    #[serde(rename = "version-probe", skip_serializing_if = "Option::is_none")]
    pub version_probe: Option<ProductionVersionProbe>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionInputTree {
    pub role: ProductionInputTreeRole,
    pub id: String,
    pub path: PathBuf,
    #[serde(rename = "tree-digest")]
    pub tree_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionInputIdentityRequest {
    pub schema: u32,
    pub scope: ProductionInputPreflightScope,
    #[serde(rename = "build-execution-policy-digest")]
    pub build_execution_policy_digest: String,
    #[serde(
        rename = "host-build-input-closure-digest",
        skip_serializing_if = "Option::is_none"
    )]
    pub host_build_input_closure_digest: Option<String>,
    pub files: Vec<ProductionInputFile>,
    pub trees: Vec<ProductionInputTree>,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionVersionProbeResult {
    pub role: ProductionInputFileRole,
    pub id: String,
    #[serde(rename = "executable-sha256")]
    pub executable_sha256: String,
    pub arguments: Vec<String>,
    #[serde(rename = "exit-code")]
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionInputIdentityObservation {
    pub schema: u32,
    #[serde(rename = "request-digest")]
    pub request_digest: String,
    pub probes: Vec<ProductionVersionProbeResult>,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionTargetFactsProbeRequest {
    pub schema: u32,
    #[serde(rename = "production-input-request-digest")]
    pub production_input_request_digest: String,
    #[serde(rename = "host-build-input-closure-digest")]
    pub host_build_input_closure_digest: String,
    #[serde(rename = "build-execution-policy-digest")]
    pub build_execution_policy_digest: String,
    #[serde(rename = "rustc-sha256")]
    pub rustc_sha256: String,
    pub target: String,
    #[serde(
        rename = "custom-target-spec-digest",
        skip_serializing_if = "Option::is_none"
    )]
    pub custom_target_spec_digest: Option<String>,
    #[serde(
        rename = "custom-target-spec-logical-path",
        skip_serializing_if = "Option::is_none"
    )]
    pub custom_target_spec_logical_path: Option<String>,
    pub arguments: Vec<String>,
    #[serde(rename = "environment-cleared")]
    pub environment_cleared: bool,
    #[serde(rename = "working-directory")]
    pub working_directory: String,
    #[serde(rename = "expected-target-facts-digest")]
    pub expected_target_facts_digest: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionTargetFactsProbeObservation {
    pub schema: u32,
    #[serde(rename = "request-digest")]
    pub request_digest: String,
    #[serde(rename = "rustc-sha256")]
    pub rustc_sha256: String,
    pub arguments: Vec<String>,
    #[serde(rename = "environment-cleared")]
    pub environment_cleared: bool,
    #[serde(rename = "working-directory")]
    pub working_directory: String,
    #[serde(rename = "exit-code")]
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    #[serde(rename = "target-facts")]
    pub target_facts: TargetFactsRecord,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedProductionInputIdentityObservation {
    request_digest: String,
    observation_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedProductionTargetFactsProbeObservation {
    request: String,
    observation: String,
    target_facts: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedProductionInputs {
    request: ProductionInputIdentityRequest,
    files: Vec<VerifiedFile>,
    trees: Vec<VerifiedTree>,
}

#[derive(Clone, Debug)]
struct VerifiedFile {
    role: ProductionInputFileRole,
    id: String,
    identity: AnchoredFileIdentity,
}

#[derive(Clone, Debug)]
struct VerifiedTree {
    role: ProductionInputTreeRole,
    id: String,
    identity: AnchoredTreeIdentity,
}

#[derive(Debug, Error)]
pub enum ProductionInputIdentityError {
    #[error("production input identity JSON exceeds the schema-v4 byte limit")]
    JsonTooLarge,
    #[error("production input identity JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "unsupported production input identity schema {0}; expected 4 for requests or 3 for observations"
    )]
    UnsupportedSchema(u32),
    #[error("production input identity request is malformed: {0}")]
    InvalidRequest(&'static str),
    #[error("production input identity request digest is invalid")]
    RequestDigestMismatch,
    #[error("production input identity observation is malformed: {0}")]
    InvalidObservation(&'static str),
    #[error("production input identity observation digest is invalid")]
    ObservationDigestMismatch,
    #[error("production input identity observation does not match its request")]
    ObservationRequestMismatch,
    #[error("production version probe failed for `{0}`")]
    VersionProbeFailed(String),
    #[error("Host input closure and production policy digests differ")]
    ClosurePolicyMismatch,
    #[error("production file `{id}` digest differs from policy: expected {expected}, got {actual}")]
    FileDigestMismatch {
        id: String,
        expected: String,
        actual: String,
    },
    #[error("production executable `{0}` is not executable")]
    FileNotExecutable(String),
    #[error("production executable `{0}` is not a Linux ELF file")]
    UnsupportedExecutableFormat(String),
    #[error("production version probe `{id}` failed to start or observe: {source}")]
    ProbeIo {
        id: String,
        #[source]
        source: io::Error,
    },
    #[error("production version probe `{id}` exceeded its {milliseconds}-millisecond deadline")]
    ProbeTimedOut { id: String, milliseconds: u128 },
    #[error("production version probe `{id}` {stream} exceeded the {maximum}-byte limit")]
    ProbeOutputTooLarge {
        id: String,
        stream: &'static str,
        maximum: usize,
    },
    #[error("production version probe `{id}` {stream} is not valid UTF-8")]
    InvalidProbeOutputEncoding { id: String, stream: &'static str },
    #[error("production version probe `{id}` output reader thread panicked")]
    ProbeReaderPanicked { id: String },
    #[error("production version probe `{0}` process-tree cleanup did not complete")]
    ProbeCleanupFailed(String),
    #[error("target-facts probe request does not match the retained build inputs or Host closure")]
    TargetFactsProbeRequestMismatch,
    #[error("local custom-target probing requires the trusted mounted-view backend")]
    CustomTargetProbeRequiresMountedView,
    #[error("target-facts probe failed with exit code {0}")]
    TargetFactsProbeFailed(i32),
    #[error("target-facts probe observation does not match its exact request")]
    TargetFactsProbeObservationMismatch,
    #[error("rustc target facts differ from the committed Host build input closure")]
    TargetFactsMismatch,
    #[error("rustc target-facts output is invalid: {0}")]
    TargetFacts(#[from] TargetError),
    #[error("production tree `{id}` digest differs from policy: expected {expected}, got {actual}")]
    TreeDigestMismatch {
        id: String,
        expected: String,
        actual: String,
    },
    #[error("production policy verification failed: {0}")]
    Policy(#[from] ProductionBuildPolicyError),
    #[error("production input descriptor preflight failed: {0}")]
    Snapshot(#[from] SnapshotMaterializationError),
    #[error("canonical production input identity encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

#[derive(Serialize)]
struct RequestProjection<'a> {
    schema: u32,
    scope: ProductionInputPreflightScope,
    #[serde(rename = "build-execution-policy-digest")]
    build_execution_policy_digest: &'a str,
    #[serde(
        rename = "host-build-input-closure-digest",
        skip_serializing_if = "Option::is_none"
    )]
    host_build_input_closure_digest: Option<&'a str>,
    files: &'a [ProductionInputFile],
    trees: &'a [ProductionInputTree],
}

#[derive(Serialize)]
struct ObservationProjection<'a> {
    schema: u32,
    #[serde(rename = "request-digest")]
    request_digest: &'a str,
    probes: &'a [ProductionVersionProbeResult],
}

#[derive(Serialize)]
struct TargetFactsProbeRequestProjection<'a> {
    schema: u32,
    #[serde(rename = "production-input-request-digest")]
    production_input_request_digest: &'a str,
    #[serde(rename = "host-build-input-closure-digest")]
    host_build_input_closure_digest: &'a str,
    #[serde(rename = "build-execution-policy-digest")]
    build_execution_policy_digest: &'a str,
    #[serde(rename = "rustc-sha256")]
    rustc_sha256: &'a str,
    target: &'a str,
    #[serde(
        rename = "custom-target-spec-digest",
        skip_serializing_if = "Option::is_none"
    )]
    custom_target_spec_digest: Option<&'a str>,
    #[serde(
        rename = "custom-target-spec-logical-path",
        skip_serializing_if = "Option::is_none"
    )]
    custom_target_spec_logical_path: Option<&'a str>,
    arguments: &'a [String],
    #[serde(rename = "environment-cleared")]
    environment_cleared: bool,
    #[serde(rename = "working-directory")]
    working_directory: &'a str,
    #[serde(rename = "expected-target-facts-digest")]
    expected_target_facts_digest: &'a str,
}

#[derive(Serialize)]
struct TargetFactsProbeObservationProjection<'a> {
    schema: u32,
    #[serde(rename = "request-digest")]
    request_digest: &'a str,
    #[serde(rename = "rustc-sha256")]
    rustc_sha256: &'a str,
    arguments: &'a [String],
    #[serde(rename = "environment-cleared")]
    environment_cleared: bool,
    #[serde(rename = "working-directory")]
    working_directory: &'a str,
    #[serde(rename = "exit-code")]
    exit_code: i32,
    stdout: &'a str,
    stderr: &'a str,
    #[serde(rename = "target-facts")]
    target_facts: &'a TargetFactsRecord,
}

pub fn preflight_production_build_inputs(
    policy: &NormalizedProductionBuildPolicy,
    closure: &NormalizedHostBuildInputClosure,
) -> Result<VerifiedProductionInputs, ProductionInputIdentityError> {
    if closure.build_execution_policy_digest() != policy.full_digest() {
        return Err(ProductionInputIdentityError::ClosurePolicyMismatch);
    }
    policy.enforcement_identity(closure.build_requirements(), closure.build_context())?;
    preflight_inputs(build_request(
        policy,
        closure.build_requirements(),
        &closure.build_context().target,
        Some(closure.digest()),
    )?)
}

pub fn preflight_production_fetch_inputs(
    policy: &NormalizedProductionBuildPolicy,
    mode: CargoFetchMode,
) -> Result<VerifiedProductionInputs, ProductionInputIdentityError> {
    preflight_inputs(fetch_request(policy, mode)?)
}

impl ProductionInputIdentityRequest {
    pub fn from_json(input: &str) -> Result<Self, ProductionInputIdentityError> {
        if input.len() > MAX_IDENTITY_JSON_BYTES {
            return Err(ProductionInputIdentityError::JsonTooLarge);
        }
        let request: Self = serde_json::from_str(input)?;
        request.verify_self()?;
        Ok(request)
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn expected_probes(&self) -> impl Iterator<Item = &ProductionInputFile> {
        self.files
            .iter()
            .filter(|file| file.version_probe.is_some())
    }

    fn recompute_digest(&self) -> Result<String, ProductionInputIdentityError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-production-input-identity-request-v4\0",
            &RequestProjection {
                schema: self.schema,
                scope: self.scope,
                build_execution_policy_digest: &self.build_execution_policy_digest,
                host_build_input_closure_digest: self.host_build_input_closure_digest.as_deref(),
                files: &self.files,
                trees: &self.trees,
            },
        )?))
    }

    fn verify_self(&self) -> Result<(), ProductionInputIdentityError> {
        if self.schema != 4 {
            return Err(ProductionInputIdentityError::UnsupportedSchema(self.schema));
        }
        if !is_digest(&self.build_execution_policy_digest)
            || self
                .host_build_input_closure_digest
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
        {
            return Err(ProductionInputIdentityError::InvalidRequest("digest"));
        }
        let maximum = MAX_BUILD_REQUIREMENT_ENTRIES_PER_KIND + 4;
        if self.files.len() > maximum || self.trees.len() > maximum {
            return Err(ProductionInputIdentityError::InvalidRequest("input count"));
        }
        if !self
            .files
            .windows(2)
            .all(|pair| file_key(&pair[0]) < file_key(&pair[1]))
            || !self
                .trees
                .windows(2)
                .all(|pair| tree_key(&pair[0]) < tree_key(&pair[1]))
        {
            return Err(ProductionInputIdentityError::InvalidRequest(
                "input ordering",
            ));
        }
        for file in &self.files {
            validate_file(file)?;
        }
        for tree in &self.trees {
            validate_tree(tree)?;
        }
        let cargo = self
            .files
            .iter()
            .filter(|file| file.role == ProductionInputFileRole::Cargo)
            .count();
        let rustc = self
            .files
            .iter()
            .filter(|file| file.role == ProductionInputFileRole::Rustc)
            .count();
        if cargo != 1 || rustc != 1 {
            return Err(ProductionInputIdentityError::InvalidRequest(
                "toolchain cardinality",
            ));
        }
        match self.scope {
            ProductionInputPreflightScope::NetworkedFetch => {
                if self.host_build_input_closure_digest.is_some()
                    || !has_only_one_sysroot(&self.trees)
                    || self.files.iter().any(|file| {
                        matches!(
                            file.role,
                            ProductionInputFileRole::BuildExecutable
                                | ProductionInputFileRole::HostLinker
                                | ProductionInputFileRole::HostLinkerHelper
                                | ProductionInputFileRole::TargetLinker
                        )
                    })
                    || self
                        .files
                        .iter()
                        .filter(|file| file.role == ProductionInputFileRole::CredentialHelper)
                        .count()
                        > 1
                    || self
                        .files
                        .iter()
                        .filter(|file| file.role == ProductionInputFileRole::FetchTlsCaBundle)
                        .count()
                        != 1
                {
                    return Err(ProductionInputIdentityError::InvalidRequest(
                        "networked fetch scope",
                    ));
                }
            }
            ProductionInputPreflightScope::PreprovisionedFetch => {
                if self.host_build_input_closure_digest.is_some()
                    || !has_only_one_sysroot(&self.trees)
                    || self.files.iter().any(|file| {
                        matches!(
                            file.role,
                            ProductionInputFileRole::CredentialHelper
                                | ProductionInputFileRole::FetchTlsCaBundle
                                | ProductionInputFileRole::BuildExecutable
                                | ProductionInputFileRole::HostLinker
                                | ProductionInputFileRole::HostLinkerHelper
                                | ProductionInputFileRole::TargetLinker
                        )
                    })
                {
                    return Err(ProductionInputIdentityError::InvalidRequest(
                        "preprovisioned fetch scope",
                    ));
                }
            }
            ProductionInputPreflightScope::Build => {
                let host_linkers = self
                    .files
                    .iter()
                    .filter(|file| file.role == ProductionInputFileRole::HostLinker)
                    .count();
                let host_linker_helpers = self
                    .files
                    .iter()
                    .filter(|file| file.role == ProductionInputFileRole::HostLinkerHelper)
                    .count();
                let target_linkers = self
                    .files
                    .iter()
                    .filter(|file| file.role == ProductionInputFileRole::TargetLinker)
                    .count();
                if self.host_build_input_closure_digest.is_none()
                    || self.files.iter().any(|file| {
                        matches!(
                            file.role,
                            ProductionInputFileRole::CredentialHelper
                                | ProductionInputFileRole::FetchTlsCaBundle
                        )
                    })
                    || self
                        .trees
                        .iter()
                        .filter(|tree| tree.role == ProductionInputTreeRole::RustSysroot)
                        .count()
                        != 1
                    || host_linkers > 1
                    || (host_linker_helpers > 0 && host_linkers != 1)
                    || target_linkers > 1
                {
                    return Err(ProductionInputIdentityError::InvalidRequest("build scope"));
                }
            }
        }
        if self.recompute_digest()? != self.digest {
            return Err(ProductionInputIdentityError::RequestDigestMismatch);
        }
        Ok(())
    }
}

fn has_only_one_sysroot(trees: &[ProductionInputTree]) -> bool {
    trees.len() == 1 && trees[0].role == ProductionInputTreeRole::RustSysroot
}

impl ProductionInputIdentityObservation {
    pub fn new(
        request_digest: String,
        probes: Vec<ProductionVersionProbeResult>,
    ) -> Result<Self, ProductionInputIdentityError> {
        let mut observation = Self {
            schema: 3,
            request_digest,
            probes,
            digest: String::new(),
        };
        observation.digest = observation.recompute_digest()?;
        observation.verify_self()?;
        Ok(observation)
    }

    pub fn from_json(input: &str) -> Result<Self, ProductionInputIdentityError> {
        if input.len() > MAX_IDENTITY_JSON_BYTES {
            return Err(ProductionInputIdentityError::JsonTooLarge);
        }
        let observation: Self = serde_json::from_str(input)?;
        observation.verify_self()?;
        Ok(observation)
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    fn recompute_digest(&self) -> Result<String, ProductionInputIdentityError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-production-input-identity-observation-v3\0",
            &ObservationProjection {
                schema: self.schema,
                request_digest: &self.request_digest,
                probes: &self.probes,
            },
        )?))
    }

    fn verify_self(&self) -> Result<(), ProductionInputIdentityError> {
        if self.schema != 3 {
            return Err(ProductionInputIdentityError::UnsupportedSchema(self.schema));
        }
        if !is_digest(&self.request_digest)
            || self.probes.len() > MAX_BUILD_REQUIREMENT_ENTRIES_PER_KIND + 3
        {
            return Err(ProductionInputIdentityError::InvalidObservation(
                "request or probe count",
            ));
        }
        if !self
            .probes
            .windows(2)
            .all(|pair| probe_result_key(&pair[0]) < probe_result_key(&pair[1]))
        {
            return Err(ProductionInputIdentityError::InvalidObservation(
                "probe ordering",
            ));
        }
        for result in &self.probes {
            if !valid_id(&result.id)
                || !is_digest(&result.executable_sha256)
                || result.stdout.len() > MAX_VERSION_PROBE_OUTPUT_BYTES
                || result.stderr.len() > MAX_VERSION_PROBE_OUTPUT_BYTES
                || result.stdout.contains('\0')
                || result.stderr.contains('\0')
            {
                return Err(ProductionInputIdentityError::InvalidObservation(
                    "probe result",
                ));
            }
        }
        if self.recompute_digest()? != self.digest {
            return Err(ProductionInputIdentityError::ObservationDigestMismatch);
        }
        Ok(())
    }
}

impl ProductionTargetFactsProbeRequest {
    pub fn from_json(input: &str) -> Result<Self, ProductionInputIdentityError> {
        if input.len() > MAX_TARGET_FACTS_PROBE_JSON_BYTES {
            return Err(ProductionInputIdentityError::JsonTooLarge);
        }
        let request: Self = serde_json::from_str(input)?;
        request.verify_self()?;
        Ok(request)
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    fn for_inputs(
        inputs: &VerifiedProductionInputs,
        closure: &NormalizedHostBuildInputClosure,
    ) -> Result<Self, ProductionInputIdentityError> {
        inputs.request.verify_self()?;
        if inputs.request.scope != ProductionInputPreflightScope::Build
            || inputs.request.host_build_input_closure_digest.as_deref() != Some(closure.digest())
            || inputs.request.build_execution_policy_digest
                != closure.build_execution_policy_digest()
        {
            return Err(ProductionInputIdentityError::TargetFactsProbeRequestMismatch);
        }
        let rustc = inputs
            .request
            .files
            .iter()
            .find(|file| file.role == ProductionInputFileRole::Rustc)
            .ok_or(ProductionInputIdentityError::TargetFactsProbeRequestMismatch)?;
        let context = closure.build_context();
        let custom_target_spec_logical_path = match &context.custom_target_spec_digest {
            Some(_) => Some(
                closure
                    .items()
                    .iter()
                    .find(|item| item.role == crate::HostBuildClosureItemRole::CustomTargetSpec)
                    .ok_or(ProductionInputIdentityError::TargetFactsProbeRequestMismatch)?
                    .logical_path
                    .clone(),
            ),
            None => None,
        };
        let target_argument = custom_target_spec_logical_path
            .as_deref()
            .unwrap_or(&context.target);
        let mut arguments = vec![
            "--print".into(),
            "cfg".into(),
            "--target".into(),
            target_argument.into(),
        ];
        if custom_target_spec_logical_path.is_some() {
            arguments.push("-Zunstable-options".into());
        }
        let mut request = Self {
            schema: 1,
            production_input_request_digest: inputs.request.digest.clone(),
            host_build_input_closure_digest: closure.digest().into(),
            build_execution_policy_digest: closure.build_execution_policy_digest().into(),
            rustc_sha256: rustc.sha256.clone(),
            target: context.target.clone(),
            custom_target_spec_digest: context.custom_target_spec_digest.clone(),
            custom_target_spec_logical_path,
            arguments,
            environment_cleared: true,
            working_directory: "/".into(),
            expected_target_facts_digest: context.target_facts_digest.clone(),
            digest: String::new(),
        };
        request.digest = request.recompute_digest()?;
        request.verify_self()?;
        Ok(request)
    }

    fn recompute_digest(&self) -> Result<String, ProductionInputIdentityError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-production-target-facts-probe-request-v1\0",
            &TargetFactsProbeRequestProjection {
                schema: self.schema,
                production_input_request_digest: &self.production_input_request_digest,
                host_build_input_closure_digest: &self.host_build_input_closure_digest,
                build_execution_policy_digest: &self.build_execution_policy_digest,
                rustc_sha256: &self.rustc_sha256,
                target: &self.target,
                custom_target_spec_digest: self.custom_target_spec_digest.as_deref(),
                custom_target_spec_logical_path: self.custom_target_spec_logical_path.as_deref(),
                arguments: &self.arguments,
                environment_cleared: self.environment_cleared,
                working_directory: &self.working_directory,
                expected_target_facts_digest: &self.expected_target_facts_digest,
            },
        )?))
    }

    fn verify_self(&self) -> Result<(), ProductionInputIdentityError> {
        if self.schema != 1 {
            return Err(ProductionInputIdentityError::UnsupportedSchema(self.schema));
        }
        if !is_digest(&self.production_input_request_digest)
            || !is_digest(&self.host_build_input_closure_digest)
            || !is_digest(&self.build_execution_policy_digest)
            || !is_digest(&self.rustc_sha256)
            || !is_digest(&self.expected_target_facts_digest)
            || validate_target_triple(&self.target).is_err()
            || !self.environment_cleared
            || self.working_directory != "/"
        {
            return Err(ProductionInputIdentityError::TargetFactsProbeRequestMismatch);
        }
        let target_argument = match (
            self.custom_target_spec_digest.as_deref(),
            self.custom_target_spec_logical_path.as_deref(),
        ) {
            (None, None) => self.target.as_str(),
            (Some(digest), Some(path))
                if is_digest(digest)
                    && is_path(Path::new(path))
                    && path.starts_with("/rust-agent/closure/") =>
            {
                path
            }
            _ => return Err(ProductionInputIdentityError::TargetFactsProbeRequestMismatch),
        };
        let mut expected_arguments = vec![
            "--print".to_owned(),
            "cfg".to_owned(),
            "--target".to_owned(),
            target_argument.to_owned(),
        ];
        if self.custom_target_spec_digest.is_some() {
            expected_arguments.push("-Zunstable-options".into());
        }
        if self.arguments != expected_arguments || self.recompute_digest()? != self.digest {
            return Err(ProductionInputIdentityError::TargetFactsProbeRequestMismatch);
        }
        Ok(())
    }
}

impl ProductionTargetFactsProbeObservation {
    pub fn new(
        request: &ProductionTargetFactsProbeRequest,
        exit_code: i32,
        stdout: String,
        stderr: String,
        target_facts: TargetFactsRecord,
    ) -> Result<Self, ProductionInputIdentityError> {
        request.verify_self()?;
        let mut observation = Self {
            schema: 1,
            request_digest: request.digest.clone(),
            rustc_sha256: request.rustc_sha256.clone(),
            arguments: request.arguments.clone(),
            environment_cleared: request.environment_cleared,
            working_directory: request.working_directory.clone(),
            exit_code,
            stdout,
            stderr,
            target_facts,
            digest: String::new(),
        };
        observation.digest = observation.recompute_digest()?;
        observation.verify_self()?;
        Ok(observation)
    }

    pub fn from_json(input: &str) -> Result<Self, ProductionInputIdentityError> {
        if input.len() > MAX_TARGET_FACTS_PROBE_JSON_BYTES {
            return Err(ProductionInputIdentityError::JsonTooLarge);
        }
        let observation: Self = serde_json::from_str(input)?;
        observation.verify_self()?;
        Ok(observation)
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    fn recompute_digest(&self) -> Result<String, ProductionInputIdentityError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-production-target-facts-probe-observation-v1\0",
            &TargetFactsProbeObservationProjection {
                schema: self.schema,
                request_digest: &self.request_digest,
                rustc_sha256: &self.rustc_sha256,
                arguments: &self.arguments,
                environment_cleared: self.environment_cleared,
                working_directory: &self.working_directory,
                exit_code: self.exit_code,
                stdout: &self.stdout,
                stderr: &self.stderr,
                target_facts: &self.target_facts,
            },
        )?))
    }

    fn verify_self(&self) -> Result<(), ProductionInputIdentityError> {
        if self.schema != 1 {
            return Err(ProductionInputIdentityError::UnsupportedSchema(self.schema));
        }
        if !is_digest(&self.request_digest)
            || !is_digest(&self.rustc_sha256)
            || self.arguments.len() > 5
            || !self.environment_cleared
            || self.working_directory != "/"
            || self.stdout.len() > MAX_RUSTC_CFG_OUTPUT_BYTES
            || self.stderr.len() > MAX_RUSTC_DIAGNOSTIC_BYTES
            || self.stdout.contains('\0')
            || self.stderr.contains('\0')
        {
            return Err(ProductionInputIdentityError::TargetFactsProbeObservationMismatch);
        }
        self.target_facts.validate()?;
        if self.recompute_digest()? != self.digest {
            return Err(ProductionInputIdentityError::ObservationDigestMismatch);
        }
        Ok(())
    }
}

impl VerifiedProductionInputs {
    pub fn request(&self) -> &ProductionInputIdentityRequest {
        &self.request
    }

    pub fn verify_unchanged(&self) -> Result<(), ProductionInputIdentityError> {
        for file in &self.files {
            file.identity.reverify().map_err(|error| {
                ProductionInputIdentityError::Snapshot(match error {
                    SnapshotMaterializationError::SourceChanged(_) => {
                        SnapshotMaterializationError::SourceChanged(format!(
                            "{:?}:{}",
                            file.role, file.id
                        ))
                    }
                    other => other,
                })
            })?;
        }
        for tree in &self.trees {
            tree.identity.reverify().map_err(|error| {
                ProductionInputIdentityError::Snapshot(match error {
                    SnapshotMaterializationError::SourceChanged(_) => {
                        SnapshotMaterializationError::SourceChanged(format!(
                            "{:?}:{}",
                            tree.role, tree.id
                        ))
                    }
                    other => other,
                })
            })?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retained_file_identity(
        &self,
        role: ProductionInputFileRole,
        id: &str,
    ) -> Result<AnchoredFileIdentity, ProductionInputIdentityError> {
        self.files
            .iter()
            .find(|file| file.role == role && file.id == id)
            .map(|file| file.identity.clone())
            .ok_or(ProductionInputIdentityError::InvalidRequest(
                "missing retained file anchor",
            ))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retained_tree_identity(
        &self,
        role: ProductionInputTreeRole,
        id: &str,
    ) -> Result<AnchoredTreeIdentity, ProductionInputIdentityError> {
        self.trees
            .iter()
            .find(|tree| tree.role == role && tree.id == id)
            .map(|tree| tree.identity.clone())
            .ok_or(ProductionInputIdentityError::InvalidRequest(
                "missing retained tree anchor",
            ))
    }

    pub fn validate_probe_observation(
        &self,
        observation: &ProductionInputIdentityObservation,
    ) -> Result<ValidatedProductionInputIdentityObservation, ProductionInputIdentityError> {
        self.verify_unchanged()?;
        let validated = self.validate_probe_observation_contract(observation)?;
        self.verify_unchanged()?;
        Ok(validated)
    }

    /// Runs the schema-fixed version probes through the retained Linux file
    /// descriptors and returns non-authoritative local evidence.
    ///
    /// This function clears the environment, uses `/` as its working
    /// directory, bounds both output streams, applies a fixed deadline and
    /// kills the complete probe process group on timeout. It deliberately does
    /// not claim production authority: immutable mounts, Landlock/seccomp and
    /// the trusted outer completion attestation remain backend responsibilities.
    pub fn run_local_version_probes(
        &self,
    ) -> Result<ProductionInputIdentityObservation, ProductionInputIdentityError> {
        self.verify_unchanged()?;
        let result = (|| {
            let mut results = Vec::new();
            for file in self.request.expected_probes() {
                let probe = file.version_probe.as_ref().expect("filtered probe");
                let verified = self
                    .files
                    .iter()
                    .find(|verified| verified.role == file.role && verified.id == file.id)
                    .ok_or(ProductionInputIdentityError::InvalidRequest(
                        "missing retained file anchor",
                    ))?;
                results.push(run_descriptor_probe(
                    verified,
                    file,
                    probe,
                    VERSION_PROBE_TIMEOUT,
                )?);
            }
            let observation =
                ProductionInputIdentityObservation::new(self.request.digest.clone(), results)?;
            self.validate_probe_observation_contract(&observation)?;
            Ok(observation)
        })();
        self.verify_unchanged()?;
        result
    }

    pub fn target_facts_probe_request(
        &self,
        closure: &NormalizedHostBuildInputClosure,
    ) -> Result<ProductionTargetFactsProbeRequest, ProductionInputIdentityError> {
        self.verify_unchanged()?;
        ProductionTargetFactsProbeRequest::for_inputs(self, closure)
    }

    pub fn validate_target_facts_probe_observation(
        &self,
        closure: &NormalizedHostBuildInputClosure,
        observation: &ProductionTargetFactsProbeObservation,
    ) -> Result<ValidatedProductionTargetFactsProbeObservation, ProductionInputIdentityError> {
        self.verify_unchanged()?;
        let request = ProductionTargetFactsProbeRequest::for_inputs(self, closure)?;
        let validated =
            Self::validate_target_facts_probe_observation_contract(&request, observation)?;
        self.verify_unchanged()?;
        Ok(validated)
    }

    /// Reproduces built-in target facts through the retained rustc descriptor
    /// and returns non-authoritative local evidence.
    ///
    /// Custom target snapshots deliberately require the future trusted mounted
    /// view so their logical path cannot be substituted with an ambient Host
    /// path. As with local version probes, this method does not produce a
    /// deployable production attestation.
    pub fn run_local_target_facts_probe(
        &self,
        closure: &NormalizedHostBuildInputClosure,
    ) -> Result<ProductionTargetFactsProbeObservation, ProductionInputIdentityError> {
        self.verify_unchanged()?;
        let result = (|| {
            let request = ProductionTargetFactsProbeRequest::for_inputs(self, closure)?;
            require_local_target_probe_support(&request)?;
            let rustc = self
                .files
                .iter()
                .find(|file| file.role == ProductionInputFileRole::Rustc)
                .ok_or(ProductionInputIdentityError::TargetFactsProbeRequestMismatch)?;
            let output = run_descriptor_command(
                rustc,
                "rustc-target-facts",
                &request.arguments,
                VERSION_PROBE_TIMEOUT,
                MAX_RUSTC_CFG_OUTPUT_BYTES,
                MAX_RUSTC_DIAGNOSTIC_BYTES,
            )?;
            if output.exit_code != 0 {
                return Err(ProductionInputIdentityError::TargetFactsProbeFailed(
                    output.exit_code,
                ));
            }
            let target_facts = target_facts_from_probe(&request, &output.stdout)?;
            let observation = ProductionTargetFactsProbeObservation::new(
                &request,
                output.exit_code,
                output.stdout,
                output.stderr,
                target_facts,
            )?;
            Self::validate_target_facts_probe_observation_contract(&request, &observation)?;
            Ok(observation)
        })();
        self.verify_unchanged()?;
        result
    }

    fn validate_target_facts_probe_observation_contract(
        request: &ProductionTargetFactsProbeRequest,
        observation: &ProductionTargetFactsProbeObservation,
    ) -> Result<ValidatedProductionTargetFactsProbeObservation, ProductionInputIdentityError> {
        request.verify_self()?;
        observation.verify_self()?;
        if observation.request_digest != request.digest
            || observation.rustc_sha256 != request.rustc_sha256
            || observation.arguments != request.arguments
            || observation.environment_cleared != request.environment_cleared
            || observation.working_directory != request.working_directory
        {
            return Err(ProductionInputIdentityError::TargetFactsProbeObservationMismatch);
        }
        if observation.exit_code != 0 {
            return Err(ProductionInputIdentityError::TargetFactsProbeFailed(
                observation.exit_code,
            ));
        }
        let parsed = target_facts_from_probe(request, &observation.stdout)?;
        let target_facts_digest = parsed.semantic_digest()?;
        if parsed != observation.target_facts
            || target_facts_digest != request.expected_target_facts_digest
        {
            return Err(ProductionInputIdentityError::TargetFactsMismatch);
        }
        Ok(ValidatedProductionTargetFactsProbeObservation {
            request: request.digest.clone(),
            observation: observation.digest.clone(),
            target_facts: target_facts_digest,
        })
    }

    fn validate_probe_observation_contract(
        &self,
        observation: &ProductionInputIdentityObservation,
    ) -> Result<ValidatedProductionInputIdentityObservation, ProductionInputIdentityError> {
        self.request.verify_self()?;
        observation.verify_self()?;
        if observation.request_digest != self.request.digest {
            return Err(ProductionInputIdentityError::ObservationRequestMismatch);
        }
        let expected = self.request.expected_probes().collect::<Vec<_>>();
        if expected.len() != observation.probes.len() {
            return Err(ProductionInputIdentityError::ObservationRequestMismatch);
        }
        for (file, result) in expected.into_iter().zip(&observation.probes) {
            let probe = file.version_probe.as_ref().expect("filtered probe");
            if result.role != file.role
                || result.id != file.id
                || result.executable_sha256 != file.sha256
                || result.arguments != probe.arguments
            {
                return Err(ProductionInputIdentityError::ObservationRequestMismatch);
            }
            if result.exit_code != 0
                || first_stdout_line(&result.stdout)
                    != Some(probe.expected_first_stdout_line.as_str())
            {
                return Err(ProductionInputIdentityError::VersionProbeFailed(
                    file.id.clone(),
                ));
            }
        }
        Ok(ValidatedProductionInputIdentityObservation {
            request_digest: self.request.digest.clone(),
            observation_digest: observation.digest.clone(),
        })
    }
}

pub(crate) fn target_facts_from_probe(
    request: &ProductionTargetFactsProbeRequest,
    stdout: &str,
) -> Result<TargetFactsRecord, ProductionInputIdentityError> {
    Ok(TargetFactsRecord::new(
        request.target.clone(),
        parse_facts(stdout)?,
        request.custom_target_spec_digest.clone(),
    )?)
}

fn require_local_target_probe_support(
    request: &ProductionTargetFactsProbeRequest,
) -> Result<(), ProductionInputIdentityError> {
    if request.custom_target_spec_digest.is_some() {
        Err(ProductionInputIdentityError::CustomTargetProbeRequiresMountedView)
    } else {
        Ok(())
    }
}

type ProbeReader = thread::JoinHandle<Result<Vec<u8>, ProductionInputIdentityError>>;

fn run_descriptor_probe(
    verified: &VerifiedFile,
    file: &ProductionInputFile,
    probe: &ProductionVersionProbe,
    timeout: Duration,
) -> Result<ProductionVersionProbeResult, ProductionInputIdentityError> {
    let output = run_descriptor_command(
        verified,
        &file.id,
        &probe.arguments,
        timeout,
        MAX_VERSION_PROBE_OUTPUT_BYTES,
        MAX_VERSION_PROBE_OUTPUT_BYTES,
    )?;
    Ok(ProductionVersionProbeResult {
        role: file.role,
        id: file.id.clone(),
        executable_sha256: file.sha256.clone(),
        arguments: probe.arguments.clone(),
        exit_code: output.exit_code,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

struct DescriptorCommandOutput {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

#[cfg(target_os = "linux")]
fn run_descriptor_command(
    verified: &VerifiedFile,
    id: &str,
    arguments: &[String],
    timeout: Duration,
    maximum_stdout: usize,
    maximum_stderr: usize,
) -> Result<DescriptorCommandOutput, ProductionInputIdentityError> {
    if !verified.identity.is_linux_elf() {
        return Err(ProductionInputIdentityError::UnsupportedExecutableFormat(
            id.into(),
        ));
    }
    let executable = verified.identity.descriptor_execution_path();
    let mut command = Command::new(executable);
    command
        .args(arguments)
        .env_clear()
        .current_dir(Path::new("/"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;

        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .map_err(|source| ProductionInputIdentityError::ProbeIo {
            id: id.into(),
            source,
        })?;
    #[cfg(unix)]
    let process_group = rustix::process::Pid::from_child(&child);
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| ProductionInputIdentityError::ProbeIo {
            id: id.into(),
            source: io::Error::other("stdout pipe was unavailable after successful spawn"),
        })?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| ProductionInputIdentityError::ProbeIo {
            id: id.into(),
            source: io::Error::other("stderr pipe was unavailable after successful spawn"),
        })?;
    let stdout_id = id.to_owned();
    let stderr_id = id.to_owned();
    let mut stdout_reader = Some(thread::spawn(move || {
        read_bounded_probe_stream(stdout, stdout_id, "stdout", maximum_stdout)
    }));
    let mut stderr_reader = Some(thread::spawn(move || {
        read_bounded_probe_stream(stderr, stderr_id, "stderr", maximum_stderr)
    }));
    let started = Instant::now();
    let deadline = started.checked_add(timeout).unwrap_or(started);
    let mut status = None;
    let mut stdout = None;
    let mut stderr = None;
    loop {
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|source| ProductionInputIdentityError::ProbeIo {
                    id: id.into(),
                    source,
                })?;
        }
        collect_finished_probe_reader(id, &mut stdout_reader, &mut stdout);
        collect_finished_probe_reader(id, &mut stderr_reader, &mut stderr);
        if status.is_some() && stdout.is_some() && stderr.is_some() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            #[cfg(unix)]
            let _ =
                rustix::process::kill_process_group(process_group, rustix::process::Signal::KILL);
            let cleaned = terminate_and_collect_probe(
                id,
                &mut child,
                &mut status,
                &mut stdout_reader,
                &mut stdout,
                &mut stderr_reader,
                &mut stderr,
                now.checked_add(VERSION_PROBE_TERMINATION_GRACE)
                    .unwrap_or(now),
            );
            if !cleaned {
                return Err(ProductionInputIdentityError::ProbeCleanupFailed(id.into()));
            }
            return Err(ProductionInputIdentityError::ProbeTimedOut {
                id: id.into(),
                milliseconds: timeout.as_millis(),
            });
        }
        thread::sleep(
            deadline
                .saturating_duration_since(now)
                .min(VERSION_PROBE_POLL_INTERVAL),
        );
    }
    let status = status.expect("probe status is present after the observation loop");
    let stdout = stdout.expect("probe stdout is present after the observation loop")?;
    let stderr = stderr.expect("probe stderr is present after the observation loop")?;
    Ok(DescriptorCommandOutput {
        exit_code: status.code().unwrap_or(-1),
        stdout: String::from_utf8(stdout).map_err(|_| {
            ProductionInputIdentityError::InvalidProbeOutputEncoding {
                id: id.into(),
                stream: "stdout",
            }
        })?,
        stderr: String::from_utf8(stderr).map_err(|_| {
            ProductionInputIdentityError::InvalidProbeOutputEncoding {
                id: id.into(),
                stream: "stderr",
            }
        })?,
    })
}

#[cfg(not(target_os = "linux"))]
fn run_descriptor_command(
    _verified: &VerifiedFile,
    _id: &str,
    _arguments: &[String],
    _timeout: Duration,
    _maximum_stdout: usize,
    _maximum_stderr: usize,
) -> Result<DescriptorCommandOutput, ProductionInputIdentityError> {
    Err(SnapshotMaterializationError::UnsupportedHost.into())
}

fn collect_finished_probe_reader(
    id: &str,
    reader: &mut Option<ProbeReader>,
    output: &mut Option<Result<Vec<u8>, ProductionInputIdentityError>>,
) {
    if reader.as_ref().is_some_and(ProbeReader::is_finished) {
        let finished = reader
            .take()
            .expect("a finished probe reader must still be present");
        *output = Some(
            finished
                .join()
                .map_err(|_| ProductionInputIdentityError::ProbeReaderPanicked { id: id.into() })
                .and_then(|value| value),
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn terminate_and_collect_probe(
    id: &str,
    child: &mut Child,
    status: &mut Option<ExitStatus>,
    stdout_reader: &mut Option<ProbeReader>,
    stdout: &mut Option<Result<Vec<u8>, ProductionInputIdentityError>>,
    stderr_reader: &mut Option<ProbeReader>,
    stderr: &mut Option<Result<Vec<u8>, ProductionInputIdentityError>>,
    cleanup_deadline: Instant,
) -> bool {
    let _ = child.kill();
    loop {
        if status.is_none()
            && let Ok(observed) = child.try_wait()
        {
            *status = observed;
        }
        collect_finished_probe_reader(id, stdout_reader, stdout);
        collect_finished_probe_reader(id, stderr_reader, stderr);
        if status.is_some() && stdout_reader.is_none() && stderr_reader.is_none() {
            return true;
        }
        let now = Instant::now();
        if now >= cleanup_deadline {
            return false;
        }
        thread::sleep(
            cleanup_deadline
                .saturating_duration_since(now)
                .min(VERSION_PROBE_POLL_INTERVAL),
        );
    }
}

fn read_bounded_probe_stream(
    mut stream: impl Read,
    id: String,
    stream_name: &'static str,
    maximum: usize,
) -> Result<Vec<u8>, ProductionInputIdentityError> {
    let mut output = Vec::with_capacity(maximum.min(8 * 1024));
    let mut buffer = [0_u8; 8 * 1024];
    let mut too_large = false;
    loop {
        let count =
            stream
                .read(&mut buffer)
                .map_err(|source| ProductionInputIdentityError::ProbeIo {
                    id: id.clone(),
                    source,
                })?;
        if count == 0 {
            break;
        }
        if !too_large {
            let remaining = maximum.saturating_sub(output.len());
            if count <= remaining {
                output.extend_from_slice(&buffer[..count]);
            } else {
                too_large = true;
            }
        }
    }
    if too_large {
        Err(ProductionInputIdentityError::ProbeOutputTooLarge {
            id,
            stream: stream_name,
            maximum,
        })
    } else {
        Ok(output)
    }
}

impl ValidatedProductionInputIdentityObservation {
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn observation_digest(&self) -> &str {
        &self.observation_digest
    }
}

impl ValidatedProductionTargetFactsProbeObservation {
    pub fn request_digest(&self) -> &str {
        &self.request
    }

    pub fn observation_digest(&self) -> &str {
        &self.observation
    }

    pub fn target_facts_digest(&self) -> &str {
        &self.target_facts
    }
}

fn fetch_request(
    policy: &NormalizedProductionBuildPolicy,
    mode: CargoFetchMode,
) -> Result<ProductionInputIdentityRequest, ProductionInputIdentityError> {
    let policy_data = policy.policy();
    let mut files = vec![
        tool_file(
            ProductionInputFileRole::Cargo,
            "cargo",
            &policy_data.toolchain.cargo.path,
            &policy_data.toolchain.cargo.sha256,
            &policy_data.toolchain.cargo.version,
            &["-V"],
        ),
        tool_file(
            ProductionInputFileRole::Rustc,
            "rustc",
            &policy_data.toolchain.rustc.path,
            &policy_data.toolchain.rustc.sha256,
            &policy_data.toolchain.rustc.version,
            &["-vV"],
        ),
    ];
    let scope = match mode {
        CargoFetchMode::Networked => {
            let ca_bundle = policy_data.fetch.tls_ca_bundle.as_ref().ok_or(
                ProductionInputIdentityError::InvalidRequest("missing fetch TLS CA bundle"),
            )?;
            files.push(ProductionInputFile {
                role: ProductionInputFileRole::FetchTlsCaBundle,
                id: "fetch-tls-ca-bundle".into(),
                path: ca_bundle.path.clone(),
                sha256: ca_bundle.sha256.clone(),
                version_probe: None,
            });
            if let Some(helper) = &policy_data.fetch.credential_helper {
                files.push(ProductionInputFile {
                    role: ProductionInputFileRole::CredentialHelper,
                    id: "cargo-credential-helper".into(),
                    path: helper.path.clone(),
                    sha256: helper.sha256.clone(),
                    version_probe: None,
                });
            }
            ProductionInputPreflightScope::NetworkedFetch
        }
        CargoFetchMode::Preprovisioned => ProductionInputPreflightScope::PreprovisionedFetch,
    };
    let trees = vec![ProductionInputTree {
        role: ProductionInputTreeRole::RustSysroot,
        id: "rust-sysroot".into(),
        path: policy_data.toolchain.sysroot.path.clone(),
        tree_digest: policy_data.toolchain.sysroot.tree_digest.clone(),
    }];
    finish_request(policy.full_digest(), scope, None, files, trees)
}

fn build_request(
    policy: &NormalizedProductionBuildPolicy,
    requirements: &BuildRequirements,
    target: &str,
    closure_digest: Option<&str>,
) -> Result<ProductionInputIdentityRequest, ProductionInputIdentityError> {
    let policy_data = policy.policy();
    let mut files = vec![
        tool_file(
            ProductionInputFileRole::Cargo,
            "cargo",
            &policy_data.toolchain.cargo.path,
            &policy_data.toolchain.cargo.sha256,
            &policy_data.toolchain.cargo.version,
            &["-V"],
        ),
        tool_file(
            ProductionInputFileRole::Rustc,
            "rustc",
            &policy_data.toolchain.rustc.path,
            &policy_data.toolchain.rustc.sha256,
            &policy_data.toolchain.rustc.version,
            &["-vV"],
        ),
    ];
    for id in &requirements.executables {
        let executable = policy_data
            .executables
            .iter()
            .find(|item| &item.id == id)
            .ok_or(ProductionInputIdentityError::InvalidRequest(
                "unresolved executable",
            ))?;
        let role = policy_data.host_linker.as_ref().map_or(
            ProductionInputFileRole::BuildExecutable,
            |bundle| {
                if bundle.executable == *id {
                    ProductionInputFileRole::HostLinker
                } else if bundle.helpers.contains(id) {
                    ProductionInputFileRole::HostLinkerHelper
                } else {
                    ProductionInputFileRole::BuildExecutable
                }
            },
        );
        files.push(tool_file(
            role,
            &executable.id,
            &executable.path,
            &executable.sha256,
            &executable.version,
            &["--version"],
        ));
    }
    if let Some(linker) = policy.selected_target_linker(target)? {
        files.push(tool_file(
            ProductionInputFileRole::TargetLinker,
            &linker.id,
            &linker.path,
            &linker.sha256,
            &linker.version,
            &["-flavor", "wasm", "--version"],
        ));
    }
    let mut trees = vec![ProductionInputTree {
        role: ProductionInputTreeRole::RustSysroot,
        id: "rust-sysroot".into(),
        path: policy_data.toolchain.sysroot.path.clone(),
        tree_digest: policy_data.toolchain.sysroot.tree_digest.clone(),
    }];
    for id in &requirements.read_inputs {
        let input = policy_data
            .read_inputs
            .iter()
            .find(|item| &item.id == id)
            .ok_or(ProductionInputIdentityError::InvalidRequest(
                "unresolved read input",
            ))?;
        trees.push(ProductionInputTree {
            role: ProductionInputTreeRole::BuildReadInput,
            id: input.id.clone(),
            path: input.path.clone(),
            tree_digest: input.tree_digest.clone(),
        });
    }
    finish_request(
        policy.full_digest(),
        ProductionInputPreflightScope::Build,
        closure_digest,
        files,
        trees,
    )
}

fn tool_file(
    role: ProductionInputFileRole,
    id: &str,
    path: &Path,
    sha256: &str,
    version: &str,
    arguments: &[&str],
) -> ProductionInputFile {
    ProductionInputFile {
        role,
        id: id.into(),
        path: path.into(),
        sha256: sha256.into(),
        version_probe: Some(ProductionVersionProbe {
            arguments: arguments
                .iter()
                .map(|argument| (*argument).into())
                .collect(),
            expected_first_stdout_line: version.into(),
        }),
    }
}

fn finish_request(
    policy_digest: &str,
    scope: ProductionInputPreflightScope,
    closure_digest: Option<&str>,
    mut files: Vec<ProductionInputFile>,
    mut trees: Vec<ProductionInputTree>,
) -> Result<ProductionInputIdentityRequest, ProductionInputIdentityError> {
    files.sort_by(|left, right| file_key(left).cmp(&file_key(right)));
    trees.sort_by(|left, right| tree_key(left).cmp(&tree_key(right)));
    let mut request = ProductionInputIdentityRequest {
        schema: 4,
        scope,
        build_execution_policy_digest: policy_digest.into(),
        host_build_input_closure_digest: closure_digest.map(str::to_owned),
        files,
        trees,
        digest: String::new(),
    };
    request.digest = request.recompute_digest()?;
    request.verify_self()?;
    Ok(request)
}

fn preflight_inputs(
    request: ProductionInputIdentityRequest,
) -> Result<VerifiedProductionInputs, ProductionInputIdentityError> {
    request.verify_self()?;
    let mut files = Vec::with_capacity(request.files.len());
    for expected in &request.files {
        let identity = anchor_file_identity(&expected.path)?;
        if expected.role != ProductionInputFileRole::FetchTlsCaBundle && !identity.is_executable() {
            return Err(ProductionInputIdentityError::FileNotExecutable(
                expected.id.clone(),
            ));
        }
        if identity.sha256() != expected.sha256 {
            return Err(ProductionInputIdentityError::FileDigestMismatch {
                id: expected.id.clone(),
                expected: expected.sha256.clone(),
                actual: identity.sha256().into(),
            });
        }
        files.push(VerifiedFile {
            role: expected.role,
            id: expected.id.clone(),
            identity,
        });
    }
    let mut trees = Vec::with_capacity(request.trees.len());
    for expected in &request.trees {
        let identity = anchor_tree_identity(&expected.path)?;
        if identity.digest() != expected.tree_digest {
            return Err(ProductionInputIdentityError::TreeDigestMismatch {
                id: expected.id.clone(),
                expected: expected.tree_digest.clone(),
                actual: identity.digest().into(),
            });
        }
        trees.push(VerifiedTree {
            role: expected.role,
            id: expected.id.clone(),
            identity,
        });
    }
    let verified = VerifiedProductionInputs {
        request,
        files,
        trees,
    };
    verified.verify_unchanged()?;
    Ok(verified)
}

fn validate_file(file: &ProductionInputFile) -> Result<(), ProductionInputIdentityError> {
    if !valid_id(&file.id) || !is_path(&file.path) || !is_digest(&file.sha256) {
        return Err(ProductionInputIdentityError::InvalidRequest(
            "file identity",
        ));
    }
    let expected_arguments: Option<&[&str]> = match file.role {
        ProductionInputFileRole::Cargo => Some(&["-V"]),
        ProductionInputFileRole::Rustc => Some(&["-vV"]),
        ProductionInputFileRole::CredentialHelper | ProductionInputFileRole::FetchTlsCaBundle => {
            None
        }
        ProductionInputFileRole::BuildExecutable
        | ProductionInputFileRole::HostLinker
        | ProductionInputFileRole::HostLinkerHelper => Some(&["--version"]),
        ProductionInputFileRole::TargetLinker => Some(&["-flavor", "wasm", "--version"]),
    };
    match (&file.version_probe, expected_arguments) {
        (None, None) => Ok(()),
        (Some(probe), Some(expected))
            if probe
                .arguments
                .iter()
                .map(String::as_str)
                .eq(expected.iter().copied())
                && valid_version(&probe.expected_first_stdout_line) =>
        {
            Ok(())
        }
        _ => Err(ProductionInputIdentityError::InvalidRequest(
            "version probe",
        )),
    }
}

fn validate_tree(tree: &ProductionInputTree) -> Result<(), ProductionInputIdentityError> {
    if valid_id(&tree.id) && is_path(&tree.path) && is_digest(&tree.tree_digest) {
        Ok(())
    } else {
        Err(ProductionInputIdentityError::InvalidRequest(
            "tree identity",
        ))
    }
}

fn file_key(file: &ProductionInputFile) -> (ProductionInputFileRole, &str) {
    (file.role, &file.id)
}

fn tree_key(tree: &ProductionInputTree) -> (ProductionInputTreeRole, &str) {
    (tree.role, &tree.id)
}

fn probe_result_key(result: &ProductionVersionProbeResult) -> (ProductionInputFileRole, &str) {
    (result.role, &result.id)
}

fn first_stdout_line(output: &str) -> Option<&str> {
    let first = output.split_once('\n').map_or(output, |(first, _)| first);
    (!first.is_empty() && !first.ends_with('\r')).then_some(first)
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.contains(['\0', '\n', '\r'])
}

fn valid_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && !bytes.windows(2).any(|pair| pair == b"--")
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn is_path(path: &Path) -> bool {
    path.to_str().is_some_and(|value| {
        value.starts_with('/')
            && (value == "/" || !value.ends_with('/'))
            && value
                .split('/')
                .skip(1)
                .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
    })
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::{
        collections::BTreeSet,
        fs,
        io::Write as _,
        process::Command,
        thread,
        time::{Duration, Instant},
    };

    use rust_agent_composition::snapshot::{CanonicalSnapshotEntry, CanonicalSnapshotTree};
    use sha2::{Digest as _, Sha256};
    use tempfile::TempDir;

    use super::*;
    use crate::{
        DerivedExecutablePolicy, ProductionAttestationPolicy, ProductionBuildExecutionPolicy,
        ProductionEnvironment, ProductionExecutable, ProductionFetchPolicy,
        ProductionFetchRedirectPolicy, ProductionFileIdentity, ProductionReadInput,
        ProductionSandboxBackend, ProductionTargetLinker, ProductionToolIdentity,
        ProductionToolchain, ProductionTreeIdentity, SigningHelper, TrustedSigner,
    };

    struct Fixture {
        temp: TempDir,
        policy: NormalizedProductionBuildPolicy,
        requirements: BuildRequirements,
        selected_executable: PathBuf,
        selected_read_input: PathBuf,
        side_effect_marker: PathBuf,
    }

    fn sha256(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    fn file_sha256(path: &Path) -> String {
        sha256(&fs::read(path).unwrap())
    }

    fn selected_tool(name: &str) -> PathBuf {
        let output = Command::new("rustup")
            .args(["which", name])
            .output()
            .unwrap();
        assert!(output.status.success());
        PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
            .canonicalize()
            .unwrap()
    }

    fn version_line(path: &Path, arguments: &[&str]) -> String {
        let output = Command::new(path)
            .args(arguments)
            .env_clear()
            .output()
            .unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        first_stdout_line(&stdout).unwrap().into()
    }

    fn tree_digest(file_name: &str, bytes: &[u8]) -> String {
        CanonicalSnapshotTree::from_entries(vec![CanonicalSnapshotEntry::regular_file(
            file_name,
            sha256(bytes),
            bytes.len() as u64,
        )])
        .unwrap()
        .digest()
        .into()
    }

    fn fixture() -> Fixture {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        let cargo = root.join("cargo");
        let rustc = root.join("rustc");
        let credential = root.join("credential-helper");
        let ca_bundle = root.join("ca-bundle.pem");
        let selected_executable = root.join("target-cc");
        let sysroot = root.join("sysroot");
        let selected_read_input = root.join("target-sdk");
        let side_effect_marker = root.join("side-effect");
        let cargo_bytes = format!("would-write:{}", side_effect_marker.display()).into_bytes();
        fs::write(&cargo, &cargo_bytes).unwrap();
        fs::write(&rustc, b"rustc-fixture").unwrap();
        fs::write(&credential, b"credential-fixture").unwrap();
        fs::write(&ca_bundle, b"fixture-ca-bundle").unwrap();
        fs::write(&selected_executable, b"target-cc-fixture").unwrap();
        #[cfg(unix)]
        for path in [&cargo, &rustc, &credential, &selected_executable] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::create_dir(&sysroot).unwrap();
        fs::write(sysroot.join("libcore.rlib"), b"sysroot-fixture").unwrap();
        fs::create_dir(&selected_read_input).unwrap();
        fs::write(selected_read_input.join("sdk.h"), b"sdk-fixture").unwrap();

        let policy = ProductionBuildExecutionPolicy {
            schema: 4,
            id: "fixture-policy".into(),
            host: "cfg(target_os = \"linux\")".into(),
            backend: ProductionSandboxBackend::LinuxLandlockSeccomp,
            fetch: ProductionFetchPolicy {
                network_endpoints: vec!["https://index.crates.io:443".into()],
                credential_helper: Some(ProductionFileIdentity {
                    path: credential,
                    sha256: sha256(b"credential-fixture"),
                }),
                tls_ca_bundle: Some(ProductionFileIdentity {
                    path: ca_bundle,
                    sha256: sha256(b"fixture-ca-bundle"),
                }),
                redirect_policy: ProductionFetchRedirectPolicy::DenyUnlistedOrigin,
            },
            attestation: ProductionAttestationPolicy {
                allowed_executors: vec!["fixture-executor".into()],
                trusted_signers: vec![TrustedSigner {
                    id: "fixture-signer".into(),
                    algorithm: "ed25519".into(),
                    public_key: root.join("not-read-signer-key"),
                    sha256: sha256(b"unused-signer-key"),
                }],
                trusted_reviewer_policies: Vec::new(),
                signing_helper: SigningHelper {
                    signer_id: "fixture-signer".into(),
                    path: root.join("not-run-signing-helper"),
                    sha256: sha256(b"unused-signing-helper"),
                },
            },
            toolchain: ProductionToolchain {
                cargo: ProductionToolIdentity {
                    path: cargo,
                    sha256: sha256(&cargo_bytes),
                    version: "cargo 1.97.1 (fixture)".into(),
                },
                rustc: ProductionToolIdentity {
                    path: rustc,
                    sha256: sha256(b"rustc-fixture"),
                    version: "rustc 1.97.1 (fixture)".into(),
                },
                sysroot: ProductionTreeIdentity {
                    path: sysroot,
                    tree_digest: tree_digest("libcore.rlib", b"sysroot-fixture"),
                },
            },
            read_inputs: vec![
                ProductionReadInput {
                    id: "target-sdk".into(),
                    path: selected_read_input.clone(),
                    tree_digest: tree_digest("sdk.h", b"sdk-fixture"),
                },
                ProductionReadInput {
                    id: "unused-sdk".into(),
                    path: root.join("does-not-exist-unused-sdk"),
                    tree_digest: "1".repeat(64),
                },
            ],
            executables: vec![
                ProductionExecutable {
                    id: "target-linker".into(),
                    path: selected_executable.clone(),
                    sha256: sha256(b"target-cc-fixture"),
                    version: "target-cc fixture-v1".into(),
                },
                ProductionExecutable {
                    id: "unused-codegen".into(),
                    path: root.join("does-not-exist-unused-codegen"),
                    sha256: "2".repeat(64),
                    version: "unused fixture-v1".into(),
                },
            ],
            host_linker: None,
            target_linkers: vec![],
            environment: vec![ProductionEnvironment {
                id: "vendor-sdk-channel".into(),
                variable: "VENDOR_SDK_CHANNEL".into(),
                value: "stable".into(),
            }],
            derived_executable: DerivedExecutablePolicy {
                roots: vec!["target".into()],
                inherit_sandbox: true,
            },
        }
        .normalize()
        .unwrap();
        Fixture {
            temp,
            policy,
            requirements: BuildRequirements {
                executables: BTreeSet::from(["target-linker".into()]),
                read_inputs: BTreeSet::from(["target-sdk".into()]),
                environment: BTreeSet::from(["vendor-sdk-channel".into()]),
            },
            selected_executable,
            selected_read_input,
            side_effect_marker,
        }
    }

    fn build_preflight(
        fixture: &Fixture,
    ) -> Result<VerifiedProductionInputs, ProductionInputIdentityError> {
        preflight_inputs(build_request(
            &fixture.policy,
            &fixture.requirements,
            "aarch64-unknown-linux-gnu",
            Some(&"a".repeat(64)),
        )?)
    }

    #[test]
    fn host_linker_helper_preflight_roles_are_closed_and_schema_four() {
        let fixture = fixture();
        let mut policy = fixture.policy.policy().clone();
        policy.host_linker = Some(crate::ProductionHostLinker {
            executable: "target-linker".into(),
            helpers: vec!["unused-codegen".into()],
        });
        let policy = policy.normalize().unwrap();
        let requirements = BuildRequirements {
            executables: BTreeSet::from(["target-linker".into(), "unused-codegen".into()]),
            ..BuildRequirements::default()
        };
        let request = build_request(
            &policy,
            &requirements,
            "aarch64-unknown-linux-gnu",
            Some(&"a".repeat(64)),
        )
        .unwrap();
        assert_eq!(request.schema, 4);
        assert!(request.files.iter().any(|file| {
            file.id == "target-linker" && file.role == ProductionInputFileRole::HostLinker
        }));
        assert!(request.files.iter().any(|file| {
            file.id == "unused-codegen" && file.role == ProductionInputFileRole::HostLinkerHelper
        }));

        let mut old_schema = request.clone();
        old_schema.schema = 3;
        old_schema.digest = old_schema.recompute_digest().unwrap();
        assert!(matches!(
            old_schema.verify_self(),
            Err(ProductionInputIdentityError::UnsupportedSchema(3))
        ));

        let mut helper_without_linker = request;
        helper_without_linker
            .files
            .iter_mut()
            .find(|file| file.role == ProductionInputFileRole::HostLinker)
            .unwrap()
            .role = ProductionInputFileRole::BuildExecutable;
        helper_without_linker
            .files
            .sort_by(|left, right| file_key(left).cmp(&file_key(right)));
        helper_without_linker.digest = helper_without_linker.recompute_digest().unwrap();
        assert!(matches!(
            helper_without_linker.verify_self(),
            Err(ProductionInputIdentityError::InvalidRequest("build scope"))
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn target_linker_preflight_is_separate_descriptor_role() {
        let fixture = fixture();
        let target_linker = selected_tool("rustc");
        let mut policy = fixture.policy.policy().clone();
        policy.target_linkers = vec![ProductionTargetLinker {
            target: "wasm32-unknown-unknown".into(),
            id: "wasm-rust-lld".into(),
            path: target_linker.clone(),
            sha256: file_sha256(&target_linker),
            version: "LLD fixture-v1".into(),
        }];
        let policy = policy.normalize().unwrap();
        let request = build_request(
            &policy,
            &fixture.requirements,
            "wasm32-unknown-unknown",
            Some(&"a".repeat(64)),
        )
        .unwrap();
        let linker = request
            .files
            .iter()
            .find(|file| file.role == ProductionInputFileRole::TargetLinker)
            .unwrap();
        assert_eq!(linker.id, "wasm-rust-lld");
        assert_eq!(
            linker.version_probe.as_ref().unwrap().arguments,
            ["-flavor", "wasm", "--version"]
        );
        assert!(request.files.iter().all(|file| {
            file.role != ProductionInputFileRole::TargetLinker || file.id == "wasm-rust-lld"
        }));

        let inputs = preflight_inputs(request).unwrap();
        let mounts = crate::LinuxSandboxReadOnlyMount::production_inputs(&inputs).unwrap();
        let target_mount = mounts
            .iter()
            .find(|mount| mount.identity().id == "wasm-rust-lld")
            .unwrap()
            .identity();
        assert_eq!(
            target_mount.kind,
            crate::LinuxSandboxMountKind::ToolchainExecutable
        );
        assert_eq!(
            target_mount.logical_path,
            "/rust-agent/target-tools/wasm-rust-lld"
        );
        assert!(target_mount.executable);
        assert!(mounts.iter().any(|mount| {
            mount.identity().kind == crate::LinuxSandboxMountKind::ToolchainSysroot
                && !mount.identity().executable
        }));
    }

    fn successful_observation(
        verified: &VerifiedProductionInputs,
    ) -> ProductionInputIdentityObservation {
        let probes = verified
            .request()
            .expected_probes()
            .map(|file| {
                let probe = file.version_probe.as_ref().unwrap();
                ProductionVersionProbeResult {
                    role: file.role,
                    id: file.id.clone(),
                    executable_sha256: file.sha256.clone(),
                    arguments: probe.arguments.clone(),
                    exit_code: 0,
                    stdout: format!("{}\n", probe.expected_first_stdout_line),
                    stderr: String::new(),
                }
            })
            .collect();
        ProductionInputIdentityObservation::new(verified.request().digest().into(), probes).unwrap()
    }

    fn current_test_probe(
        arguments: &[&str],
    ) -> (VerifiedFile, ProductionInputFile, ProductionVersionProbe) {
        let path = std::env::current_exe().unwrap().canonicalize().unwrap();
        let identity = anchor_file_identity(&path).unwrap();
        let probe = ProductionVersionProbe {
            arguments: arguments
                .iter()
                .map(|argument| (*argument).into())
                .collect(),
            expected_first_stdout_line: "fixture".into(),
        };
        let file = ProductionInputFile {
            role: ProductionInputFileRole::BuildExecutable,
            id: "probe-fixture".into(),
            path,
            sha256: identity.sha256().into(),
            version_probe: Some(probe.clone()),
        };
        let verified = VerifiedFile {
            role: file.role,
            id: file.id.clone(),
            identity,
        };
        (verified, file, probe)
    }

    #[test]
    fn selected_build_inputs_are_descriptor_anchored_minimal_and_deterministic() {
        let fixture = fixture();
        let first = build_preflight(&fixture).unwrap();
        let second = build_preflight(&fixture).unwrap();
        assert_eq!(first.request(), second.request());
        assert_eq!(first.request().files.len(), 3);
        assert_eq!(first.request().trees.len(), 2);
        let json = serde_json::to_string(first.request()).unwrap();
        assert!(!json.contains("unused-codegen"));
        assert!(!json.contains("unused-sdk"));
        assert!(!json.contains("not-run-signing-helper"));
        assert_eq!(
            &ProductionInputIdentityRequest::from_json(&json).unwrap(),
            first.request()
        );
        first.verify_unchanged().unwrap();
        assert!(!fixture.side_effect_marker.exists());
    }

    #[test]
    fn digest_and_tree_drift_fail_before_any_probe_side_effect() {
        let file_drift = fixture();
        fs::write(&file_drift.selected_executable, b"wrong-target-cc").unwrap();
        assert!(matches!(
            build_preflight(&file_drift),
            Err(ProductionInputIdentityError::FileDigestMismatch { id, .. })
                if id == "target-linker"
        ));
        assert!(!file_drift.side_effect_marker.exists());

        let tree_drift = fixture();
        fs::write(tree_drift.selected_read_input.join("sdk.h"), b"wrong-sdk").unwrap();
        assert!(matches!(
            build_preflight(&tree_drift),
            Err(ProductionInputIdentityError::TreeDigestMismatch { id, .. })
                if id == "target-sdk"
        ));
        assert!(!tree_drift.side_effect_marker.exists());

        #[cfg(unix)]
        {
            let non_executable = fixture();
            fs::set_permissions(
                &non_executable.selected_executable,
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(matches!(
                build_preflight(&non_executable),
                Err(ProductionInputIdentityError::FileNotExecutable(id))
                    if id == "target-linker"
            ));
            assert!(!non_executable.side_effect_marker.exists());
        }
    }

    #[test]
    fn symlinks_and_post_preflight_replacement_fail_closed() {
        let post_preflight_drift = fixture();
        let verified = build_preflight(&post_preflight_drift).unwrap();
        let moved = post_preflight_drift.temp.path().join("target-cc-original");
        fs::rename(&post_preflight_drift.selected_executable, &moved).unwrap();
        fs::write(
            &post_preflight_drift.selected_executable,
            b"target-cc-fixture",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            fs::set_permissions(
                &post_preflight_drift.selected_executable,
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        assert!(matches!(
            verified.verify_unchanged(),
            Err(ProductionInputIdentityError::Snapshot(
                SnapshotMaterializationError::SourceChanged(_)
            ))
        ));

        #[cfg(unix)]
        {
            let permission_drift = fixture();
            let verified = build_preflight(&permission_drift).unwrap();
            fs::set_permissions(
                &permission_drift.selected_executable,
                fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(matches!(
                verified.verify_unchanged(),
                Err(ProductionInputIdentityError::Snapshot(
                    SnapshotMaterializationError::SourceChanged(_)
                ))
            ));
        }

        let tree_replacement = fixture();
        let verified = build_preflight(&tree_replacement).unwrap();
        let moved = tree_replacement.temp.path().join("target-sdk-original");
        fs::rename(&tree_replacement.selected_read_input, &moved).unwrap();
        fs::create_dir(&tree_replacement.selected_read_input).unwrap();
        fs::write(
            tree_replacement.selected_read_input.join("sdk.h"),
            b"sdk-fixture",
        )
        .unwrap();
        assert!(matches!(
            verified.verify_unchanged(),
            Err(ProductionInputIdentityError::Snapshot(
                SnapshotMaterializationError::SourceChanged(_)
            ))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let symlink_fixture = fixture();
            let target = symlink_fixture.temp.path().join("target-cc-real");
            fs::write(&target, b"target-cc-fixture").unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
            fs::remove_file(&symlink_fixture.selected_executable).unwrap();
            symlink(&target, &symlink_fixture.selected_executable).unwrap();
            assert!(matches!(
                build_preflight(&symlink_fixture),
                Err(ProductionInputIdentityError::Snapshot(
                    SnapshotMaterializationError::InvalidConcretePath(_)
                ))
            ));
        }
    }

    #[test]
    fn exact_probe_observation_is_closed_bounded_and_request_bound() {
        let fixture = fixture();
        let verified = build_preflight(&fixture).unwrap();
        let observation = successful_observation(&verified);
        let validated = verified.validate_probe_observation(&observation).unwrap();
        assert_eq!(validated.request_digest(), verified.request().digest());
        assert_eq!(validated.observation_digest(), observation.digest());
        let json = serde_json::to_string(&observation).unwrap();
        assert_eq!(
            ProductionInputIdentityObservation::from_json(&json).unwrap(),
            observation
        );
        let unknown = json.replacen("\"schema\":3", "\"schema\":3,\"ambient\":true", 1);
        assert!(matches!(
            ProductionInputIdentityObservation::from_json(&unknown),
            Err(ProductionInputIdentityError::Json(_))
        ));

        let mut wrong_arguments = observation.clone();
        wrong_arguments.probes[0].arguments.push("--verbose".into());
        wrong_arguments.digest = wrong_arguments.recompute_digest().unwrap();
        assert!(matches!(
            verified.validate_probe_observation(&wrong_arguments),
            Err(ProductionInputIdentityError::ObservationRequestMismatch)
        ));

        let mut wrong_version = observation.clone();
        wrong_version.probes[0].stdout = "cargo 1.97.2\n".into();
        wrong_version.digest = wrong_version.recompute_digest().unwrap();
        assert!(matches!(
            verified.validate_probe_observation(&wrong_version),
            Err(ProductionInputIdentityError::VersionProbeFailed(_))
        ));

        let mut failed = observation.clone();
        failed.probes[0].exit_code = 1;
        failed.digest = failed.recompute_digest().unwrap();
        assert!(matches!(
            verified.validate_probe_observation(&failed),
            Err(ProductionInputIdentityError::VersionProbeFailed(_))
        ));

        let mut oversized = observation;
        oversized.probes[0].stdout = "x".repeat(MAX_VERSION_PROBE_OUTPUT_BYTES + 1);
        oversized.digest = oversized.recompute_digest().unwrap();
        assert!(matches!(
            verified.validate_probe_observation(&oversized),
            Err(ProductionInputIdentityError::InvalidObservation(
                "probe result"
            ))
        ));
    }

    #[test]
    fn fetch_scopes_include_only_their_exact_identity_surface() {
        let fixture = fixture();
        let networked =
            preflight_production_fetch_inputs(&fixture.policy, CargoFetchMode::Networked).unwrap();
        assert_eq!(networked.request().files.len(), 4);
        assert_eq!(networked.request().trees.len(), 1);
        assert_eq!(
            networked.request().trees[0].role,
            ProductionInputTreeRole::RustSysroot
        );
        assert!(
            networked
                .request()
                .files
                .iter()
                .any(|file| { file.role == ProductionInputFileRole::CredentialHelper })
        );
        assert!(networked.request().files.iter().any(|file| {
            file.role == ProductionInputFileRole::FetchTlsCaBundle && file.version_probe.is_none()
        }));

        let preprovisioned =
            preflight_production_fetch_inputs(&fixture.policy, CargoFetchMode::Preprovisioned)
                .unwrap();
        assert_eq!(preprovisioned.request().files.len(), 2);
        assert_eq!(preprovisioned.request().trees.len(), 1);
        assert!(preprovisioned.request().files.iter().all(|file| {
            !matches!(
                file.role,
                ProductionInputFileRole::CredentialHelper
                    | ProductionInputFileRole::FetchTlsCaBundle
            )
        }));
    }

    #[test]
    fn custom_target_probe_is_logical_mount_bound_and_local_execution_fails_closed() {
        let digest = "a".repeat(64);
        let logical_path = "/rust-agent/closure/host/targets/aarch64-fixture-none.json".to_owned();
        let mut request = ProductionTargetFactsProbeRequest {
            schema: 1,
            production_input_request_digest: digest.clone(),
            host_build_input_closure_digest: digest.clone(),
            build_execution_policy_digest: digest.clone(),
            rustc_sha256: digest.clone(),
            target: "aarch64-fixture-none".into(),
            custom_target_spec_digest: Some(digest.clone()),
            custom_target_spec_logical_path: Some(logical_path.clone()),
            arguments: vec![
                "--print".into(),
                "cfg".into(),
                "--target".into(),
                logical_path,
                "-Zunstable-options".into(),
            ],
            environment_cleared: true,
            working_directory: "/".into(),
            expected_target_facts_digest: digest,
            digest: String::new(),
        };
        request.digest = request.recompute_digest().unwrap();
        request.verify_self().unwrap();
        assert!(matches!(
            require_local_target_probe_support(&request),
            Err(ProductionInputIdentityError::CustomTargetProbeRequiresMountedView)
        ));

        let mut ambient_path = request;
        ambient_path.custom_target_spec_logical_path = Some("/tmp/target.json".into());
        ambient_path.arguments[3] = "/tmp/target.json".into();
        ambient_path.digest = ambient_path.recompute_digest().unwrap();
        assert!(matches!(
            ambient_path.verify_self(),
            Err(ProductionInputIdentityError::TargetFactsProbeRequestMismatch)
        ));
    }

    #[test]
    fn local_runner_executes_real_pinned_tools_through_retained_descriptors() {
        let fixture = fixture();
        let cargo = selected_tool("cargo");
        let rustc = selected_tool("rustc");
        let mut policy = fixture.policy.policy().clone();
        policy.fetch.credential_helper = None;
        policy.toolchain.cargo = ProductionToolIdentity {
            sha256: file_sha256(&cargo),
            version: version_line(&cargo, &["-V"]),
            path: cargo,
        };
        policy.toolchain.rustc = ProductionToolIdentity {
            sha256: file_sha256(&rustc),
            version: version_line(&rustc, &["-vV"]),
            path: rustc,
        };
        let policy = policy.normalize().unwrap();
        let verified =
            preflight_production_fetch_inputs(&policy, CargoFetchMode::Preprovisioned).unwrap();
        let observation = verified.run_local_version_probes().unwrap();
        assert_eq!(observation.probes.len(), 2);
        assert_eq!(observation.request_digest, verified.request().digest());
        verified.validate_probe_observation(&observation).unwrap();
    }

    #[test]
    fn local_runner_clears_environment_and_rejects_failure_and_non_elf_inputs() {
        let arguments = [
            "--ignored",
            "--exact",
            "production_inputs::tests::probe_child_environment",
            "--nocapture",
            "--test-threads=1",
        ];
        let (verified, file, probe) = current_test_probe(&arguments);
        let result =
            run_descriptor_probe(&verified, &file, &probe, Duration::from_secs(5)).unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("probe-child-environment-ok"));

        let arguments = [
            "--ignored",
            "--exact",
            "production_inputs::tests::probe_child_failure",
            "--nocapture",
            "--test-threads=1",
        ];
        let (verified, file, probe) = current_test_probe(&arguments);
        let result =
            run_descriptor_probe(&verified, &file, &probe, Duration::from_secs(5)).unwrap();
        assert_ne!(result.exit_code, 0);

        let fixture = fixture();
        let verified =
            preflight_production_fetch_inputs(&fixture.policy, CargoFetchMode::Preprovisioned)
                .unwrap();
        assert!(matches!(
            verified.run_local_version_probes(),
            Err(ProductionInputIdentityError::UnsupportedExecutableFormat(id))
                if id == "cargo"
        ));
        assert!(!fixture.side_effect_marker.exists());
    }

    #[test]
    fn local_runner_bounds_output_encoding_deadline_and_descendant_lifetime() {
        let oversized_arguments = [
            "--ignored",
            "--exact",
            "production_inputs::tests::probe_child_oversized",
            "--nocapture",
            "--test-threads=1",
        ];
        let (verified, file, probe) = current_test_probe(&oversized_arguments);
        assert!(matches!(
            run_descriptor_probe(&verified, &file, &probe, Duration::from_secs(5)),
            Err(ProductionInputIdentityError::ProbeOutputTooLarge {
                stream: "stdout",
                ..
            })
        ));

        let invalid_utf8_arguments = [
            "--ignored",
            "--exact",
            "production_inputs::tests::probe_child_invalid_utf8",
            "--nocapture",
            "--test-threads=1",
        ];
        let (verified, file, probe) = current_test_probe(&invalid_utf8_arguments);
        assert!(matches!(
            run_descriptor_probe(&verified, &file, &probe, Duration::from_secs(5)),
            Err(ProductionInputIdentityError::InvalidProbeOutputEncoding {
                stream: "stdout",
                ..
            })
        ));

        for child in ["probe_child_timeout", "probe_child_pipe_descendant"] {
            let exact = format!("production_inputs::tests::{child}");
            let arguments = [
                "--ignored",
                "--exact",
                exact.as_str(),
                "--nocapture",
                "--test-threads=1",
            ];
            let (verified, file, probe) = current_test_probe(&arguments);
            let started = Instant::now();
            assert!(matches!(
                run_descriptor_probe(&verified, &file, &probe, Duration::from_millis(100)),
                Err(ProductionInputIdentityError::ProbeTimedOut { .. })
            ));
            assert!(started.elapsed() < Duration::from_secs(2));
        }
    }

    #[test]
    #[ignore = "descriptor-runner child fixture"]
    fn probe_child_environment() {
        assert!(std::env::var_os("HOME").is_none());
        assert_eq!(std::env::current_dir().unwrap(), Path::new("/"));
        println!("probe-child-environment-ok");
    }

    #[test]
    #[ignore = "descriptor-runner child fixture"]
    fn probe_child_failure() {
        panic!("intentional descriptor-runner child failure");
    }

    #[test]
    #[ignore = "descriptor-runner child fixture"]
    fn probe_child_oversized() {
        println!("{}", "x".repeat(MAX_VERSION_PROBE_OUTPUT_BYTES + 1));
    }

    #[test]
    #[ignore = "descriptor-runner child fixture"]
    fn probe_child_invalid_utf8() {
        std::io::stdout().write_all(&[0xff]).unwrap();
    }

    #[test]
    #[ignore = "descriptor-runner child fixture"]
    fn probe_child_timeout() {
        thread::sleep(Duration::from_secs(5));
    }

    #[test]
    #[ignore = "descriptor-runner child fixture"]
    #[allow(clippy::zombie_processes)]
    fn probe_child_pipe_descendant() {
        // Deliberately leave a live child holding the inherited output pipes;
        // the parent test proves the probe runner kills the whole process group.
        Command::new("/bin/sleep").arg("5").spawn().unwrap();
    }
}
