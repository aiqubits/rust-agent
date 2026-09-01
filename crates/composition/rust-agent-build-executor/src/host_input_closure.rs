use std::collections::{BTreeMap, BTreeSet};

use rust_agent_composition::{canonical, metadata::BuildRequirements};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    BuildEnforcementContext, CargoPackageIdentity, CargoUnitGraphError, HostCargoUnitGraph,
    NormalizedProductionBuildPolicy, ProductionBuildPolicyError,
};

const CLOSURE_LOGICAL_ROOT: &str = "/rust-agent/closure/";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostBuildInputClosure {
    pub schema: u32,
    #[serde(rename = "composition-hash")]
    pub composition_hash: String,
    #[serde(rename = "host-dependency-alias")]
    pub host_dependency_alias: String,
    #[serde(rename = "generated-package-name")]
    pub generated_package_name: String,
    pub items: Vec<HostBuildClosureItem>,
    #[serde(rename = "standalone-unit-graph")]
    pub standalone_unit_graph: HostCargoUnitGraph,
    #[serde(rename = "final-unit-graph")]
    pub final_unit_graph: HostCargoUnitGraph,
    #[serde(rename = "build-context")]
    pub build_context: BuildEnforcementContext,
    #[serde(rename = "build-requirements")]
    pub build_requirements: BuildRequirements,
    #[serde(rename = "build-execution-policy-digest")]
    pub build_execution_policy_digest: String,
    #[serde(rename = "build-enforcement-identity-digest")]
    pub build_enforcement_identity_digest: String,
    #[serde(rename = "host-feature-policy")]
    pub host_feature_policy: HostFeaturePolicyClosure,
    #[serde(rename = "unit-feature-delta-digest")]
    pub unit_feature_delta_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostBuildClosureItem {
    pub role: HostBuildClosureItemRole,
    pub id: String,
    #[serde(rename = "logical-path")]
    pub logical_path: String,
    #[serde(rename = "metadata-contract")]
    pub metadata_contract: CanonicalSnapshotMetadataContract,
    pub content: HostBuildClosureContent,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CanonicalSnapshotMetadataContract {
    ReadOnlyEpochV1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostBuildClosureItemRole {
    HostWorkspaceManifest,
    HostRootManifest,
    HostMemberManifest,
    HostCargoLock,
    CargoConfig,
    HostPackageTree,
    PathPackageTree,
    EmittedCompositionTree,
    CargoResolutionRecord,
    TargetFactsRecord,
    CustomTargetSpec,
    RustcSettingsRecord,
    ArtifactSelectorRecord,
    FeatureSemanticsEvidence,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HostBuildClosureContent {
    File {
        sha256: String,
    },
    SnapshotTree {
        #[serde(rename = "tree-digest")]
        tree_digest: String,
    },
    CanonicalRecord {
        digest: String,
    },
    SignedEvidence {
        #[serde(rename = "bytes-digest")]
        bytes_digest: String,
        #[serde(rename = "reviewer-policy")]
        reviewer_policy: String,
        #[serde(rename = "reviewer-policy-digest")]
        reviewer_policy_digest: String,
        #[serde(rename = "signature-set-digest")]
        signature_set_digest: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum HostFeaturePolicyClosure {
    None,
    Policy {
        digest: String,
        #[serde(rename = "evidence-ids", default)]
        evidence_ids: Vec<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedHostBuildClosureItem {
    pub role: HostBuildClosureItemRole,
    pub id: String,
    #[serde(rename = "logical-path")]
    pub logical_path: String,
    #[serde(rename = "metadata-contract")]
    pub metadata_contract: CanonicalSnapshotMetadataContract,
    pub content: HostBuildClosureContent,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalizedHostBuildInputClosure {
    items: Vec<NormalizedHostBuildClosureItem>,
    generated_package_name: String,
    build_context: BuildEnforcementContext,
    final_unit_packages: BTreeSet<CargoPackageIdentity>,
    standalone_unit_graph_digest: String,
    final_unit_graph_digest: String,
    build_execution_policy_digest: String,
    build_enforcement_identity_digest: String,
    host_feature_policy_digest: Option<String>,
    unit_feature_delta_digest: String,
    digest: String,
}

#[derive(Serialize)]
struct ClosureProjection<'a> {
    schema: u32,
    composition_hash: &'a str,
    host_dependency_alias: &'a str,
    generated_package_name: &'a str,
    items: &'a [NormalizedHostBuildClosureItem],
    standalone_unit_graph_digest: &'a str,
    final_unit_graph_digest: &'a str,
    build_context: &'a BuildEnforcementContext,
    build_requirements: &'a BuildRequirements,
    build_execution_policy_digest: &'a str,
    build_enforcement_identity_digest: &'a str,
    host_feature_policy: &'a HostFeaturePolicyClosure,
    unit_feature_delta_digest: &'a str,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostBuildClosureStage {
    Pre,
    BuildHost,
    Post,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DevelopmentHostClosureStageReceipt {
    pub schema: u32,
    pub stage: HostBuildClosureStage,
    pub deployable: bool,
    #[serde(rename = "host-build-input-closure-digest")]
    pub host_build_input_closure_digest: String,
    #[serde(rename = "build-execution-policy-digest")]
    pub build_execution_policy_digest: String,
    #[serde(rename = "build-enforcement-identity-digest")]
    pub build_enforcement_identity_digest: String,
    #[serde(rename = "host-feature-policy-digest")]
    pub host_feature_policy_digest: Option<String>,
    #[serde(rename = "standalone-unit-graph-digest")]
    pub standalone_unit_graph_digest: String,
    #[serde(rename = "final-unit-graph-digest")]
    pub final_unit_graph_digest: String,
    #[serde(rename = "unit-feature-delta-digest")]
    pub unit_feature_delta_digest: String,
    pub digest: String,
}

#[derive(Debug, Error)]
pub enum HostBuildInputClosureError {
    #[error("HostBuildInputClosure JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported HostBuildInputClosure schema {0}; expected 1")]
    UnsupportedSchema(u32),
    #[error("invalid HostBuildInputClosure field `{0}`")]
    InvalidField(&'static str),
    #[error("invalid HostBuildInputClosure item id `{0}`")]
    InvalidItemId(String),
    #[error("closure item logical path is not canonical and below {CLOSURE_LOGICAL_ROOT}: {0}")]
    InvalidLogicalPath(String),
    #[error("duplicate closure item id or logical path: {0}")]
    DuplicateItem(String),
    #[error("closure item `{id}` has content incompatible with role {role:?}")]
    ItemContentMismatch {
        id: String,
        role: HostBuildClosureItemRole,
    },
    #[error("closure item `{0}` contains an invalid canonical digest")]
    InvalidItemDigest(String),
    #[error("closure role {role:?} has invalid cardinality {actual}; expected {expected}")]
    InvalidRoleCardinality {
        role: HostBuildClosureItemRole,
        actual: usize,
        expected: &'static str,
    },
    #[error("closure item `{item}` does not match build context field `{field}`")]
    ContextItemMismatch { item: String, field: &'static str },
    #[error(
        "standalone/final unit graphs do not share the exact planner/build/target/profile context"
    )]
    UnitGraphContextMismatch,
    #[error("unit graph context does not match the build enforcement context")]
    BuildContextMismatch,
    #[error("unit graph planner does not match the pinned production policy toolchain")]
    PlannerToolchainMismatch,
    #[error("build execution policy digest does not match the normalized policy")]
    BuildPolicyDigestMismatch,
    #[error("build enforcement identity digest does not match policy, requirements and context")]
    BuildEnforcementIdentityMismatch,
    #[error("Host feature policy/evidence closure is invalid")]
    HostFeaturePolicyEvidenceMismatch,
    #[error("feature-semantics evidence `{0}` does not match a trusted reviewer policy")]
    FeatureEvidenceTrustMismatch(String),
    #[error("Host Cargo unit graph is invalid: {0}")]
    UnitGraph(#[from] CargoUnitGraphError),
    #[error("production build policy verification failed: {0}")]
    ProductionPolicy(#[from] ProductionBuildPolicyError),
    #[error("unsupported development Host closure receipt schema {0}; expected 1")]
    UnsupportedReceiptSchema(u32),
    #[error("development Host closure receipt cannot be deployable")]
    DevelopmentReceiptDeployable,
    #[error("development Host closure receipt digest is invalid")]
    ReceiptDigestMismatch,
    #[error("development Host closure receipts have an invalid pre/build-host/post stage order")]
    ReceiptStageMismatch,
    #[error("pre/build-host/post Host closure receipt inputs differ")]
    ReceiptInputMismatch,
    #[error("canonical HostBuildInputClosure encoding failed: {0}")]
    Canonical(#[from] canonical::CanonicalError),
}

impl HostBuildInputClosure {
    pub fn from_json(input: &str) -> Result<Self, HostBuildInputClosureError> {
        Ok(serde_json::from_str(input)?)
    }

    pub fn normalize(
        &self,
        policy: &NormalizedProductionBuildPolicy,
    ) -> Result<NormalizedHostBuildInputClosure, HostBuildInputClosureError> {
        if self.schema != 1 {
            return Err(HostBuildInputClosureError::UnsupportedSchema(self.schema));
        }
        if !is_digest(&self.composition_hash) {
            return Err(HostBuildInputClosureError::InvalidField("composition-hash"));
        }
        if !is_cargo_name(&self.host_dependency_alias) {
            return Err(HostBuildInputClosureError::InvalidField(
                "host-dependency-alias",
            ));
        }
        if !is_cargo_name(&self.generated_package_name) {
            return Err(HostBuildInputClosureError::InvalidField(
                "generated-package-name",
            ));
        }
        for (field, digest) in [
            (
                "build-execution-policy-digest",
                self.build_execution_policy_digest.as_str(),
            ),
            (
                "build-enforcement-identity-digest",
                self.build_enforcement_identity_digest.as_str(),
            ),
            (
                "unit-feature-delta-digest",
                self.unit_feature_delta_digest.as_str(),
            ),
        ] {
            if !is_digest(digest) {
                return Err(HostBuildInputClosureError::InvalidField(field));
            }
        }
        if self.build_execution_policy_digest != policy.full_digest() {
            return Err(HostBuildInputClosureError::BuildPolicyDigestMismatch);
        }
        self.build_context.validate()?;
        let expected_enforcement =
            policy.enforcement_identity_digest(&self.build_requirements, &self.build_context)?;
        if self.build_enforcement_identity_digest != expected_enforcement {
            return Err(HostBuildInputClosureError::BuildEnforcementIdentityMismatch);
        }

        let standalone = self.standalone_unit_graph.normalize()?;
        let final_graph = self.final_unit_graph.normalize()?;
        if standalone.planner() != final_graph.planner()
            || standalone.build_triple() != final_graph.build_triple()
            || standalone.composition_target() != final_graph.composition_target()
            || standalone.profile() != final_graph.profile()
        {
            return Err(HostBuildInputClosureError::UnitGraphContextMismatch);
        }
        if standalone.build_triple() != self.build_context.build_triple
            || standalone.composition_target() != self.build_context.target
            || standalone.profile() != self.build_context.profile
        {
            return Err(HostBuildInputClosureError::BuildContextMismatch);
        }
        let toolchain = &policy.policy().toolchain;
        let planner = standalone.planner();
        if planner.cargo_version != declared_tool_version(&toolchain.cargo.version)
            || planner.cargo_digest != toolchain.cargo.sha256
            || planner.rustc_version != declared_tool_version(&toolchain.rustc.version)
            || planner.rustc_digest != toolchain.rustc.sha256
        {
            return Err(HostBuildInputClosureError::PlannerToolchainMismatch);
        }

        let items = normalize_items(&self.items, &self.build_context, policy)?;
        let host_feature_policy = normalize_host_feature_policy(&self.host_feature_policy, &items)?;
        let host_feature_policy_digest = match &host_feature_policy {
            HostFeaturePolicyClosure::None => None,
            HostFeaturePolicyClosure::Policy { digest, .. } => Some(digest.clone()),
        };

        let standalone_unit_graph_digest = standalone.digest().to_owned();
        let final_unit_graph_digest = final_graph.digest().to_owned();
        let final_unit_packages = final_graph
            .nodes()
            .keys()
            .map(|selector| selector.package.clone())
            .collect();
        let projection = ClosureProjection {
            schema: 1,
            composition_hash: &self.composition_hash,
            host_dependency_alias: &self.host_dependency_alias,
            generated_package_name: &self.generated_package_name,
            items: &items,
            standalone_unit_graph_digest: &standalone_unit_graph_digest,
            final_unit_graph_digest: &final_unit_graph_digest,
            build_context: &self.build_context,
            build_requirements: &self.build_requirements,
            build_execution_policy_digest: &self.build_execution_policy_digest,
            build_enforcement_identity_digest: &self.build_enforcement_identity_digest,
            host_feature_policy: &host_feature_policy,
            unit_feature_delta_digest: &self.unit_feature_delta_digest,
        };
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-host-build-input-closure-v1\0",
            &projection,
        )?);
        Ok(NormalizedHostBuildInputClosure {
            items,
            generated_package_name: self.generated_package_name.clone(),
            build_context: self.build_context.clone(),
            final_unit_packages,
            standalone_unit_graph_digest,
            final_unit_graph_digest,
            build_execution_policy_digest: self.build_execution_policy_digest.clone(),
            build_enforcement_identity_digest: self.build_enforcement_identity_digest.clone(),
            host_feature_policy_digest,
            unit_feature_delta_digest: self.unit_feature_delta_digest.clone(),
            digest,
        })
    }
}

impl NormalizedHostBuildInputClosure {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn items(&self) -> &[NormalizedHostBuildClosureItem] {
        &self.items
    }

    pub fn generated_package_name(&self) -> &str {
        &self.generated_package_name
    }

    pub fn build_context(&self) -> &BuildEnforcementContext {
        &self.build_context
    }

    pub fn final_unit_packages(&self) -> &BTreeSet<CargoPackageIdentity> {
        &self.final_unit_packages
    }

    pub fn standalone_unit_graph_digest(&self) -> &str {
        &self.standalone_unit_graph_digest
    }

    pub fn final_unit_graph_digest(&self) -> &str {
        &self.final_unit_graph_digest
    }

    pub fn build_execution_policy_digest(&self) -> &str {
        &self.build_execution_policy_digest
    }

    pub fn development_stage_receipt(
        &self,
        stage: HostBuildClosureStage,
    ) -> Result<DevelopmentHostClosureStageReceipt, HostBuildInputClosureError> {
        let mut receipt = DevelopmentHostClosureStageReceipt {
            schema: 1,
            stage,
            deployable: false,
            host_build_input_closure_digest: self.digest.clone(),
            build_execution_policy_digest: self.build_execution_policy_digest.clone(),
            build_enforcement_identity_digest: self.build_enforcement_identity_digest.clone(),
            host_feature_policy_digest: self.host_feature_policy_digest.clone(),
            standalone_unit_graph_digest: self.standalone_unit_graph_digest.clone(),
            final_unit_graph_digest: self.final_unit_graph_digest.clone(),
            unit_feature_delta_digest: self.unit_feature_delta_digest.clone(),
            digest: String::new(),
        };
        receipt.digest = receipt.recompute_digest()?;
        Ok(receipt)
    }
}

impl DevelopmentHostClosureStageReceipt {
    fn recompute_digest(&self) -> Result<String, HostBuildInputClosureError> {
        Ok(hex::encode(canonical::domain_hash(
            b"rust-agent-development-host-closure-stage-receipt-v1\0",
            &(
                self.schema,
                self.stage,
                self.deployable,
                &self.host_build_input_closure_digest,
                &self.build_execution_policy_digest,
                &self.build_enforcement_identity_digest,
                &self.host_feature_policy_digest,
                &self.standalone_unit_graph_digest,
                &self.final_unit_graph_digest,
                &self.unit_feature_delta_digest,
            ),
        )?))
    }

    pub fn verify(&self) -> Result<(), HostBuildInputClosureError> {
        if self.schema != 1 {
            return Err(HostBuildInputClosureError::UnsupportedReceiptSchema(
                self.schema,
            ));
        }
        if self.deployable {
            return Err(HostBuildInputClosureError::DevelopmentReceiptDeployable);
        }
        if [
            self.host_build_input_closure_digest.as_str(),
            self.build_execution_policy_digest.as_str(),
            self.build_enforcement_identity_digest.as_str(),
            self.standalone_unit_graph_digest.as_str(),
            self.final_unit_graph_digest.as_str(),
            self.unit_feature_delta_digest.as_str(),
        ]
        .into_iter()
        .any(|digest| !is_digest(digest))
            || self
                .host_feature_policy_digest
                .as_deref()
                .is_some_and(|digest| !is_digest(digest))
        {
            return Err(HostBuildInputClosureError::ReceiptDigestMismatch);
        }
        if self.digest != self.recompute_digest()? {
            return Err(HostBuildInputClosureError::ReceiptDigestMismatch);
        }
        Ok(())
    }
}

pub fn verify_development_host_closure_stage_chain(
    pre: &DevelopmentHostClosureStageReceipt,
    build_host: &DevelopmentHostClosureStageReceipt,
    post: &DevelopmentHostClosureStageReceipt,
) -> Result<(), HostBuildInputClosureError> {
    pre.verify()?;
    build_host.verify()?;
    post.verify()?;
    if pre.stage != HostBuildClosureStage::Pre
        || build_host.stage != HostBuildClosureStage::BuildHost
        || post.stage != HostBuildClosureStage::Post
    {
        return Err(HostBuildInputClosureError::ReceiptStageMismatch);
    }
    let same_inputs = |left: &DevelopmentHostClosureStageReceipt,
                       right: &DevelopmentHostClosureStageReceipt| {
        left.host_build_input_closure_digest == right.host_build_input_closure_digest
            && left.build_execution_policy_digest == right.build_execution_policy_digest
            && left.build_enforcement_identity_digest == right.build_enforcement_identity_digest
            && left.host_feature_policy_digest == right.host_feature_policy_digest
            && left.standalone_unit_graph_digest == right.standalone_unit_graph_digest
            && left.final_unit_graph_digest == right.final_unit_graph_digest
            && left.unit_feature_delta_digest == right.unit_feature_delta_digest
    };
    if !same_inputs(pre, build_host) || !same_inputs(pre, post) {
        return Err(HostBuildInputClosureError::ReceiptInputMismatch);
    }
    Ok(())
}

fn normalize_items(
    raw_items: &[HostBuildClosureItem],
    context: &BuildEnforcementContext,
    policy: &NormalizedProductionBuildPolicy,
) -> Result<Vec<NormalizedHostBuildClosureItem>, HostBuildInputClosureError> {
    let mut ids = BTreeSet::new();
    let mut paths = BTreeSet::new();
    let mut counts = BTreeMap::<HostBuildClosureItemRole, usize>::new();
    let mut items = Vec::with_capacity(raw_items.len());
    for raw in raw_items {
        if !is_id(&raw.id) {
            return Err(HostBuildInputClosureError::InvalidItemId(raw.id.clone()));
        }
        if !is_logical_closure_path(&raw.logical_path) {
            return Err(HostBuildInputClosureError::InvalidLogicalPath(
                raw.logical_path.clone(),
            ));
        }
        if !ids.insert(raw.id.clone()) {
            return Err(HostBuildInputClosureError::DuplicateItem(raw.id.clone()));
        }
        if !paths.insert(raw.logical_path.clone()) {
            return Err(HostBuildInputClosureError::DuplicateItem(
                raw.logical_path.clone(),
            ));
        }
        if !role_accepts_content(raw.role, &raw.content) {
            return Err(HostBuildInputClosureError::ItemContentMismatch {
                id: raw.id.clone(),
                role: raw.role,
            });
        }
        if !content_has_valid_digests(&raw.content) {
            return Err(HostBuildInputClosureError::InvalidItemDigest(
                raw.id.clone(),
            ));
        }
        if let HostBuildClosureContent::SignedEvidence {
            reviewer_policy,
            reviewer_policy_digest,
            ..
        } = &raw.content
            && (!is_id(reviewer_policy)
                || policy.reviewer_policy_digest(reviewer_policy)?.as_deref()
                    != Some(reviewer_policy_digest))
        {
            return Err(HostBuildInputClosureError::FeatureEvidenceTrustMismatch(
                raw.id.clone(),
            ));
        }
        let digest = hex::encode(canonical::domain_hash(
            b"rust-agent-host-build-closure-item-v1\0",
            &(
                raw.role,
                &raw.id,
                &raw.logical_path,
                raw.metadata_contract,
                &raw.content,
            ),
        )?);
        *counts.entry(raw.role).or_default() += 1;
        items.push(NormalizedHostBuildClosureItem {
            role: raw.role,
            id: raw.id.clone(),
            logical_path: raw.logical_path.clone(),
            metadata_contract: raw.metadata_contract,
            content: raw.content.clone(),
            digest,
        });
    }
    items.sort_by(|left, right| {
        (&left.role, &left.id, &left.logical_path).cmp(&(
            &right.role,
            &right.id,
            &right.logical_path,
        ))
    });

    require_count(
        &counts,
        HostBuildClosureItemRole::HostWorkspaceManifest,
        0,
        1,
        "zero or one",
    )?;
    require_count(
        &counts,
        HostBuildClosureItemRole::HostRootManifest,
        1,
        1,
        "exactly one",
    )?;
    require_count(
        &counts,
        HostBuildClosureItemRole::HostCargoLock,
        1,
        1,
        "exactly one",
    )?;
    require_count(
        &counts,
        HostBuildClosureItemRole::CargoConfig,
        1,
        1,
        "exactly one",
    )?;
    require_count(
        &counts,
        HostBuildClosureItemRole::HostPackageTree,
        1,
        usize::MAX,
        "one or more",
    )?;
    require_count(
        &counts,
        HostBuildClosureItemRole::EmittedCompositionTree,
        1,
        1,
        "exactly one",
    )?;
    require_count(
        &counts,
        HostBuildClosureItemRole::CargoResolutionRecord,
        1,
        1,
        "exactly one",
    )?;
    require_count(
        &counts,
        HostBuildClosureItemRole::TargetFactsRecord,
        1,
        1,
        "exactly one",
    )?;
    require_count(
        &counts,
        HostBuildClosureItemRole::RustcSettingsRecord,
        1,
        1,
        "exactly one",
    )?;
    require_count(
        &counts,
        HostBuildClosureItemRole::ArtifactSelectorRecord,
        1,
        1,
        "exactly one",
    )?;
    let expected_custom_spec = usize::from(context.custom_target_spec_digest.is_some());
    require_count(
        &counts,
        HostBuildClosureItemRole::CustomTargetSpec,
        expected_custom_spec,
        expected_custom_spec,
        if expected_custom_spec == 0 {
            "none"
        } else {
            "exactly one"
        },
    )?;

    verify_context_item(
        &items,
        HostBuildClosureItemRole::CargoConfig,
        &context.cargo_config_digest,
        "cargo-config-digest",
    )?;
    verify_context_item(
        &items,
        HostBuildClosureItemRole::CargoResolutionRecord,
        &context.cargo_resolution_digest,
        "cargo-resolution-digest",
    )?;
    verify_context_item(
        &items,
        HostBuildClosureItemRole::TargetFactsRecord,
        &context.target_facts_digest,
        "target-facts-digest",
    )?;
    verify_context_item(
        &items,
        HostBuildClosureItemRole::RustcSettingsRecord,
        &context.rustc_settings_digest,
        "rustc-settings-digest",
    )?;
    verify_context_item(
        &items,
        HostBuildClosureItemRole::ArtifactSelectorRecord,
        &context.artifact_selector.digest()?,
        "artifact-selector-digest",
    )?;
    if let Some(digest) = &context.custom_target_spec_digest {
        verify_context_item(
            &items,
            HostBuildClosureItemRole::CustomTargetSpec,
            digest,
            "custom-target-spec-digest",
        )?;
    }
    Ok(items)
}

fn normalize_host_feature_policy(
    raw: &HostFeaturePolicyClosure,
    items: &[NormalizedHostBuildClosureItem],
) -> Result<HostFeaturePolicyClosure, HostBuildInputClosureError> {
    let actual_evidence: BTreeSet<_> = items
        .iter()
        .filter(|item| item.role == HostBuildClosureItemRole::FeatureSemanticsEvidence)
        .map(|item| item.id.clone())
        .collect();
    match raw {
        HostFeaturePolicyClosure::None if actual_evidence.is_empty() => {
            Ok(HostFeaturePolicyClosure::None)
        }
        HostFeaturePolicyClosure::None => {
            Err(HostBuildInputClosureError::HostFeaturePolicyEvidenceMismatch)
        }
        HostFeaturePolicyClosure::Policy {
            digest,
            evidence_ids,
        } => {
            if !is_digest(digest) {
                return Err(HostBuildInputClosureError::InvalidField(
                    "host-feature-policy-digest",
                ));
            }
            let evidence: BTreeSet<_> = evidence_ids.iter().cloned().collect();
            if evidence.len() != evidence_ids.len()
                || evidence.iter().any(|id| !is_id(id))
                || evidence != actual_evidence
            {
                return Err(HostBuildInputClosureError::HostFeaturePolicyEvidenceMismatch);
            }
            Ok(HostFeaturePolicyClosure::Policy {
                digest: digest.clone(),
                evidence_ids: evidence.into_iter().collect(),
            })
        }
    }
}

fn verify_context_item(
    items: &[NormalizedHostBuildClosureItem],
    role: HostBuildClosureItemRole,
    expected_digest: &str,
    field: &'static str,
) -> Result<(), HostBuildInputClosureError> {
    let item = items
        .iter()
        .find(|item| item.role == role)
        .expect("required context item cardinality was checked");
    if content_primary_digest(&item.content) == expected_digest {
        Ok(())
    } else {
        Err(HostBuildInputClosureError::ContextItemMismatch {
            item: item.id.clone(),
            field,
        })
    }
}

fn require_count(
    counts: &BTreeMap<HostBuildClosureItemRole, usize>,
    role: HostBuildClosureItemRole,
    minimum: usize,
    maximum: usize,
    expected: &'static str,
) -> Result<(), HostBuildInputClosureError> {
    let actual = counts.get(&role).copied().unwrap_or(0);
    if (minimum..=maximum).contains(&actual) {
        Ok(())
    } else {
        Err(HostBuildInputClosureError::InvalidRoleCardinality {
            role,
            actual,
            expected,
        })
    }
}

fn role_accepts_content(role: HostBuildClosureItemRole, content: &HostBuildClosureContent) -> bool {
    matches!(
        (role, content),
        (
            HostBuildClosureItemRole::HostWorkspaceManifest
                | HostBuildClosureItemRole::HostRootManifest
                | HostBuildClosureItemRole::HostMemberManifest
                | HostBuildClosureItemRole::HostCargoLock
                | HostBuildClosureItemRole::CargoConfig
                | HostBuildClosureItemRole::CustomTargetSpec,
            HostBuildClosureContent::File { .. }
        ) | (
            HostBuildClosureItemRole::HostPackageTree
                | HostBuildClosureItemRole::PathPackageTree
                | HostBuildClosureItemRole::EmittedCompositionTree,
            HostBuildClosureContent::SnapshotTree { .. }
        ) | (
            HostBuildClosureItemRole::CargoResolutionRecord
                | HostBuildClosureItemRole::TargetFactsRecord
                | HostBuildClosureItemRole::RustcSettingsRecord
                | HostBuildClosureItemRole::ArtifactSelectorRecord,
            HostBuildClosureContent::CanonicalRecord { .. }
        ) | (
            HostBuildClosureItemRole::FeatureSemanticsEvidence,
            HostBuildClosureContent::SignedEvidence { .. }
        )
    )
}

fn content_has_valid_digests(content: &HostBuildClosureContent) -> bool {
    match content {
        HostBuildClosureContent::File { sha256 } => is_digest(sha256),
        HostBuildClosureContent::SnapshotTree { tree_digest } => is_digest(tree_digest),
        HostBuildClosureContent::CanonicalRecord { digest } => is_digest(digest),
        HostBuildClosureContent::SignedEvidence {
            bytes_digest,
            reviewer_policy: _,
            reviewer_policy_digest,
            signature_set_digest,
        } => {
            is_digest(bytes_digest)
                && is_digest(reviewer_policy_digest)
                && is_digest(signature_set_digest)
        }
    }
}

fn content_primary_digest(content: &HostBuildClosureContent) -> &str {
    match content {
        HostBuildClosureContent::File { sha256 } => sha256,
        HostBuildClosureContent::SnapshotTree { tree_digest } => tree_digest,
        HostBuildClosureContent::CanonicalRecord { digest } => digest,
        HostBuildClosureContent::SignedEvidence { bytes_digest, .. } => bytes_digest,
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes[0].is_ascii_lowercase()
        && bytes[bytes.len() - 1] != b'-'
        && !bytes.windows(2).any(|pair| pair == b"--")
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn is_cargo_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn is_logical_closure_path(value: &str) -> bool {
    value.starts_with(CLOSURE_LOGICAL_ROOT)
        && !value.ends_with('/')
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

fn declared_tool_version(value: &str) -> &str {
    value.split_ascii_whitespace().nth(1).unwrap_or(value)
}
