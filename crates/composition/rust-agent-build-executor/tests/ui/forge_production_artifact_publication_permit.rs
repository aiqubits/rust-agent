use std::path::PathBuf;

use rust_agent_build_executor::ProductionArtifactPublicationPermit;

fn main() {
    let _forged = ProductionArtifactPublicationPermit {
        build_manifest_digest: "11".repeat(32),
        build_output_digest: "22".repeat(32),
        attestation_path: PathBuf::from("/tmp/forged-attestation.json"),
        attestation_file_sha256: "33".repeat(32),
    };
}
