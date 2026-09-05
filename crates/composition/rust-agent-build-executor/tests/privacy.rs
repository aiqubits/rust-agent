#![cfg(target_os = "linux")]

#[test]
fn production_artifact_publication_permit_cannot_be_forged() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/forge_production_artifact_publication_permit.rs");
}
