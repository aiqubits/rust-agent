#[test]
fn private_protocol_fields_cannot_be_forged() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}

#[test]
fn binding_assembly_authority_cannot_be_forged() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/forge_binding_assembly.rs");
}
