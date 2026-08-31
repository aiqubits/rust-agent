#[test]
fn private_protocol_fields_cannot_be_forged() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
