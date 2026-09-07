#[test]
fn model_call_authority_types_cannot_be_forged() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
