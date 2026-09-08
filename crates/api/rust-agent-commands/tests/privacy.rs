#[test]
fn command_authority_and_tool_grants_cannot_be_forged_or_cloned() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
