#[test]
fn tool_policy_registration_and_permit_boundaries_cannot_be_bypassed() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
