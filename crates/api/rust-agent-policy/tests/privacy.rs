#[test]
fn permission_and_approval_bindings_keep_raw_providers_private() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
