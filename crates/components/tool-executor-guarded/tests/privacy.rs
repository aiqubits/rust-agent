#[test]
fn wrapper_cannot_access_guarded_registry_or_builder_internals() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
