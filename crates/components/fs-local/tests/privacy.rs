#[test]
fn writable_prepared_local_root_anchor_remains_private() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/*.rs");
}
