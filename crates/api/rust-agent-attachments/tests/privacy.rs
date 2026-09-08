#[test]
fn attachment_references_context_and_raw_provider_remain_private() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
