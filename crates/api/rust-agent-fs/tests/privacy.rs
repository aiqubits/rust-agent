#[test]
fn filesystem_paths_contexts_pages_and_raw_providers_remain_private() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
