#[test]
fn prompt_and_compaction_state_and_raw_providers_remain_private() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
