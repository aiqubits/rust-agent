#[test]
fn telemetry_event_and_raw_provider_remain_private() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
