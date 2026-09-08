#[test]
fn private_session_protocol_fields_cannot_be_accessed() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/access_private_session_protocol_fields.rs");
}
