#[test]
fn confinement_process_shell_terminal_authority_remains_private() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/ui/*.rs");
}
