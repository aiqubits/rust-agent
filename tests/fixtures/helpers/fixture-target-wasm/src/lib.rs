#![forbid(unsafe_code)]

pub const TARGET_DEPENDENCY_MARKER: &str = "wasm";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_the_wasm_marker() {
        assert_eq!(TARGET_DEPENDENCY_MARKER, "wasm");
    }
}
