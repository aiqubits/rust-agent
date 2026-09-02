#![forbid(unsafe_code)]

pub const TARGET_DEPENDENCY_MARKER: &str = "native";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_the_native_marker() {
        assert_eq!(TARGET_DEPENDENCY_MARKER, "native");
    }
}
