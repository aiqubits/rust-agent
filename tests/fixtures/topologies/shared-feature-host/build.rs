fn main() {
    println!("cargo:rustc-check-cfg=cfg(product_build_generated)");
    println!("cargo:rustc-cfg=product_build_generated");
}
