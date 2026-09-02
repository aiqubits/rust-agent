#[cfg(not(product_build_generated))]
compile_error!("the product build unit did not inject its downstream cfg contribution");

fn require_std_error<T: std::error::Error>() {}

fn main() {
    require_std_error::<hex::FromHexError>();
    let runtime = agent::create_runtime_primitives().expect("fixture runtime must initialize");
    let app = agent::build(
        agent::RuntimeConfig::default(),
        agent::HostBindings::default(),
        runtime,
    )
    .expect("emitted composition must build in the product Host");
    println!("{}:product-generated-marker", app.run("shared-feature"));
}
