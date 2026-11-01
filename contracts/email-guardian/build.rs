// The contract's wasm gets a 64 KiB stack instead of rustc's 1 MiB default.
// Every cross-contract call instantiates a fresh VM and is charged its whole
// initial linear memory, and the guardian runs inside every recovery
// approval it gives.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_FAMILY").as_deref() == Ok("wasm") {
        println!("cargo:rustc-link-arg-cdylib=-zstack-size=65536");
    }
}
