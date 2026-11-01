// The contract's wasm gets a 128 KiB stack instead of rustc's 1 MiB default,
// as Perch's ZK adapter does for the same verifier: its zero-knowledge
// UltraHonk verification needs more than 32 KiB, and every cross-contract
// call instantiates a fresh VM charged its whole initial linear memory.
fn main() {
    if std::env::var("CARGO_CFG_TARGET_FAMILY").as_deref() == Ok("wasm") {
        println!("cargo:rustc-link-arg-cdylib=-zstack-size=131072");
    }
}
