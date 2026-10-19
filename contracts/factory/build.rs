//! Pin the Perch account wasm hash the factory deploys.
//!
//! The factory deploys every account from one installed `perch-account` wasm,
//! by its hash. The hash comes from Perch's deployment manifest for the
//! network the build targets, `vendor/perch/deployments/<network>.json`,
//! where `<network>` is `STELLAR_NETWORK` (default `testnet`, as for
//! `just perch-infra`). A missing manifest, a manifest naming another network,
//! or one without the account's hash fails the build: there is no fallback
//! to another network's account.
//!
//! The pin is written to `$OUT_DIR/perch_account.rs`, which `src/contract.rs`
//! includes as `perch_account::WASM_HASH`.

use std::path::PathBuf;

#[path = "src/pin.rs"]
mod pin;

fn main() {
    println!("cargo:rerun-if-env-changed=STELLAR_NETWORK");
    let network = std::env::var("STELLAR_NETWORK").unwrap_or_else(|_| "testnet".to_owned());
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/perch/deployments")
        .join(format!("{network}.json"));
    println!("cargo:rerun-if-changed={}", manifest.display());

    let text = std::fs::read_to_string(&manifest).unwrap_or_else(|e| {
        panic!(
            "factory: no Perch deployment manifest for network {network:?} at {} ({e}). \
             STELLAR_NETWORK picks the manifest; run `git submodule update --init` \
             for vendor/perch.",
            manifest.display()
        )
    });
    let hash = pin::account_wasm_hash(&text, &network).unwrap_or_else(|why| {
        panic!(
            "factory: cannot pin the perch-account wasm from {}: {why}",
            manifest.display()
        )
    });

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    std::fs::write(
        out.join("perch_account.rs"),
        format!("pub const WASM_HASH: [u8; 32] = {hash:?};\n"),
    )
    .expect("write the account pin");
}
