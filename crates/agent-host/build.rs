//! Builds `crates/grant-component` for `wasm32v1-none`, the target the
//! Soroban smart account compiles `grant-eval` for, and wraps the core module
//! as a component. The host embeds the result (`$OUT_DIR/grant_eval.wasm`).
//!
//! The nested build has its own target directory, so it never waits on the
//! lock the outer build holds, and none of the outer build's compiler flags
//! or wrappers (`clippy-driver` under `cargo clippy`), which are for the host
//! target.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const TARGET: &str = "wasm32v1-none";

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let crates = manifest_dir.parent().unwrap();
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    for input in [
        "grant-component/src",
        "grant-component/wit",
        "grant-component/Cargo.toml",
        "grant-eval/src",
        "grant-eval/Cargo.toml",
    ] {
        println!("cargo:rerun-if-changed={}", crates.join(input).display());
    }

    // `$OUT_DIR` is `<profile dir>/build/<package>-<hash>/out`.
    let target_dir = out_dir.ancestors().nth(3).unwrap().join("grant-component");
    let core = build_core_module(crates, &target_dir);
    let component = wit_component::ComponentEncoder::default()
        .validate(true)
        .module(&core)
        .and_then(wit_component::ComponentEncoder::encode)
        .unwrap_or_else(|e| panic!("wrapping grant-component as a component: {e:?}"));
    std::fs::write(out_dir.join("grant_eval.wasm"), component).unwrap();
}

fn build_core_module(crates: &Path, target_dir: &Path) -> Vec<u8> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args([
            "build",
            "--release",
            "--package",
            "grant-component",
            "--target",
            TARGET,
        ])
        .arg("--manifest-path")
        .arg(crates.join("grant-component/Cargo.toml"))
        .arg("--target-dir")
        .arg(target_dir)
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("RUSTFLAGS")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env_remove("CLIPPY_ARGS")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("CARGO_BUILD_TARGET")
        .status()
        .expect("running cargo for grant-component");
    assert!(
        status.success(),
        "building grant-component for {TARGET} failed (is the target installed? `rustup target add {TARGET}`)"
    );
    let wasm = target_dir.join(TARGET).join("release/grant_component.wasm");
    std::fs::read(&wasm).unwrap_or_else(|e| panic!("reading {}: {e}", wasm.display()))
}
