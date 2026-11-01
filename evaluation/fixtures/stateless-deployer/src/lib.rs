//! `deploy(wasm_hash)` deploys the uploaded wasm with this contract as the
//! deployer and `salt = wasm_hash`, with no constructor arguments.
//!
//! That is the address derivation of Perch's stateless registry
//! (`perch-registry-resolve`: `deployer(registry, salt = sha256(wasm))`), so a
//! Perch account built with this contract's address as its `stateless.id`
//! finds the doc compiler, interpreter and spending limit this contract
//! deploys. It stands in for the registry on a local network, where the
//! registry Perch's testnet account names does not exist.
#![no_std]

use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

#[contract]
pub struct StatelessDeployer;

#[contractimpl]
impl StatelessDeployer {
    pub fn deploy(env: Env, wasm_hash: BytesN<32>) -> Address {
        env.deployer()
            .with_current_contract(wasm_hash.clone())
            .deploy_v2(wasm_hash, ())
    }
}
