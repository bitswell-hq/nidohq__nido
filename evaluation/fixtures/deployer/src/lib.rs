//! `deploy(deployer, wasm, salt)` deploys `wasm` with `deployer` as the
//! deploying address and `deployer` as its constructor argument, which needs
//! `deployer`'s authorization of the creation. The attack suite's `Deployer`
//! (`evaluation/harness/src/soroban/attacks.rs`), built as wasm so the local
//! network can run it.
#![no_std]

use soroban_sdk::{contract, contractimpl, Address, BytesN, ContractExecutable, Env};

#[contract]
pub struct Deployer;

#[contractimpl]
impl Deployer {
    pub fn deploy(e: Env, deployer: Address, wasm: BytesN<32>, salt: BytesN<32>) -> Address {
        e.deployer()
            .with_address(deployer.clone(), salt)
            .deploy_contract(ContractExecutable::Wasm(wasm), (deployer,))
    }
}
