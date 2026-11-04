//! A registry stand-in for the local network: every link of the chain a
//! Perch account derives its infra from is one instance of this contract.
//!
//! A Perch account reads `wasm/registry.path` at build time: a root deployed
//! by an account with `sha256(root-salt)`, then one named deploy per path
//! segment at `deployer(parent, sha256(name))`, then each infra contract at
//! `deployer(<last registry>, salt = sha256(wasm))` (`perch-registry-resolve`).
//! On a local network, where the Stellar Registry that Perch's committed path
//! names does not exist, `evaluation/fixtures/local-registry.path` names a
//! root this contract is deployed at:
//!
//! - `deploy_named(wasm_hash, name)` deploys the uploaded wasm (another
//!   instance, for the next path segment) with `salt = sha256(name)`;
//! - `deploy(wasm_hash)` deploys the uploaded wasm (an infra contract) with
//!   `salt = wasm_hash`.
//!
//! Neither passes constructor arguments.
#![no_std]

use soroban_sdk::{contract, contractimpl, Address, Bytes, BytesN, ContractExecutable, Env};

#[contract]
pub struct StatelessDeployer;

#[contractimpl]
impl StatelessDeployer {
    pub fn deploy(env: Env, wasm_hash: BytesN<32>) -> Address {
        env.deployer()
            .with_current_contract(wasm_hash.clone())
            .deploy_contract(ContractExecutable::Wasm(wasm_hash), ())
    }

    /// `name` is a registry name as the path writes it (lowercase ASCII
    /// letters, digits and `-`), so its bytes are the salt preimage.
    pub fn deploy_named(env: Env, wasm_hash: BytesN<32>, name: Bytes) -> Address {
        let salt: BytesN<32> = env.crypto().sha256(&name).into();
        env.deployer()
            .with_current_contract(salt)
            .deploy_contract(ContractExecutable::Wasm(wasm_hash), ())
    }
}
