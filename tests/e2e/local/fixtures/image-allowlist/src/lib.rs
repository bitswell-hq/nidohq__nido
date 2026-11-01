//! TEST-ONLY: `is_active(measurement)` is true for exactly the measurement
//! given at construction.
//!
//! The enclave-image registry (`contracts/enclave-image-registry`) activates
//! a measurement only 241,920 ledgers (14 days) after its approval, which a
//! local network in an end-to-end test cannot wait out. The wallet asks this
//! contract the same question (`is_active`) it asks the registry, so its code
//! path is the production one; the registry's own lifecycle is tested on the
//! integration-test host (`crates/integration-tests/tests/it/email_alerts.rs`).
#![no_std]

use soroban_sdk::{contract, contractimpl, symbol_short, BytesN, Env};

#[contract]
pub struct ImageAllowlist;

#[contractimpl]
impl ImageAllowlist {
    pub fn __constructor(env: Env, measurement: BytesN<32>) {
        env.storage()
            .instance()
            .set(&symbol_short!("m"), &measurement);
    }

    pub fn is_active(env: Env, measurement: BytesN<32>) -> bool {
        env.storage()
            .instance()
            .get::<_, BytesN<32>>(&symbol_short!("m"))
            == Some(measurement)
    }
}
