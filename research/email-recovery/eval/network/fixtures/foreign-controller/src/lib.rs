//! TEST-ONLY. `submit_guardian(guardian, digest)` asks `guardian` to
//! authorize exactly `(digest,)`, as Perch's controller does
//! (`require_auth_for_args`), from a contract that is not the guardian's
//! controller. The guardian must refuse it: its authorization context is a
//! call on this contract, not on its controller (spec §8.3 check 1).
#![no_std]

use soroban_sdk::{contract, contractimpl, vec, Address, BytesN, Env, IntoVal};

#[contract]
pub struct ForeignController;

#[contractimpl]
impl ForeignController {
    pub fn submit_guardian(env: Env, guardian: Address, digest: BytesN<32>) {
        guardian.require_auth_for_args(vec![&env, digest.into_val(&env)]);
    }
}
