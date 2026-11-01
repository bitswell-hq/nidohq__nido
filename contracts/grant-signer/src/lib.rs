//! `nido-grant-signer`: AI agents' authority over a Nido account, held as
//! attenuating grants and enforced by `grant-eval` on every authorization.
//!
//! Each Nido account that admits agents gets its own instance, deployed with
//! the account's address. The account's policy document declares the
//! instance as a CAP-0071 delegated signer and names it as the signer of the
//! rules agents act through. When an agent authorizes for the account, the
//! account's `__check_auth` delegates to this contract's `__check_auth`,
//! which the host calls with the account's signature payload and every
//! context of the authorization. This contract then:
//!
//! 1. loads the signing grant and its ancestors, refusing if any of them is
//!    revoked;
//! 2. verifies the holder's ed25519 signature over the payload;
//! 3. refuses any context that calls the account itself;
//! 4. maps every other context to a `grant_eval::chain::Action` and refuses
//!    unless `grant_eval::chain::allows_all` holds for the grant's caveats;
//! 5. charges every `transfer` on the grant's budget asset to the grant and
//!    each ancestor with `grant_eval::budget::spend`, refusing the whole
//!    authorization if any of them would be overdrawn, and refuses any other
//!    call on that asset.
//!
//! Issuing a root grant, revoking, rotating a holder's key and refilling a
//! budget require the account's own authorization, which only its admin rule
//! gives. A holder can only delegate: [`GrantSignerClient::delegate`]
//! creates a child grant whose caveats are the parent's followed by the new
//! ones, with its own budget node under the parent's. It is authorized by
//! this contract's own address, whose `__check_auth` accepts a delegation
//! only from the signing grant itself.
//!
//! `README.md` states the integration, the threat model coverage, the trusted
//! wiring and what is tested.
#![no_std]

extern crate alloc;

mod actions;
mod contract;
mod error;

pub use contract::{GrantSigner, GrantSignerClient};
pub use error::GrantError;

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Vec};

/// A contract-call argument as the evaluator sees it
/// (`grant_eval::chain::Val`). `Address` holds a strkey and `Other` the full
/// `ScVal` XDR of an argument of any type the other variants do not model.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Arg {
    I128(i128),
    U64(u64),
    Bool(bool),
    Bytes(Bytes),
    Address(Bytes),
    Symbol(Bytes),
    Other(Bytes),
}

/// A chain caveat (`grant_eval::chain::Caveat`). Contracts are named by
/// their strkey (`C…`) and functions by their symbol's bytes, as in
/// `crates/grant-relay`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Caveat {
    ContractIn(Vec<Bytes>),
    FunctionIn(Vec<Bytes>),
    ArgI128AtMost(u32, i128),
    ArgEq(u32, Arg),
}

/// One grant: its caveats, its holder's key and its budget node.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    /// The grant this one was delegated from; `None` for a root grant. A
    /// parent's id is always smaller than its children's.
    pub parent: Option<u32>,
    /// The holder's ed25519 public key.
    pub key: BytesN<32>,
    /// The parent's caveats, then the ones added at delegation.
    pub caveats: Vec<Caveat>,
    /// The Stellar Asset Contract the budget is denominated in, the root
    /// grant's for every grant under it.
    pub asset: Address,
    pub allowance: u128,
    /// Every successful spend at or under this grant.
    pub spent: u128,
    pub revoked: bool,
}

/// The signature `__check_auth` takes: the signing grant and its holder's
/// ed25519 signature over the host's signature payload.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantSignature {
    pub grant: u32,
    pub signature: BytesN<64>,
}
