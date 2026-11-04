//! `nido-grant-signer`: AI agents' authority over a Nido account, held as
//! attenuating grants and enforced on every authorization by `rule-eval`'s
//! rule check and budget tree.
//!
//! Each Nido account that admits agents gets its own instance, deployed with
//! the account's address. The account applies a scoped document for its
//! agents (`apply_scope`) whose rules name this instance as their CAP-0071
//! delegated signer. When an agent authorizes for the account, the account's
//! `__check_auth` checks every context against the scoped rule chosen for it
//! and then delegates to this contract's `__check_auth`, which the host calls
//! with the account's signature payload and every context of the
//! authorization. This contract then:
//!
//! 1. loads the signing grant and its ancestors, refusing if any of them is
//!    revoked;
//! 2. verifies the holder's ed25519 signature over the payload;
//! 3. refuses any context that creates a contract or calls the account
//!    itself, and any call on this contract other than the holder's own
//!    delegation;
//! 4. checks every other context, a contract call read through
//!    `soroban-facade`, against the grant's rule set with
//!    `rule_eval::authorize`, each context by the first rule that allows it,
//!    with this contract as the authenticated signer and the grant's spending
//!    records;
//! 5. charges every `transfer` on the grant's budget asset to the grant and
//!    each ancestor with `rule_eval::spend`, refusing the whole
//!    authorization if any of them would be overdrawn, and refuses any other
//!    call on that asset.
//!
//! A root grant's rule set is the rules the owner issues it with: the rules
//! the account's scoped document for the agent lowers to, as the account's
//! `scope_rule_set` view returns them. Issuing a root grant, revoking,
//! rotating a holder's key and refilling a budget require the account's own
//! authorization, which only its admin rule gives. A holder can only
//! delegate: [`GrantSignerClient::delegate`] creates a child grant whose rule
//! set is the parent's with the child's [`Step`]s, `rule_eval`'s attenuation
//! steps, replayed on it, and whose budget node is under the parent's. It is
//! authorized by this contract's own address, whose `__check_auth` accepts a
//! delegation only from the signing grant itself. So `__check_auth` is also
//! the check of this contract's own address, a role the host calls it in
//! with the same arguments.
//!
//! `README.md` states the integration, both roles of `__check_auth`, the
//! threat model coverage, the trusted wiring and what is tested.
//! `formal/AttenuatingGrants/Signer.lean` proves that the budget path below
//! keeps budget safety on the whole ledger of grants.
#![no_std]

extern crate alloc;

mod actions;
mod budget;
mod contract;
mod error;
mod rules;

pub use contract::{GrantSigner, GrantSignerClient};
pub use error::GrantError;
pub use perch_rule_eval::{StoredCap, StoredCond, StoredFunctions, StoredRule, StoredVal};

use soroban_sdk::{contracttype, Address, BytesN, Symbol, Vec};
use stellar_accounts::smart_account::Signer;

/// One of `rule_eval`'s attenuation steps, on the rule at the index: each
/// returns a rule set that allows no context, and accepts no run of
/// authorizations from empty records, that the rule set it was applied to
/// does not.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Step {
    /// `rule_eval::drop_rule`: every later rule's index moves down by one.
    DropRule(u32),
    /// `rule_eval::add_cond`.
    AddCond(u32, StoredCond),
    /// `rule_eval::remove_functions`.
    RemoveFunctions(u32, Vec<Symbol>),
    /// `rule_eval::restrict_functions`.
    RestrictFunctions(u32, Vec<Symbol>),
    /// `rule_eval::remove_signers`.
    RemoveSigners(u32, Vec<Signer>),
    /// `rule_eval::raise_threshold`.
    RaiseThreshold(u32, u32),
    /// `rule_eval::add_cap`.
    AddCap(u32, StoredCap),
    /// `rule_eval::lower_cap_limit`.
    LowerCapLimit(u32, i128),
    /// `rule_eval::lengthen_cap_period`.
    LengthenCapPeriod(u32, u32),
    /// `rule_eval::lower_valid_until`.
    LowerValidUntil(u32, u32),
}

/// One grant: its rule set, its holder's key and its budget node.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Grant {
    /// The grant this one was delegated from; `None` for a root grant. A
    /// parent's id is always smaller than its children's.
    pub parent: Option<u32>,
    /// The holder's ed25519 public key.
    pub key: BytesN<32>,
    /// A root grant's rule set; empty for a delegated grant. Every rule
    /// holds at most one valid cap, and all carry the same generation.
    pub rules: Vec<StoredRule>,
    /// A delegated grant's attenuation steps, replayed on its parent's rule
    /// set; empty for a root grant.
    pub steps: Vec<Step>,
    /// The Stellar Asset Contract the budget is denominated in, the root
    /// grant's for every grant under it.
    pub asset: Address,
    /// At most `i128::MAX`: `issue`, `delegate` and `refill` refuse more.
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
