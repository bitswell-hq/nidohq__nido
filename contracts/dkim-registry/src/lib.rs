//! `nido-dkim-registry`: the DKIM key registry email guardians trust.
//!
//! The registry holds a depth-16 Poseidon2 Merkle tree of
//! `(domain, key_hash)` leaves for the launch providers' RSA-2048 DKIM keys
//! and answers one question for the email guardian:
//! [`is_accepted_root`](DkimRegistry::is_accepted_root). The email circuit
//! proves that the key that signed a recovery email is a leaf of the root the
//! approval names, so a root is acceptable exactly when every key in it is
//! one the registry has admitted and not revoked.
//!
//! - **Governance.** A k-of-n multisig fixed at construction proposes and
//!   approves additions, retirements, and revocations. There is no admin, no
//!   setter, and no upgrade entry point.
//! - **Attestation feed.** Independent DNS attesters (an Ed25519 key set and
//!   threshold fixed at construction) sign what they saw at
//!   `selector._domainkey.domain`. An addition that the attester threshold
//!   saw live in DNS activates 72 hours after it is approved and attested;
//!   any other addition 7 days after approval. A retirement needs the
//!   attester threshold to have seen the key gone from DNS.
//! - **Grace.** A root stays acceptable for the grace period after a newer
//!   root supersedes it.
//! - **Revocation.** Revoking a key for compromise refuses every root that
//!   contains it at once, grace included, and stops pending additions of it.
//!
//! `docs/email-recovery/spec.md` §7 is the normative specification (key
//! hash, leaf, tree, acceptance rules, attestation format, parameters).
#![no_std]

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Vec};

pub mod attestation;
mod contract;
mod error;
mod events;
pub mod hash;
mod tree;

pub use contract::{DkimRegistry, DkimRegistryClient};
pub use error::DkimRegistryError;
pub use events::{
    DnsAttested, KeyActivated, KeyProposed, KeyRetired, KeyRevoked, ProposalApproved,
};
pub use tree::{empty_root, root_of, REGISTRY_CAPACITY, REGISTRY_DEPTH};

/// Version of this contract's semantics. A new version is a new wasm and
/// therefore a new registry address.
pub const VERSION: u32 = 1;

/// Timelock of an addition the attester threshold saw live in DNS: 72 hours
/// at 5-second ledgers, counted from the later of its approval and the
/// attestation that reached the threshold.
pub const TIMELOCK_ATTESTED_LEDGERS: u32 = 51_840;

/// Timelock of any other addition: 7 days, counted from its approval.
pub const TIMELOCK_LEDGERS: u32 = 120_960;

/// Largest grace period the constructor accepts: the 7-day timelock.
pub const MAX_GRACE_LEDGERS: u32 = 120_960;

/// A proposal must be executed within 30 days of its creation, or it lapses.
pub const PROPOSAL_LIFETIME_LEDGERS: u32 = 518_400;

/// An attestation is refused when its observation is more than 24 hours
/// older than the ledger's close time.
pub const MAX_ATTESTATION_AGE_SECONDS: u64 = 86_400;

/// An attestation is refused when its observation is more than 5 minutes
/// after the ledger's close time.
pub const MAX_CLOCK_SKEW_SECONDS: u64 = 300;

/// Most multisig members, and most attesters (approvals and attestations are
/// kept as bit sets in a `u32`).
pub const MAX_MEMBERS: u32 = 20;
pub const MAX_ATTESTERS: u32 = 20;

/// Most allowlisted domains.
pub const MAX_DOMAINS: u32 = 32;

/// Most roots kept for acceptance: the current root and those still in their
/// grace period. When more roots than this are inside their grace period, the
/// oldest superseded root loses the rest of its grace.
pub const MAX_LIVE_ROOTS: u32 = 16;

/// The proposed launch allowlist (spec §7.6): the primary address domains of
/// the launch providers. Whether each provider signs its secondary domains
/// with their own `d=` is to be confirmed with provider-format fixtures
/// (spec §13), so this list is a deployment parameter, not part of the
/// contract.
pub const LAUNCH_DOMAINS: [&str; 11] = [
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "icloud.com",
    "yahoo.com",
    "proton.me",
    "protonmail.com",
    "fastmail.com",
    "gmx.net",
    "gmx.de",
    "web.de",
];

/// Everything fixed at construction.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryConfig {
    /// The multisig members, distinct, at most [`MAX_MEMBERS`].
    pub members: Vec<Address>,
    /// Approvals an addition or retirement needs.
    pub threshold: u32,
    /// Approvals a revocation needs: `1 ≤ revoke_threshold ≤ threshold`.
    pub revoke_threshold: u32,
    /// The DNS attesters' Ed25519 public keys, distinct, at most
    /// [`MAX_ATTESTERS`].
    pub attesters: Vec<BytesN<32>>,
    /// Attestations of the same observation an addition needs for the 72-hour
    /// timelock, and a retirement needs at all.
    pub attest_threshold: u32,
    /// How long a superseded root stays acceptable, in ledgers, at most
    /// [`MAX_GRACE_LEDGERS`].
    pub grace_ledgers: u32,
    /// The domains leaves may name: lowercase, 1 to 62 bytes, at least two
    /// LDH labels, distinct, at most [`MAX_DOMAINS`].
    pub domains: Vec<Bytes>,
}

/// What a proposal does.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ProposalKind {
    /// Admit a key: needs `threshold` approvals, then a timelock.
    Add = 1,
    /// Retire a key its provider no longer publishes: needs `threshold`
    /// approvals and `attest_threshold` attestations that it is gone.
    Retire = 2,
    /// Revoke a key for compromise: needs `revoke_threshold` approvals and
    /// takes effect with the approval that reaches it.
    Revoke = 3,
}

/// A governance proposal and its progress.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub kind: ProposalKind,
    pub domain: Bytes,
    pub key_hash: BytesN<32>,
    /// The ledger the proposal was created in.
    pub created_at: u32,
    /// Bit `i` set: `members[i]` approved.
    pub approvals: u32,
    /// The ledger the approvals reached the proposal's threshold.
    pub approved_at: Option<u32>,
    /// Bit `i` set: `attesters[i]`'s latest observation saw the key
    /// published.
    pub live: u32,
    /// Bit `i` set: `attesters[i]`'s latest observation saw the record absent
    /// or its `p=` empty.
    pub blank: u32,
    /// `observed_at[i]`: the time of `attesters[i]`'s latest recorded
    /// observation, meaningful where bit `i` of `live` or `blank` is set.
    pub observed_at: Vec<u64>,
    /// The ledger since which the latest observations that count for this
    /// kind (`live` for an addition, `blank` for a retirement) have numbered
    /// at least `attest_threshold`; `None` while they number fewer.
    pub attested_at: Option<u32>,
    pub executed: bool,
}

/// A key leaf's identity: the DKIM `d=` domain and the key hash.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafId {
    pub domain: Bytes,
    pub key_hash: BytesN<32>,
}

/// Root sequence numbers `from..to` during which a leaf was in the tree;
/// `to` is `u32::MAX` while it still is.
#[contracttype]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootSpan {
    pub from: u32,
    pub to: u32,
}

/// What the registry knows about one `(domain, key_hash)` leaf.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafRecord {
    /// Its tree index while present, or its last index.
    pub index: u32,
    pub present: bool,
    /// Every interval of root sequence numbers it was part of.
    pub spans: Vec<RootSpan>,
    /// The id of the latest revocation of this leaf; `0` if never revoked.
    pub revoked_by: u32,
}

/// A root that may still be acceptable.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveRoot {
    pub root: BytesN<32>,
    /// Its root sequence number: the count of tree changes that produced it.
    pub seq: u32,
    /// The ledger a newer root superseded it in; `None` for the current root.
    pub superseded_at: Option<u32>,
}

/// The registry's mutable state.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryState {
    /// The current root.
    pub root: BytesN<32>,
    /// The current root's sequence number (`0`: the empty tree at
    /// construction).
    pub seq: u32,
    /// The index the next admitted key takes. Indices are never reused.
    pub next_index: u32,
    /// The id the next proposal takes (ids start at 1).
    pub next_proposal: u32,
    /// The current root (unless the tree is empty) and the superseded roots
    /// still inside their grace period, oldest first.
    pub live_roots: Vec<LiveRoot>,
}

#[cfg(test)]
mod test;
