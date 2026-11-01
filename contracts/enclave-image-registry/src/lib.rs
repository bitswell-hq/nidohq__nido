//! `nido-enclave-image-registry`: the public record of which enclave images
//! may hold the email-alert vault's key.
//!
//! The alert vault's decryption key is split across custodians, and a
//! custodian releases its share only to an enclave whose attested
//! measurement is **active** here. A measurement becomes active in three
//! public steps, each emitting an event:
//!
//! 1. A signer of the registry's fixed multisig proposes it
//!    ([`MeasurementProposed`]); each signer's vote, the proposer's included,
//!    is recorded ([`MeasurementApproved`]).
//! 2. When `threshold` signers have voted, the measurement is queued with
//!    `active_from = L + TIMELOCK_LEDGERS` ([`MeasurementQueued`]): 14 days in
//!    which anyone can inspect the image before it can receive a share.
//! 3. After `active_from`, anyone may call [`activate`](EnclaveImageRegistry::activate)
//!    ([`MeasurementActivated`]).
//!
//! `threshold` signers can revoke a measurement at any stage; revocation
//! takes effect at once and is final ([`MeasurementRevoked`]).
//!
//! The signer set and threshold are fixed at construction. There is no
//! admin, no upgrade entry point, and no way to shorten the timelock.
//!
//! `docs/email-recovery/spec.md` §10.4 is the normative specification,
//! including how a measurement is computed from an enclave image's PCRs.
#![no_std]

use soroban_sdk::{contractevent, contracttype, Address, BytesN, Vec};

mod contract;
mod error;

pub use contract::{EnclaveImageRegistry, EnclaveImageRegistryClient};
pub use error::RegistryError;

/// Version of this contract's semantics.
pub const VERSION: u32 = 1;

/// Ledgers between the multisig reaching its threshold and the earliest
/// activation: 14 days at 5-second ledgers.
pub const TIMELOCK_LEDGERS: u32 = 241_920;

/// Largest signer set the constructor accepts.
pub const MAX_SIGNERS: u32 = 10;

/// Where a measurement stands.
#[contracttype]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Status {
    /// Proposed; fewer than `threshold` signers have voted to approve.
    Pending = 0,
    /// Approved by the multisig; inside the timelock until `active_from`.
    Queued = 1,
    /// Custodians may release shares to an enclave with this measurement.
    Active = 2,
    /// Revoked by the multisig; never active again.
    Revoked = 3,
}

/// Everything recorded about one measurement.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Measurement {
    pub status: Status,
    /// Signers who voted to approve, in voting order.
    pub approvals: Vec<Address>,
    /// Signers who voted to revoke, in voting order.
    pub revocations: Vec<Address>,
    /// Ledger of the proposal.
    pub proposed_at: u32,
    /// First ledger `activate` succeeds at; `0` until queued.
    pub active_from: u32,
    /// Ledger of activation; `0` until active.
    pub activated_at: u32,
    /// Ledger of revocation; `0` unless revoked.
    pub revoked_at: u32,
}

/// A signer proposed a measurement for approval.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementProposed {
    #[topic]
    pub measurement: BytesN<32>,
    pub proposer: Address,
}

/// A signer voted to approve a measurement (the proposal is the proposer's
/// vote).
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementApproved {
    #[topic]
    pub measurement: BytesN<32>,
    pub signer: Address,
    pub approvals: u32,
}

/// The multisig approved a measurement; it can be activated from
/// `active_from`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementQueued {
    #[topic]
    pub measurement: BytesN<32>,
    pub active_from: u32,
}

/// A measurement became active.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementActivated {
    #[topic]
    pub measurement: BytesN<32>,
}

/// A signer voted to revoke a measurement.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementRevocationVoted {
    #[topic]
    pub measurement: BytesN<32>,
    pub signer: Address,
    pub revocations: u32,
}

/// The multisig revoked a measurement.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeasurementRevoked {
    #[topic]
    pub measurement: BytesN<32>,
}

#[cfg(test)]
mod test;
