//! `nido-email-guardian`: one email inbox as one guardian vote in Perch's
//! account recovery.
//!
//! Each account that enrolls email recovery gets its own instance, deployed
//! with the account's salted address commitment `C`, the DKIM key registry it
//! trusts, an optional key pin, the recovery controller it answers to, the
//! actions it may approve, and the proof verifier (with the verification
//! key's hash). Nothing about it changes after construction.
//!
//! The account lists the guardian's address in its Perch recovery
//! configuration like any other guardian. When the controller collects a
//! guardian approval (`submit_guardian` for attempts, `approve_change` for
//! reconfiguration and upgrades), it calls
//! `guardian.require_auth_for_args((digest,))`, and the host runs this
//! contract's `__check_auth` with an [`EmailApproval`] as the signature. The
//! guardian checks that the approval's statement bytes are the digest's
//! preimage and name its own account, network, and controller; that the
//! action is allowed and expired evidence is refused; that the proof's key
//! root is the pin or a root the registry accepts; and finally that the proof
//! verifies against public inputs it builds itself from `C`, the digest, and
//! the root.
//!
//! The approval counts as exactly one guardian vote. Quorum, the recovery
//! delay, cancellation, and every other rule stay Perch's.
//!
//! `docs/email-recovery/spec.md` is the normative specification: statement
//! binding, email format, enrollment, circuit public inputs, key registry,
//! and the property-to-obligation table.
#![no_std]

use soroban_sdk::{contracttype, Address, Bytes, BytesN, Vec};

mod contract;
mod error;
mod registry;
mod statement;
mod verifier;

pub use contract::{EmailGuardian, EmailGuardianClient};
pub use error::EmailGuardianError;
pub use registry::{DkimRegistryClient, DkimRegistryInterface};
pub use statement::{parse as parse_statement, StatementView, MAX_STATEMENT_LEN};
pub use verifier::{VerifierIdentity, VerifierIdentityClient};

/// Version of this contract's semantics. A new version is a new wasm and
/// therefore a new guardian address.
pub const VERSION: u32 = 1;

/// Length of the public-input blob the guardian hands the verifier:
/// `C || digest_hi || digest_lo || key_root`, four 32-byte big-endian BN254
/// field elements in the circuit's `pub` parameter order.
pub const PUBLIC_INPUTS_LEN: u32 = 128;

/// Longest key pin the constructor accepts, in seconds of ledger close time
/// past the deployment ledger's close time: 365 days. A key the registry
/// revokes stays usable through the pin until the pin's expiry, so this
/// bounds that window. The pin is measured on close time, like the
/// registry's timelocks and grace, so the window keeps its wall-clock
/// length whatever the network's target ledger close time.
pub const MAX_PIN_LIFETIME_SECONDS: u64 = 365 * 86_400;

/// Allowed-action bits: bit `code - 1` for each Perch action code
/// (`docs/recovery/statement.md`, byte 25).
pub const ALLOW_LOST_KEY: u32 = 1 << 0;
pub const ALLOW_COMPROMISE: u32 = 1 << 1;
pub const ALLOW_CANCEL: u32 = 1 << 2;
pub const ALLOW_RECONFIGURE: u32 = 1 << 3;
pub const ALLOW_UPGRADE: u32 = 1 << 4;
/// Every action.
pub const ALLOW_ALL: u32 =
    ALLOW_LOST_KEY | ALLOW_COMPROMISE | ALLOW_CANCEL | ALLOW_RECONFIGURE | ALLOW_UPGRADE;

/// The per-account key pin: the root of a salted key tree (spec "DKIM key
/// identity and registry leaf format"), accepted in place of a registry root
/// while the ledger's close time is at most `valid_until` (Unix seconds).
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPin {
    pub root: BytesN<32>,
    pub valid_until: u64,
}

/// Everything fixed at construction.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardianConfig {
    /// The one account whose statements this guardian approves. A contract.
    pub account: Address,
    /// The Perch recovery controller the account uses. A contract.
    pub controller: Address,
    /// `C = Poseidon2(DOM_COMMIT, address length, address limbs,
    /// account_code)`: a canonical, non-zero BN254 field element.
    pub commitment: BytesN<32>,
    /// The DKIM key registry ([`DkimRegistryInterface`]). A contract.
    pub registry: Address,
    /// An additional accepted key root: zero or one [`KeyPin`] (a `Vec`, as
    /// Perch writes optional members of contract types).
    pub key_pin: Vec<KeyPin>,
    /// The `ALLOW_*` bits of the actions this guardian may approve.
    pub allowed_actions: u32,
    /// The proof verifier: Perch's `ProofVerifierInterface` with the email
    /// circuit's verification key compiled in.
    pub verifier: Address,
    /// `sha256` of that verification key, as the verifier's `circuit_id()`
    /// reports it.
    pub circuit_id: BytesN<32>,
}

/// The signature a caller places in the guardian's authorization entry.
///
/// There is no public-input field: the guardian builds the public inputs
/// from its own configuration, the authorized digest, and `key_root`, which
/// it accepts only as the pin or a registry-accepted root.
#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmailApproval {
    /// The Perch statement encoding whose `sha256` the controller asks the
    /// guardian to authorize (`docs/recovery/statement.md`).
    pub statement: Bytes,
    /// The key-tree root the proof's DKIM key membership was proven against.
    pub key_root: BytesN<32>,
    /// The zero-knowledge `UltraHonk` proof.
    pub proof: Bytes,
}

#[cfg(test)]
mod test;
