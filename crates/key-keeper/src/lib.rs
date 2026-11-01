//! The key keeper: the component that holds signing keys on behalf of agents
//! that hold none.
//!
//! An agent asks a [`KeyKeeper`] to sign a [`Payload`] with key `K`. The grant
//! check (is this agent allowed to have `K` sign this payload?) runs before
//! the call and is not part of this crate; a keeper only refuses what its own
//! backend refuses (an unknown key, a payload kind the key cannot sign, a
//! backend policy).
//!
//! Implementations:
//!
//! - [`MemoryKeyKeeper`]: Ed25519 keys in process, for unit tests of the
//!   components built on this interface.
//! - [`dfns::DfnsKeyKeeper`]: a client for the Dfns Keys API Generate
//!   Signature endpoint.
//! - [`dfns::mock`]: a local HTTP server implementing that endpoint (and the
//!   user action signing flow it requires) over local Ed25519 keys; the
//!   `dfns-mock` binary runs it.
//!
//! [`stellar`] has the Stellar transaction hash and decorated-signature
//! helpers the implementations and their tests share.

use std::fmt;

pub mod dfns;
mod ed25519;
mod memory;
pub mod stellar;

pub use memory::MemoryKeyKeeper;
pub use stellar::StellarNetwork;

/// Signs payloads with keys the caller does not hold.
pub trait KeyKeeper {
    /// Sign `payload` with the key `key`.
    ///
    /// # Errors
    ///
    /// A [`SignError`] naming why no signature was produced.
    fn sign(&self, key: &KeyId, payload: &Payload) -> Result<Signature, SignError>;
}

/// A keeper-scoped key identifier (for Dfns, the `key-…` id).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(pub String);

impl KeyId {
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What to sign. The variants are the payload kinds of the signing action
/// vocabulary; each maps onto one Dfns Generate Signature `kind`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Payload {
    /// A 32-byte digest, signed as given (Dfns `Hash`). For a Stellar
    /// transaction this is the transaction hash, which is the message an
    /// Ed25519 transaction signature covers.
    Hash([u8; 32]),
    /// Arbitrary bytes (Dfns `Message`).
    Message(Vec<u8>),
    /// An unsigned Stellar `TransactionEnvelope` in XDR (Dfns `Transaction`).
    /// The keeper derives the transaction hash for `network` and signs it.
    StellarTransaction {
        network: StellarNetwork,
        envelope_xdr: Vec<u8>,
    },
}

/// A signature in the encoding the key's network expects. For Ed25519 this is
/// the 64-byte `R || S`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

impl Signature {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The signature as an Ed25519 `R || S`, if it is 64 bytes long.
    #[must_use]
    pub fn to_ed25519(&self) -> Option<[u8; 64]> {
        self.0.as_slice().try_into().ok()
    }
}

/// Why a keeper produced no signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignError {
    /// The keeper has no key with this id.
    UnknownKey(KeyId),
    /// The key cannot sign this payload (wrong kind for its scheme, or a
    /// payload that does not decode).
    UnsupportedPayload(String),
    /// The keeper refused the caller's credentials.
    Unauthorized(String),
    /// The backend accepted the request but holds it for a policy approval.
    /// `request_id` identifies it for a later status read.
    PendingApproval {
        request_id: String,
        approval_id: Option<String>,
    },
    /// The backend refused to sign (for Dfns, status `Rejected`).
    Rejected {
        request_id: Option<String>,
        reason: Option<String>,
    },
    /// The backend tried to sign and failed (for Dfns, status `Failed`).
    Failed {
        request_id: Option<String>,
        reason: Option<String>,
    },
    /// The backend rejected the request as invalid.
    InvalidRequest(String),
    /// Any other error status from the backend.
    Backend { status: u16, message: String },
    /// The backend could not be reached, or did not finish in time.
    Transport(String),
    /// The backend answered with something that does not parse as the
    /// documented response.
    MalformedResponse(String),
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKey(key) => write!(f, "unknown key {key}"),
            Self::UnsupportedPayload(why) => write!(f, "unsupported payload: {why}"),
            Self::Unauthorized(why) => write!(f, "unauthorized: {why}"),
            Self::PendingApproval {
                request_id,
                approval_id,
            } => write!(
                f,
                "signature request {request_id} awaits policy approval {}",
                approval_id.as_deref().unwrap_or("(no approval id)")
            ),
            Self::Rejected { request_id, reason } => write!(
                f,
                "signature request {} rejected: {}",
                request_id.as_deref().unwrap_or("?"),
                reason.as_deref().unwrap_or("no reason given")
            ),
            Self::Failed { request_id, reason } => write!(
                f,
                "signature request {} failed: {}",
                request_id.as_deref().unwrap_or("?"),
                reason.as_deref().unwrap_or("no reason given")
            ),
            Self::InvalidRequest(why) => write!(f, "invalid request: {why}"),
            Self::Backend { status, message } => write!(f, "backend error {status}: {message}"),
            Self::Transport(why) => write!(f, "transport error: {why}"),
            Self::MalformedResponse(why) => write!(f, "malformed response: {why}"),
        }
    }
}

impl std::error::Error for SignError {}
