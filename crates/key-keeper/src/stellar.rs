//! Stellar transaction hashing and decorated signatures.
//!
//! A Stellar transaction signature is an Ed25519 signature over the
//! transaction hash: `SHA-256(TransactionSignaturePayload)`, where the payload
//! is the network id (`SHA-256` of the network passphrase) followed by the
//! envelope-type-tagged transaction. The envelope carries it as a
//! `DecoratedSignature`: the last four bytes of the signer's public key (the
//! hint) and the 64-byte signature.

use ed25519_dalek::{Signature as EdSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    DecoratedSignature, Limits, ReadXdr, Signature, SignatureHint, TransactionEnvelope,
};

/// Passphrase of the Stellar public network.
pub const MAINNET_PASSPHRASE: &str = "Public Global Stellar Network ; September 2015";
/// Passphrase of the Stellar test network.
pub const TESTNET_PASSPHRASE: &str = "Test SDF Network ; September 2015";

/// A Stellar network, as Dfns names them (`Stellar`, `StellarTestnet`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StellarNetwork {
    Mainnet,
    Testnet,
}

impl StellarNetwork {
    #[must_use]
    pub fn passphrase(self) -> &'static str {
        match self {
            Self::Mainnet => MAINNET_PASSPHRASE,
            Self::Testnet => TESTNET_PASSPHRASE,
        }
    }

    /// `SHA-256` of the network passphrase.
    #[must_use]
    pub fn network_id(self) -> [u8; 32] {
        Sha256::digest(self.passphrase().as_bytes()).into()
    }

    /// The Dfns `Network` value for this network.
    #[must_use]
    pub fn dfns_name(self) -> &'static str {
        match self {
            Self::Mainnet => "Stellar",
            Self::Testnet => "StellarTestnet",
        }
    }

    /// The network a Dfns `Network` value names, if it is a Stellar one.
    #[must_use]
    pub fn from_dfns_name(name: &str) -> Option<Self> {
        match name {
            "Stellar" => Some(Self::Mainnet),
            "StellarTestnet" => Some(Self::Testnet),
            _ => None,
        }
    }
}

/// The hash a signature over `envelope` on `network` covers
/// (`stellar-xdr`'s `TransactionEnvelope::hash`).
///
/// # Errors
///
/// If the signature payload does not encode as XDR.
pub fn transaction_hash(
    network: StellarNetwork,
    envelope: &TransactionEnvelope,
) -> Result<[u8; 32], stellar_xdr::Error> {
    envelope.hash(network.network_id())
}

/// [`transaction_hash`] of an XDR-encoded envelope.
///
/// # Errors
///
/// If `envelope_xdr` is not a `TransactionEnvelope`.
pub fn transaction_hash_from_xdr(
    network: StellarNetwork,
    envelope_xdr: &[u8],
) -> Result<[u8; 32], stellar_xdr::Error> {
    let envelope = TransactionEnvelope::from_xdr(envelope_xdr, Limits::none())?;
    transaction_hash(network, &envelope)
}

/// The envelope entry for an Ed25519 `signature` by `public_key`.
///
/// # Panics
///
/// Never: 64 bytes always fit the XDR `Signature` bound of 64.
#[must_use]
pub fn decorated_signature(public_key: &[u8; 32], signature: &[u8; 64]) -> DecoratedSignature {
    let mut hint = [0u8; 4];
    hint.copy_from_slice(&public_key[28..]);
    DecoratedSignature {
        hint: SignatureHint(hint),
        signature: Signature(
            signature
                .to_vec()
                .try_into()
                .expect("64 bytes fit Signature's 64-byte bound"),
        ),
    }
}

/// Whether `decorated` is a valid signature by `public_key` over the
/// transaction with hash `tx_hash`: the hint names the key and the signature
/// verifies (strict Ed25519 verification).
#[must_use]
pub fn verify_decorated_signature(
    public_key: &[u8; 32],
    tx_hash: &[u8; 32],
    decorated: &DecoratedSignature,
) -> bool {
    if decorated.hint.0 != public_key[28..] {
        return false;
    }
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = EdSignature::from_slice(decorated.signature.as_slice()) else {
        return false;
    };
    key.verify_strict(tx_hash, &sig).is_ok()
}

/// The `G…` strkey of an Ed25519 public key.
#[must_use]
pub fn account_strkey(public_key: &[u8; 32]) -> String {
    stellar_strkey::ed25519::PublicKey(*public_key).to_string()
}

/// The Ed25519 public key a `G…` strkey encodes.
///
/// # Errors
///
/// If `strkey` is not a valid `G…` account strkey.
pub fn account_public_key(strkey: &str) -> Result<[u8; 32], stellar_strkey::DecodeError> {
    Ok(stellar_strkey::ed25519::PublicKey::from_string(strkey)?.0)
}
