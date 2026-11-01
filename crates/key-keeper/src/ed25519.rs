//! Ed25519 signing of a [`Payload`], shared by the in-process keeper and the
//! Dfns mock so both sign exactly the same bytes.

use ed25519_dalek::{Signer, SigningKey};

use crate::{stellar, Payload, SignError};

/// The bytes an Ed25519 signature over `payload` covers.
pub(crate) fn message(payload: &Payload) -> Result<Vec<u8>, SignError> {
    match payload {
        Payload::Hash(hash) => Ok(hash.to_vec()),
        Payload::Message(bytes) => Ok(bytes.clone()),
        Payload::StellarTransaction {
            network,
            envelope_xdr,
        } => stellar::transaction_hash_from_xdr(*network, envelope_xdr)
            .map(|hash| hash.to_vec())
            .map_err(|e| {
                SignError::UnsupportedPayload(format!("not a Stellar TransactionEnvelope: {e}"))
            }),
    }
}

pub(crate) fn sign(key: &SigningKey, payload: &Payload) -> Result<[u8; 64], SignError> {
    Ok(key.sign(&message(payload)?).to_bytes())
}
