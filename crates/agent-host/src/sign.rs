//! Signing wiring: the agent names a key, a network and a payload; the host
//! checks the signing action, then asks the key keeper. The agent holds no
//! key, and nothing reaches the keeper before the check passes.
//!
//! The action's network is a network passphrase (as `grant-relay` names
//! networks), and each payload kind is signed so that the signature is bound
//! to what the action says:
//!
//! | Payload | Agent supplies | Keeper signs |
//! | - | - | - |
//! | `transaction` | `TransactionEnvelope` XDR (base64) | the transaction hash on the action's network (`KeyKeeper` payload `StellarTransaction`), so the signature is valid on that network only |
//! | `auth_entry` | `HashIdPreimage` XDR (base64) of type `SorobanAuthorization` | `SHA-256` of the preimage, after the host checks the preimage's network id is `SHA-256` of the action's passphrase |
//! | `message` | UTF-8 text | the SEP-53 message hash, `SHA-256("Stellar Signed Message:\n" ‖ message)` |
//!
//! A message signature is not bound to a network: the action's network is
//! the label the agent gives, and a `network_in` caveat restricts only that
//! label. The SEP-53 prefix keeps a message signature from being a
//! transaction or authorization-entry signature, whose signed hashes start
//! from a network id and an envelope type instead. The host never offers the
//! keeper's raw `Hash` payload to an agent.

use base64::Engine as _;
use nido_key_keeper::{KeyId, Payload as KeeperPayload, StellarNetwork};
use sha2::{Digest, Sha256};
use stellar_xdr::{HashIdPreimage, Limits, ReadXdr};

use crate::grant::Payload;

/// SEP-53's message prefix.
pub const MESSAGE_PREFIX: &[u8] = b"Stellar Signed Message:\n";

/// What the agent asks the host to sign.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub key: String,
    /// The network passphrase.
    pub network: String,
    #[serde(flatten)]
    pub payload: RequestPayload,
}

#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestPayload {
    /// `TransactionEnvelope` XDR, base64.
    Transaction(String),
    /// `HashIdPreimage` XDR, base64.
    AuthEntry(String),
    /// UTF-8 text.
    Message(String),
}

/// A request turned into its signing action and the keeper call it makes.
#[derive(Debug)]
pub struct Prepared {
    pub key: KeyId,
    pub network: String,
    pub kind: Payload,
    pub payload: KeeperPayload,
}

fn known_network(passphrase: &str) -> Option<StellarNetwork> {
    [StellarNetwork::Mainnet, StellarNetwork::Testnet]
        .into_iter()
        .find(|n| n.passphrase() == passphrase)
}

fn base64_xdr(text: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|e| format!("not base64: {e}"))
}

/// Decode `request` into the action to check and the payload to sign.
///
/// # Errors
///
/// A payload that does not decode, a transaction on a network the keeper
/// does not know, or an authorization preimage for another network.
pub fn prepare(request: &Request) -> Result<Prepared, String> {
    let (kind, payload) = match &request.payload {
        RequestPayload::Transaction(envelope) => {
            let network = known_network(&request.network).ok_or_else(|| {
                format!("no Stellar network has passphrase {:?}", request.network)
            })?;
            (
                Payload::Transaction,
                KeeperPayload::StellarTransaction {
                    network,
                    envelope_xdr: base64_xdr(envelope)?,
                },
            )
        }
        RequestPayload::AuthEntry(preimage) => {
            let xdr = base64_xdr(preimage)?;
            let HashIdPreimage::SorobanAuthorization(auth) =
                HashIdPreimage::from_xdr(&xdr, Limits::none())
                    .map_err(|e| format!("not a HashIdPreimage: {e}"))?
            else {
                return Err("not a SorobanAuthorization preimage".into());
            };
            let network_id: [u8; 32] = Sha256::digest(request.network.as_bytes()).into();
            if auth.network_id.0 != network_id {
                return Err(format!(
                    "the preimage's network id is not that of {:?}",
                    request.network
                ));
            }
            (
                Payload::AuthEntry,
                KeeperPayload::Hash(Sha256::digest(&xdr).into()),
            )
        }
        RequestPayload::Message(text) => {
            let mut hasher = Sha256::new();
            hasher.update(MESSAGE_PREFIX);
            hasher.update(text.as_bytes());
            (
                Payload::Message,
                KeeperPayload::Hash(hasher.finalize().into()),
            )
        }
    };
    Ok(Prepared {
        key: KeyId::new(request.key.clone()),
        network: request.network.clone(),
        kind,
        payload,
    })
}
