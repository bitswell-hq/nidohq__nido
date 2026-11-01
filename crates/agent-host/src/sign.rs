//! Signing wiring: the agent names a key, a network and a payload; the host
//! checks the signing action, and for a transaction or an authorization
//! entry the chain action of every context the signature authorizes, then
//! asks the key keeper. The agent holds no key, and nothing reaches the
//! keeper before every check passes.
//!
//! The action's network is a network passphrase (as `grant-relay` names
//! networks), and each payload kind is signed so that the signature is bound
//! to what the actions say:
//!
//! | Payload | Agent supplies | Chain actions checked | Keeper signs |
//! | - | - | - | - |
//! | `transaction` | `TransactionEnvelope` XDR (base64) of type `Tx`, with one `InvokeHostFunction` operation | the host function, and every context of every authorization entry | the transaction hash on the action's network (`KeyKeeper` payload `StellarTransaction`, with the checked envelope's XDR), so the signature is valid on that network only |
//! | `auth_entry` | `HashIdPreimage` XDR (base64) of type `SorobanAuthorization` or `SorobanAuthorizationWithAddress` | every context of the preimage's invocation tree | `SHA-256` of the checked preimage's XDR, after the host checks the preimage's network id is `SHA-256` of the action's passphrase |
//! | `message` | UTF-8 text | none | the SEP-53 message hash, `SHA-256("Stellar Signed Message:\n" ‖ message)` |
//!
//! A transaction is refused unless the chain vocabulary can describe all it
//! does: a fee-bump or `TxV0` envelope, any other operation (a payment, a
//! new account or signer, a trustline, …), a second operation, and an
//! `UploadContractWasm` host function are never signed. Contexts map onto
//! chain actions through `grant_relay::actions`, the relay's mapping. The
//! keeper is given the checked payload encoded again, so what it signs is the
//! value the checks read.
//!
//! A message signature is not bound to a network: the action's network is
//! the label the agent gives, and a `network_in` caveat restricts only that
//! label. The SEP-53 prefix keeps a message signature from being a
//! transaction or authorization-entry signature, whose signed hashes start
//! from a network id and an envelope type instead. The host never offers the
//! keeper's raw `Hash` payload to an agent.
//!
//! `SorobanAuthorizationWithAddress` is the preimage a delegated signer signs
//! (`AddressWithDelegates` credentials): the grant signer's holder key
//! authorizes for a Nido account over it, and the preimage names that
//! account. Its invocation tree is checked as a `SorobanAuthorization`
//! preimage's is.

use base64::Engine as _;
use grant_eval::chain;
use grant_relay::actions;
use nido_key_keeper::{KeyId, Payload as KeeperPayload, StellarNetwork};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    HashIdPreimage, Limits, Operation, OperationBody, ReadXdr, TransactionEnvelope,
    TransactionV1Envelope, WriteXdr,
};

use crate::evaluator::wit;
use crate::grant::{self, Payload};

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

impl RequestPayload {
    /// The payload kind the signing grant checks.
    #[must_use]
    pub fn kind(&self) -> Payload {
        match self {
            Self::Transaction(_) => Payload::Transaction,
            Self::AuthEntry(_) => Payload::AuthEntry,
            Self::Message(_) => Payload::Message,
        }
    }
}

/// A request turned into its signing action, the chain actions it
/// authorizes, and the keeper call it makes.
#[derive(Debug)]
pub struct Prepared {
    pub key: KeyId,
    pub network: String,
    pub kind: Payload,
    /// Every context the signature authorizes, for the chain grant. Empty
    /// for a message.
    pub chain: Vec<wit::chain::Action>,
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

fn encode(value: &impl WriteXdr) -> Result<Vec<u8>, String> {
    value
        .to_xdr(Limits::none())
        .map_err(|e| format!("does not encode: {e}"))
}

/// The host function and every context of every authorization entry of a
/// transaction of one `InvokeHostFunction` operation.
fn transaction_actions(envelope: &TransactionEnvelope) -> Result<Vec<chain::Action>, String> {
    let TransactionEnvelope::Tx(TransactionV1Envelope { tx, .. }) = envelope else {
        return Err("only a transaction envelope of type Tx is signed".into());
    };
    let [Operation {
        body: OperationBody::InvokeHostFunction(op),
        ..
    }] = tx.operations.as_slice()
    else {
        return Err("only a transaction of one InvokeHostFunction operation is signed".into());
    };
    let mut out = vec![actions::host_function(&op.host_function)
        .map_err(|e| format!("{} host functions are not signed", e.0))?];
    for entry in &op.auth {
        actions::authorization_tree(entry, &mut out);
    }
    Ok(out)
}

/// Decode `request` into the action to check and the payload to sign.
///
/// # Errors
///
/// A payload that does not decode, a transaction on a network the keeper
/// does not know or with anything but one `InvokeHostFunction` operation
/// the chain vocabulary describes, or an authorization preimage for another
/// network.
pub fn prepare(request: &Request) -> Result<Prepared, String> {
    let (kind, chain, payload) = match &request.payload {
        RequestPayload::Transaction(envelope) => {
            let network = known_network(&request.network).ok_or_else(|| {
                format!("no Stellar network has passphrase {:?}", request.network)
            })?;
            let envelope = TransactionEnvelope::from_xdr(base64_xdr(envelope)?, Limits::none())
                .map_err(|e| format!("not a TransactionEnvelope: {e}"))?;
            (
                Payload::Transaction,
                transaction_actions(&envelope)?,
                KeeperPayload::StellarTransaction {
                    network,
                    envelope_xdr: encode(&envelope)?,
                },
            )
        }
        RequestPayload::AuthEntry(preimage) => {
            let preimage = HashIdPreimage::from_xdr(base64_xdr(preimage)?, Limits::none())
                .map_err(|e| format!("not a HashIdPreimage: {e}"))?;
            let (preimage_network, invocation) = match &preimage {
                HashIdPreimage::SorobanAuthorization(auth) => (&auth.network_id, &auth.invocation),
                HashIdPreimage::SorobanAuthorizationWithAddress(auth) => {
                    (&auth.network_id, &auth.invocation)
                }
                _ => {
                    return Err(
                        "not a SorobanAuthorization or SorobanAuthorizationWithAddress preimage"
                            .into(),
                    )
                }
            };
            let network_id: [u8; 32] = Sha256::digest(request.network.as_bytes()).into();
            if preimage_network.0 != network_id {
                return Err(format!(
                    "the preimage's network id is not that of {:?}",
                    request.network
                ));
            }
            let mut contexts = Vec::new();
            actions::invocation_tree(invocation, &mut contexts);
            (
                Payload::AuthEntry,
                contexts,
                KeeperPayload::Hash(Sha256::digest(encode(&preimage)?).into()),
            )
        }
        RequestPayload::Message(text) => {
            let mut hasher = Sha256::new();
            hasher.update(MESSAGE_PREFIX);
            hasher.update(text.as_bytes());
            (
                Payload::Message,
                Vec::new(),
                KeeperPayload::Hash(hasher.finalize().into()),
            )
        }
    };
    Ok(Prepared {
        key: KeyId::new(request.key.clone()),
        network: request.network.clone(),
        kind,
        chain: chain.into_iter().map(grant::lower_chain_action).collect(),
        payload,
    })
}
