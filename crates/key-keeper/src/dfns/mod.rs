//! A [`KeyKeeper`] backed by the Dfns Keys API.
//!
//! Signing is one state-changing call, `POST /keys/{keyId}/signatures`
//! (Generate Signature), which Dfns authenticates with two headers:
//!
//! - `Authorization: Bearer <token>`: a service account token, personal
//!   access token or login token.
//! - `X-DFNS-USERACTION: <token>`: a one-time user action token for this exact
//!   request, from the user action signing flow. The client asks
//!   `POST /auth/action/init` for a challenge naming the method, path and body
//!   it will send, signs `{"type":"key.get","challenge":…}` with its `Key`
//!   credential, and trades the signature at `POST /auth/action` for the
//!   token.
//!
//! A request that is not finished when Generate Signature returns (status
//! `Pending` or `Executing`) is read back with
//! `GET /keys/{keyId}/signatures/{signatureId}` until it is, unless it carries
//! an `approvalId`: a policy approval waits on people, so the keeper reports
//! [`SignError::PendingApproval`] instead of waiting.

pub mod api;
pub mod mock;

use std::fmt;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde::de::DeserializeOwned;
use serde::Serialize;

use self::api::{
    ErrorBody, FirstFactor, GenerateSignatureRequest, KeyAssertion, SignatureComponents,
    SignatureRequest, SignatureStatus, UserActionChallenge, UserActionChallengeRequest,
    UserActionSignature, UserActionSignatureRequest,
};
use crate::{KeyId, KeyKeeper, Payload, SignError, Signature};

/// The default (Europe) Dfns API host.
pub const DEFAULT_BASE_URL: &str = "https://api.dfns.io";

/// A Dfns `Key` credential: the id Dfns assigned it and the Ed25519 private
/// key whose public half was registered with it.
pub struct KeyCredential {
    pub cred_id: String,
    pub signing_key: SigningKey,
}

/// How a [`DfnsKeyKeeper`] reaches Dfns.
pub struct DfnsConfig {
    /// API origin, without a trailing slash (for example
    /// [`DEFAULT_BASE_URL`], or a local mock's URL).
    pub base_url: String,
    /// The bearer token.
    pub auth_token: String,
    /// The credential that signs user action challenges for `auth_token`.
    pub credential: KeyCredential,
    /// Status reads after a `Pending` or `Executing` response, before giving
    /// up with [`SignError::Transport`].
    pub poll_attempts: u32,
    pub poll_interval: Duration,
}

impl DfnsConfig {
    #[must_use]
    pub fn new(
        base_url: impl Into<String>,
        auth_token: impl Into<String>,
        credential: KeyCredential,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            auth_token: auth_token.into(),
            credential,
            poll_attempts: 30,
            poll_interval: Duration::from_millis(500),
        }
    }
}

/// A [`KeyKeeper`] that signs through Dfns Generate Signature.
pub struct DfnsKeyKeeper {
    config: DfnsConfig,
    agent: ureq::Agent,
}

impl DfnsKeyKeeper {
    #[must_use]
    pub fn new(config: DfnsConfig) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Self { config, agent }
    }

    /// Generate Signature with an explicit request body.
    ///
    /// # Errors
    ///
    /// The error status Dfns answered with, mapped onto [`SignError`], or a
    /// transport or decoding failure.
    pub fn generate_signature(
        &self,
        key: &KeyId,
        request: &GenerateSignatureRequest,
    ) -> Result<SignatureRequest, SignError> {
        let path = format!("/keys/{}/signatures", key.as_str());
        let body = to_json(request)?;
        let user_action = self.user_action("POST", &path, &body)?;
        let response = self
            .agent
            .post(&self.url(&path))
            .header("Authorization", &self.bearer())
            .header("X-DFNS-USERACTION", &user_action)
            .content_type("application/json")
            .send(&body);
        read(response, Some(key))
    }

    /// Get Signature.
    ///
    /// # Errors
    ///
    /// As [`Self::generate_signature`].
    pub fn get_signature(
        &self,
        key: &KeyId,
        signature_id: &str,
    ) -> Result<SignatureRequest, SignError> {
        let path = format!("/keys/{}/signatures/{signature_id}", key.as_str());
        let response = self
            .agent
            .get(&self.url(&path))
            .header("Authorization", &self.bearer())
            .call();
        read(response, Some(key))
    }

    /// Run the user action signing flow for one request, returning the
    /// `X-DFNS-USERACTION` token that authorizes exactly it.
    fn user_action(&self, method: &str, path: &str, body: &str) -> Result<String, SignError> {
        let init = UserActionChallengeRequest {
            user_action_http_method: method.to_owned(),
            user_action_http_path: path.to_owned(),
            user_action_payload: body.to_owned(),
            user_action_server_kind: Some("Api".to_owned()),
        };
        let challenge: UserActionChallenge = self.post_json("/auth/action/init", &init)?;

        let credential = &self.config.credential;
        if !challenge
            .allow_credentials
            .key
            .iter()
            .any(|c| c.id == credential.cred_id)
        {
            return Err(SignError::Unauthorized(format!(
                "credential {} is not among the challenge's allowed key credentials",
                credential.cred_id
            )));
        }
        // The shape Dfns's TypeScript `AsymmetricKeySigner` signs.
        let client_data = serde_json::json!({
            "type": "key.get",
            "challenge": challenge.challenge,
        })
        .to_string();
        let signature = credential.signing_key.sign(client_data.as_bytes());
        let complete = UserActionSignatureRequest {
            challenge_identifier: challenge.challenge_identifier,
            first_factor: FirstFactor::Key {
                credential_assertion: KeyAssertion {
                    cred_id: credential.cred_id.clone(),
                    client_data: URL_SAFE_NO_PAD.encode(client_data.as_bytes()),
                    signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                    algorithm: None,
                },
            },
            second_factor: None,
        };
        let token: UserActionSignature = self.post_json("/auth/action", &complete)?;
        Ok(token.user_action)
    }

    fn post_json<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, SignError> {
        let response = self
            .agent
            .post(&self.url(path))
            .header("Authorization", &self.bearer())
            .content_type("application/json")
            .send(&to_json(body)?);
        read(response, None)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.base_url)
    }

    fn bearer(&self) -> String {
        format!("Bearer {}", self.config.auth_token)
    }

    /// Wait out `Pending`/`Executing` (without a policy approval) by reading
    /// the request back.
    fn settle(
        &self,
        key: &KeyId,
        mut request: SignatureRequest,
    ) -> Result<SignatureRequest, SignError> {
        let mut attempts = 0;
        while matches!(
            request.status,
            SignatureStatus::Pending | SignatureStatus::Executing
        ) && request.approval_id.is_none()
        {
            if attempts == self.config.poll_attempts {
                return Err(SignError::Transport(format!(
                    "signature request {} still {:?} after {attempts} status reads",
                    request.id, request.status
                )));
            }
            attempts += 1;
            std::thread::sleep(self.config.poll_interval);
            request = self.get_signature(key, &request.id)?;
        }
        Ok(request)
    }
}

impl KeyKeeper for DfnsKeyKeeper {
    fn sign(&self, key: &KeyId, payload: &Payload) -> Result<Signature, SignError> {
        let request = self.settle(key, self.generate_signature(key, &request_for(payload))?)?;
        match request.status {
            SignatureStatus::Signed | SignatureStatus::Confirmed => {
                let components = request.signature.ok_or_else(|| {
                    SignError::MalformedResponse(format!(
                        "signature request {} is {:?} but carries no signature",
                        request.id, request.status
                    ))
                })?;
                signature_bytes(&components).map(Signature)
            }
            SignatureStatus::Pending | SignatureStatus::Executing => {
                Err(SignError::PendingApproval {
                    request_id: request.id,
                    approval_id: request.approval_id,
                })
            }
            SignatureStatus::Rejected => Err(SignError::Rejected {
                request_id: Some(request.id),
                reason: request.reason,
            }),
            SignatureStatus::Failed => Err(SignError::Failed {
                request_id: Some(request.id),
                reason: request.reason,
            }),
        }
    }
}

impl fmt::Debug for DfnsKeyKeeper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DfnsKeyKeeper")
            .field("base_url", &self.config.base_url)
            .field("cred_id", &self.config.credential.cred_id)
            .finish_non_exhaustive()
    }
}

/// The Generate Signature body for `payload`.
#[must_use]
pub fn request_for(payload: &Payload) -> GenerateSignatureRequest {
    match payload {
        Payload::Hash(hash) => GenerateSignatureRequest::Hash {
            hash: hex0x(hash),
            taproot_merkle_root: None,
            network: None,
            blockchain_kind: None,
            external_id: None,
        },
        Payload::Message(bytes) => GenerateSignatureRequest::Message {
            message: hex0x(bytes),
            network: None,
            blockchain_kind: None,
            external_id: None,
        },
        Payload::StellarTransaction {
            network,
            envelope_xdr,
        } => GenerateSignatureRequest::Transaction {
            transaction: serde_json::Value::String(hex0x(envelope_xdr)),
            network: Some(network.dfns_name().to_owned()),
            blockchain_kind: None,
            external_id: None,
        },
    }
}

/// The signature bytes of a response: `encoded` when present, otherwise
/// `r || s` with each half left-padded to 32 bytes.
///
/// # Errors
///
/// If a component is not hex, or `r`/`s` is longer than 32 bytes.
pub fn signature_bytes(components: &SignatureComponents) -> Result<Vec<u8>, SignError> {
    if let Some(encoded) = &components.encoded {
        return unhex(encoded);
    }
    let mut out = Vec::with_capacity(64);
    for half in [&components.r, &components.s] {
        let bytes = unhex(half)?;
        if bytes.len() > 32 {
            return Err(SignError::MalformedResponse(format!(
                "signature component of {} bytes",
                bytes.len()
            )));
        }
        out.extend(std::iter::repeat_n(0u8, 32 - bytes.len()));
        out.extend(bytes);
    }
    Ok(out)
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn unhex(s: &str) -> Result<Vec<u8>, SignError> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s))
        .map_err(|e| SignError::MalformedResponse(format!("not hex: {e}")))
}

fn to_json(body: &impl Serialize) -> Result<String, SignError> {
    serde_json::to_string(body).map_err(|e| SignError::InvalidRequest(e.to_string()))
}

/// Decode a 2xx body as `T`, or map an error response onto [`SignError`].
fn read<T: DeserializeOwned>(
    response: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    key: Option<&KeyId>,
) -> Result<T, SignError> {
    let mut response = response.map_err(|e| SignError::Transport(e.to_string()))?;
    let status = response.status().as_u16();
    let text = response
        .body_mut()
        .read_to_string()
        .map_err(|e| SignError::Transport(e.to_string()))?;
    if (200..300).contains(&status) {
        return serde_json::from_str(&text)
            .map_err(|e| SignError::MalformedResponse(format!("{e}: {text}")));
    }
    let message = serde_json::from_str::<ErrorBody>(&text)
        .map(|b| b.error.message)
        .unwrap_or(text);
    Err(match (status, key) {
        (400, _) => SignError::InvalidRequest(message),
        (401 | 403, _) => SignError::Unauthorized(message),
        (404, Some(key)) => SignError::UnknownKey(key.clone()),
        _ => SignError::Backend { status, message },
    })
}
