//! A local stand-in for the Dfns endpoints [`super::DfnsKeyKeeper`] calls,
//! signing with Ed25519 keys it holds in memory.
//!
//! Routes:
//!
//! | Route | Auth |
//! | - | - |
//! | `POST /auth/action/init` | bearer |
//! | `POST /auth/action` | bearer |
//! | `POST /keys/{keyId}/signatures` | bearer + `X-DFNS-USERACTION` |
//! | `GET /keys/{keyId}/signatures/{signatureId}` | bearer |
//!
//! Request bodies must match the documented schemas exactly (unknown fields,
//! missing fields, wrong types and pattern violations are `400`). Errors use
//! the documented `{"error": {"id", "status", "message", "details"}}` body
//! and the documented statuses: `400` invalid body, `401` missing, malformed
//! or unknown bearer token, `403` missing `X-DFNS-USERACTION`, `404` unknown
//! key or signature, `409` an `externalId` reused with a different request.
//!
//! Where the reference states no behavior, the mock picks one and the crate
//! README lists each choice: the status for an invalid (rather than missing)
//! user action token or credential signature, the scope of its keys (Stellar
//! networks only), and the kinds it does not implement.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature as EdSignature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::api::{
    AllowCredentials, AllowedCredential, ErrorBody, ErrorDetail, FirstFactor,
    GenerateSignatureRequest, Requester, SignatureComponents, SignatureRequest, SignatureStatus,
    SupportedCredentialKind, UserActionChallenge, UserActionChallengeRequest, UserActionSignature,
    UserActionSignatureRequest, BLOCKCHAIN_KINDS, NETWORKS, SIGNATURE_KINDS,
};
use crate::{ed25519, stellar, Payload, SignError, StellarNetwork};

/// Largest request body the mock reads.
const MAX_BODY: u64 = 1 << 20;

/// Who and what the mock serves. Deserializes from the `dfns-mock` config
/// file.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MockConfig {
    pub tokens: Vec<MockToken>,
    pub keys: Vec<MockKey>,
}

/// A bearer token and the `Key` credentials that sign its user actions.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MockToken {
    pub token: String,
    pub user_id: String,
    #[serde(default)]
    pub token_id: Option<String>,
    pub credentials: Vec<MockCredential>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MockCredential {
    pub cred_id: String,
    /// Ed25519 public key, hex.
    pub public_key: String,
}

/// A signing key: its Dfns key id and Ed25519 secret seed (hex).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MockKey {
    pub key_id: String,
    pub seed: String,
}

impl MockConfig {
    /// Add a signing key.
    #[must_use]
    pub fn with_key(mut self, key_id: &str, seed: [u8; 32]) -> Self {
        self.keys.push(MockKey {
            key_id: key_id.to_owned(),
            seed: hex::encode(seed),
        });
        self
    }

    /// Add a bearer token whose user actions `credential` signs.
    #[must_use]
    pub fn with_token(
        mut self,
        token: &str,
        user_id: &str,
        cred_id: &str,
        credential: &VerifyingKey,
    ) -> Self {
        self.tokens.push(MockToken {
            token: token.to_owned(),
            user_id: user_id.to_owned(),
            token_id: None,
            credentials: vec![MockCredential {
                cred_id: cred_id.to_owned(),
                public_key: hex::encode(credential.to_bytes()),
            }],
        });
        self
    }
}

/// A running mock, serving until dropped.
pub struct MockServer {
    url: String,
    server: Arc<tiny_http::Server>,
    thread: Option<JoinHandle<()>>,
}

impl MockServer {
    /// Bind `addr` (for example `127.0.0.1:0`) and serve `config`.
    ///
    /// # Errors
    ///
    /// If the config holds a malformed key or credential, or `addr` cannot
    /// be bound.
    pub fn start(config: &MockConfig, addr: &str) -> std::io::Result<Self> {
        let mut mock = Mock::new(config).map_err(std::io::Error::other)?;
        let server = Arc::new(tiny_http::Server::http(addr).map_err(std::io::Error::other)?);
        let bound = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| std::io::Error::other("not an IP listener"))?;
        let url = format!("http://{bound}");
        let thread = {
            let server = Arc::clone(&server);
            std::thread::spawn(move || {
                for request in server.incoming_requests() {
                    serve(&mut mock, request);
                }
            })
        };
        Ok(Self {
            url,
            server,
            thread: Some(thread),
        })
    }

    /// The mock's base URL, for [`super::DfnsConfig::base_url`].
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Serve until the process ends.
    pub fn wait(mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.server.unblock();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(mock: &mut Mock, mut request: tiny_http::Request) {
    let method = request.method().as_str().to_owned();
    let path = request.url().split('?').next().unwrap_or("").to_owned();
    let header = |name: &'static str| {
        request
            .headers()
            .iter()
            .find(|h| h.field.equiv(name))
            .map(|h| h.value.as_str().to_owned())
    };
    let headers = Headers {
        authorization: header("Authorization"),
        user_action: header("X-DFNS-USERACTION"),
    };
    let mut body = String::new();
    let (status, text) = match request.as_reader().take(MAX_BODY).read_to_string(&mut body) {
        Ok(_) => mock.handle(&method, &path, &headers, &body),
        Err(_) => Reply::error(400, "request body is not UTF-8", None),
    };
    let response = tiny_http::Response::from_string(text)
        .with_status_code(status)
        .with_header(
            tiny_http::Header::from_bytes("Content-Type", "application/json")
                .expect("static header"),
        );
    let _ = request.respond(response);
}

/// The headers the mock reads.
#[derive(Clone, Debug, Default)]
pub struct Headers {
    pub authorization: Option<String>,
    pub user_action: Option<String>,
}

type Reply = (u16, String);

trait ReplyExt {
    fn error(status: u16, message: &str, details: Option<Value>) -> Reply;
    fn ok(body: &impl Serialize) -> Reply;
}

impl ReplyExt for Reply {
    fn error(status: u16, message: &str, details: Option<Value>) -> Reply {
        let body = ErrorBody {
            error: ErrorDetail {
                id: random_digits(19),
                status,
                message: message.to_owned(),
                details,
            },
        };
        (
            status,
            serde_json::to_string(&body).expect("error body serializes"),
        )
    }

    fn ok(body: &impl Serialize) -> Reply {
        (
            200,
            serde_json::to_string(body).expect("response serializes"),
        )
    }
}

struct Caller {
    user_id: String,
    token_id: Option<String>,
    credentials: BTreeMap<String, VerifyingKey>,
}

/// The call a challenge or user action token authorizes.
#[derive(Clone, PartialEq, Eq)]
struct Action {
    token: String,
    method: String,
    path: String,
    payload: String,
}

/// The mock's state and request handling, independent of the transport.
pub struct Mock {
    tokens: BTreeMap<String, Caller>,
    keys: BTreeMap<String, SigningKey>,
    challenges: BTreeMap<String, (String, Action)>,
    user_actions: BTreeMap<String, Action>,
    signatures: BTreeMap<String, SignatureRequest>,
    /// `externalId` → (key id, request body, signature id).
    external_ids: BTreeMap<String, (String, Value, String)>,
}

impl Mock {
    /// # Errors
    ///
    /// If a key seed or credential public key in `config` is malformed.
    pub fn new(config: &MockConfig) -> Result<Self, String> {
        let mut keys = BTreeMap::new();
        for key in &config.keys {
            let seed: [u8; 32] = hex::decode(&key.seed)
                .ok()
                .and_then(|b| b.try_into().ok())
                .ok_or_else(|| format!("key {}: seed is not 32 hex bytes", key.key_id))?;
            keys.insert(key.key_id.clone(), SigningKey::from_bytes(&seed));
        }
        let mut tokens = BTreeMap::new();
        for token in &config.tokens {
            let mut credentials = BTreeMap::new();
            for cred in &token.credentials {
                let public: [u8; 32] = hex::decode(&cred.public_key)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| format!("credential {}: not 32 hex bytes", cred.cred_id))?;
                let public = VerifyingKey::from_bytes(&public)
                    .map_err(|e| format!("credential {}: {e}", cred.cred_id))?;
                credentials.insert(cred.cred_id.clone(), public);
            }
            tokens.insert(
                token.token.clone(),
                Caller {
                    user_id: token.user_id.clone(),
                    token_id: token.token_id.clone(),
                    credentials,
                },
            );
        }
        Ok(Self {
            tokens,
            keys,
            challenges: BTreeMap::new(),
            user_actions: BTreeMap::new(),
            signatures: BTreeMap::new(),
            external_ids: BTreeMap::new(),
        })
    }

    /// The public key of `key_id`, if the mock holds it.
    #[must_use]
    pub fn public_key(&self, key_id: &str) -> Option<[u8; 32]> {
        self.keys.get(key_id).map(|k| k.verifying_key().to_bytes())
    }

    /// Answer one request: `(status, JSON body)`.
    pub fn handle(&mut self, method: &str, path: &str, headers: &Headers, body: &str) -> Reply {
        let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let token = match self.bearer(headers) {
            Ok(token) => token,
            Err(reply) => return reply,
        };
        match (method, segments.as_slice()) {
            ("POST", ["auth", "action", "init"]) => self.create_challenge(&token, body),
            ("POST", ["auth", "action"]) => self.create_user_action(&token, body),
            ("POST", ["keys", key_id, "signatures"]) => {
                self.generate_signature(&token, method, path, headers, key_id, body)
            }
            ("GET", ["keys", key_id, "signatures", signature_id]) => {
                self.get_signature(key_id, signature_id)
            }
            _ => Reply::error(404, "route not found", Some(json!({ "path": path }))),
        }
    }

    fn bearer(&self, headers: &Headers) -> Result<String, Reply> {
        let token = headers
            .authorization
            .as_deref()
            .and_then(|h| h.strip_prefix("Bearer "))
            .filter(|t| !t.is_empty())
            .ok_or_else(|| {
                Reply::error(401, "Authorization header is missing or malformed", None)
            })?;
        if !self.tokens.contains_key(token) {
            return Err(Reply::error(
                401,
                "authentication token is invalid or expired",
                None,
            ));
        }
        Ok(token.to_owned())
    }

    fn create_challenge(&mut self, token: &str, body: &str) -> Reply {
        let request: UserActionChallengeRequest = match parse(body) {
            Ok(r) => r,
            Err(reply) => return reply,
        };
        if !["POST", "PUT", "DELETE", "GET"].contains(&request.user_action_http_method.as_str()) {
            return Reply::error(
                400,
                "userActionHttpMethod must be POST, PUT, DELETE or GET",
                None,
            );
        }
        if request.user_action_http_path.is_empty() {
            return Reply::error(400, "userActionHttpPath must not be empty", None);
        }
        if request
            .user_action_server_kind
            .as_deref()
            .is_some_and(|k| k != "Api")
        {
            return Reply::error(400, "userActionServerKind must be Api", None);
        }
        let challenge = URL_SAFE_NO_PAD.encode(random_bytes::<32>());
        let challenge_identifier = URL_SAFE_NO_PAD.encode(random_bytes::<24>());
        let allowed = self.tokens[token]
            .credentials
            .keys()
            .map(|id| AllowedCredential {
                kind: "public-key".to_owned(),
                id: id.clone(),
            })
            .collect();
        self.challenges.insert(
            challenge_identifier.clone(),
            (
                challenge.clone(),
                Action {
                    token: token.to_owned(),
                    method: request.user_action_http_method,
                    path: request.user_action_http_path,
                    payload: request.user_action_payload,
                },
            ),
        );
        Reply::ok(&UserActionChallenge {
            challenge,
            challenge_identifier,
            supported_credential_kinds: vec![SupportedCredentialKind {
                kind: "Key".to_owned(),
                factor: "first".to_owned(),
                requires_second_factor: false,
            }],
            user_verification: "required".to_owned(),
            attestation: "none".to_owned(),
            allow_credentials: AllowCredentials {
                key: allowed,
                webauthn: Vec::new(),
                password_protected_key: None,
            },
            external_authentication_url: String::new(),
            rp: None,
        })
    }

    fn create_user_action(&mut self, token: &str, body: &str) -> Reply {
        let kind = serde_json::from_str::<Value>(body).ok().and_then(|v| {
            v.pointer("/firstFactor/kind")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        if let Some(kind) =
            kind.filter(|k| ["Fido2", "PasswordProtectedKey", "Password"].contains(&k.as_str()))
        {
            return Reply::error(
                400,
                &format!("first factor kind {kind} is not supported by this mock"),
                None,
            );
        }
        let request: UserActionSignatureRequest = match parse(body) {
            Ok(r) => r,
            Err(reply) => return reply,
        };
        let Some((challenge, action)) = self.challenges.remove(&request.challenge_identifier)
        else {
            return Reply::error(400, "challenge not found", None);
        };
        if action.token != token {
            return Reply::error(400, "challenge not found", None);
        }
        let FirstFactor::Key {
            credential_assertion: assertion,
        } = request.first_factor;
        let Some(public) = self.tokens[token].credentials.get(&assertion.cred_id) else {
            return Reply::error(401, "credential is not registered for this token", None);
        };
        if !client_data_signed(
            public,
            &challenge,
            &assertion.client_data,
            &assertion.signature,
        ) {
            return Reply::error(401, "Unable to verify signature", None);
        }
        let user_action = URL_SAFE_NO_PAD.encode(random_bytes::<32>());
        self.user_actions.insert(user_action.clone(), action);
        Reply::ok(&UserActionSignature { user_action })
    }

    fn generate_signature(
        &mut self,
        token: &str,
        method: &str,
        path: &str,
        headers: &Headers,
        key_id: &str,
        body: &str,
    ) -> Reply {
        let Some(user_action) = headers.user_action.as_deref() else {
            return Reply::error(403, "User action signature is missing", None);
        };
        // One-time: a presented token is spent whether or not it matches.
        let authorized = self.user_actions.remove(user_action);
        let presented = Action {
            token: token.to_owned(),
            method: method.to_owned(),
            path: path.to_owned(),
            payload: body.to_owned(),
        };
        if authorized.as_ref() != Some(&presented) {
            return Reply::error(
                403,
                "user action signature does not authorize this request",
                None,
            );
        }
        if key_id.is_empty() || key_id.len() > 64 {
            return Reply::error(400, "keyId must be 1 to 64 characters", None);
        }
        let (request, body_value) = match parse_signature_request(body) {
            Ok(r) => r,
            Err(reply) => return reply,
        };
        let Some(signing_key) = self.keys.get(key_id) else {
            return Reply::error(404, "key not found", Some(json!({ "keyId": key_id })));
        };
        if let Some(external_id) = request.external_id() {
            if let Some((prior_key, prior_body, prior_id)) = self.external_ids.get(external_id) {
                if prior_key == key_id && *prior_body == body_value {
                    return Reply::ok(&self.signatures[prior_id]);
                }
                return Reply::error(
                    409,
                    "Conflicting signature request with same externalId",
                    Some(json!({ "duplicate": { "id": prior_id, "externalId": external_id } })),
                );
            }
        }
        let payload = match payload_of(&request) {
            Ok(p) => p,
            Err(reply) => return reply,
        };
        let signature = match ed25519::sign(signing_key, &payload) {
            Ok(s) => s,
            Err(SignError::UnsupportedPayload(why)) => return Reply::error(400, &why, None),
            Err(e) => return Reply::error(500, &e.to_string(), None),
        };
        let now = iso8601_now();
        let caller = &self.tokens[token];
        let record = SignatureRequest {
            id: dfns_id("sig"),
            key_id: key_id.to_owned(),
            requester: Requester {
                user_id: caller.user_id.clone(),
                token_id: caller.token_id.clone(),
            },
            request_body: body_value.clone(),
            status: SignatureStatus::Signed,
            reason: None,
            signature: Some(SignatureComponents {
                r: format!("0x{}", hex::encode(&signature[..32])),
                s: format!("0x{}", hex::encode(&signature[32..])),
                recid: None,
                encoded: Some(format!("0x{}", hex::encode(signature))),
            }),
            signatures: None,
            signed_data: None,
            network: request.network().map(str::to_owned),
            tx_hash: None,
            fee: None,
            approval_id: None,
            date_requested: now.clone(),
            date_policy_resolved: None,
            date_signed: Some(now),
            date_confirmed: None,
            external_id: request.external_id().map(str::to_owned),
            details: None,
        };
        if let Some(external_id) = request.external_id() {
            self.external_ids.insert(
                external_id.to_owned(),
                (key_id.to_owned(), body_value, record.id.clone()),
            );
        }
        self.signatures.insert(record.id.clone(), record.clone());
        Reply::ok(&record)
    }

    fn get_signature(&self, key_id: &str, signature_id: &str) -> Reply {
        match self.signatures.get(signature_id) {
            Some(record) if record.key_id == key_id => Reply::ok(record),
            _ => Reply::error(
                404,
                "signature not found",
                Some(json!({ "keyId": key_id, "signatureId": signature_id })),
            ),
        }
    }
}

/// Parse a Generate Signature body: valid JSON, a documented `kind` this
/// mock implements, the kind's exact schema, and the schema's patterns and
/// enums.
fn parse_signature_request(body: &str) -> Result<(GenerateSignatureRequest, Value), Reply> {
    let value: Value =
        serde_json::from_str(body).map_err(|e| bad(&format!("malformed JSON body: {e}")))?;
    let kind = value
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("kind is required"))?;
    if !SIGNATURE_KINDS.contains(&kind) {
        return Err(bad(&format!("unknown signature kind {kind}")));
    }
    if ![
        "Hash",
        "Message",
        "Transaction",
        "StellarFeeBumpTransaction",
    ]
    .contains(&kind)
    {
        return Err(bad(&format!(
            "signature kind {kind} is not supported for EdDSA keys"
        )));
    }
    let request: GenerateSignatureRequest = serde_json::from_value(value.clone())
        .map_err(|e| bad(&format!("invalid {kind} request: {e}")))?;
    check_scope(&request)?;
    check_patterns(&request)?;
    Ok((request, value))
}

/// `network`, `blockchainKind` and `externalId`: documented values, and a
/// network this mock's (Stellar) keys sign for.
fn check_scope(request: &GenerateSignatureRequest) -> Result<(), Reply> {
    if let Some(network) = request.network() {
        if !NETWORKS.contains(&network) {
            return Err(bad(&format!("unknown network {network}")));
        }
        if StellarNetwork::from_dfns_name(network).is_none() {
            return Err(bad(&format!(
                "network {network} is not supported by this mock's Stellar keys"
            )));
        }
    }
    if let Some(kind) = request.blockchain_kind() {
        if !BLOCKCHAIN_KINDS.contains(&kind) {
            return Err(bad(&format!("unknown blockchainKind {kind}")));
        }
        if kind != "Stellar" {
            return Err(bad(&format!(
                "blockchainKind {kind} is not supported by this mock's Stellar keys"
            )));
        }
    }
    if request
        .external_id()
        .is_some_and(|id| id.is_empty() || id.chars().count() > 50)
    {
        return Err(bad("externalId must be 1 to 50 characters"));
    }
    Ok(())
}

/// The documented patterns of each kind's payload field.
fn check_patterns(request: &GenerateSignatureRequest) -> Result<(), Reply> {
    const HEX: &str = "^(0x)?([0-9a-fA-F][0-9a-fA-F])*$";
    match request {
        GenerateSignatureRequest::Hash {
            hash,
            taproot_merkle_root,
            ..
        } => {
            if hex_body(hash).is_none_or(|h| h.len() != 64) {
                return Err(bad("hash must match ^(0x)?[0-9a-fA-F]{64}$"));
            }
            if taproot_merkle_root
                .as_deref()
                .is_some_and(|r| hex_body(r).is_none_or(|h| !h.is_empty() && h.len() != 64))
            {
                return Err(bad(
                    "taprootMerkleRoot must match ^(0x)?([0-9A-Fa-f]{64})?$",
                ));
            }
        }
        GenerateSignatureRequest::Message { message, .. } => {
            if hex_body(message).is_none() {
                return Err(bad(&format!("message must match {HEX}")));
            }
        }
        GenerateSignatureRequest::Transaction { transaction, .. } => match transaction {
            Value::String(tx) if hex_body(tx).is_some() => {}
            Value::String(_) => return Err(bad(&format!("transaction must match {HEX}"))),
            Value::Object(_) => {
                return Err(bad(
                    "Stellar transactions must be hex-encoded, not JSON objects",
                ))
            }
            _ => return Err(bad("transaction must be a hex string or a JSON object")),
        },
        GenerateSignatureRequest::StellarFeeBumpTransaction { .. } => {}
    }
    Ok(())
}

fn bad(message: &str) -> Reply {
    Reply::error(400, message, None)
}

/// The payload a validated request signs.
fn payload_of(request: &GenerateSignatureRequest) -> Result<Payload, Reply> {
    let bytes = |s: &str| hex::decode(hex_body(s).unwrap_or_default()).unwrap_or_default();
    match request {
        GenerateSignatureRequest::Hash { hash, .. } => Ok(Payload::Hash(
            bytes(hash).try_into().expect("validated as 32 bytes"),
        )),
        GenerateSignatureRequest::Message { message, .. } => Ok(Payload::Message(bytes(message))),
        GenerateSignatureRequest::Transaction {
            transaction: Value::String(tx),
            network,
            ..
        } => {
            let network = network
                .as_deref()
                .and_then(StellarNetwork::from_dfns_name)
                .ok_or_else(|| {
                    Reply::error(
                        400,
                        "network is required to sign a Stellar transaction",
                        None,
                    )
                })?;
            Ok(Payload::StellarTransaction {
                network,
                envelope_xdr: bytes(tx),
            })
        }
        GenerateSignatureRequest::Transaction { .. } => {
            Err(Reply::error(400, "transaction must be a hex string", None))
        }
        GenerateSignatureRequest::StellarFeeBumpTransaction { .. } => Err(Reply::error(
            400,
            "StellarFeeBumpTransaction is not implemented by this mock",
            None,
        )),
    }
}

/// `s` without its optional `0x`, if the rest is an even number of hex
/// digits.
fn hex_body(s: &str) -> Option<&str> {
    let body = s.strip_prefix("0x").unwrap_or(s);
    (body.len().is_multiple_of(2) && body.bytes().all(|b| b.is_ascii_hexdigit())).then_some(body)
}

/// Whether `signature_b64` is `public`'s signature over the
/// `client_data_b64` bytes, and those bytes are a `key.get` client data
/// object for `challenge`.
fn client_data_signed(
    public: &VerifyingKey,
    challenge: &str,
    client_data_b64: &str,
    signature_b64: &str,
) -> bool {
    let Ok(client_data) = URL_SAFE_NO_PAD.decode(client_data_b64) else {
        return false;
    };
    let Ok(parsed) = serde_json::from_slice::<Value>(&client_data) else {
        return false;
    };
    if parsed.get("type").and_then(Value::as_str) != Some("key.get")
        || parsed.get("challenge").and_then(Value::as_str) != Some(challenge)
    {
        return false;
    }
    let Some(signature) = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .ok()
        .and_then(|b| EdSignature::from_slice(&b).ok())
    else {
        return false;
    };
    public.verify_strict(&client_data, &signature).is_ok()
}

fn parse<T: serde::de::DeserializeOwned>(body: &str) -> Result<T, Reply> {
    serde_json::from_str(body)
        .map_err(|e| Reply::error(400, &format!("invalid request body: {e}"), None))
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).expect("OS randomness");
    buf
}

fn random_digits(n: usize) -> String {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).expect("OS randomness");
    buf.iter().map(|b| char::from(b'0' + b % 10)).collect()
}

/// An id in Dfns's `{prefix}-xxxxx-xxxxx-xxxxxxxxxxxxxxxx` form.
fn dfns_id(prefix: &str) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let raw = random_bytes::<26>();
    let chars: String = raw
        .iter()
        .map(|b| char::from(ALPHABET[usize::from(*b) % ALPHABET.len()]))
        .collect();
    format!(
        "{prefix}-{}-{}-{}",
        &chars[..5],
        &chars[5..10],
        &chars[10..]
    )
}

fn iso8601_now() -> String {
    iso8601(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after 1970"),
    )
}

/// `since` the Unix epoch as UTC `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn iso8601(since: Duration) -> String {
    let secs = since.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        since.subsec_millis()
    )
}

/// The `G…` address of each key in `config`, for the `dfns-mock` banner.
///
/// # Errors
///
/// If a key seed is malformed.
pub fn key_addresses(config: &MockConfig) -> Result<Vec<(String, String)>, String> {
    let mock = Mock::new(config)?;
    Ok(mock
        .keys
        .iter()
        .map(|(id, key)| {
            (
                id.clone(),
                stellar::account_strkey(&key.verifying_key().to_bytes()),
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso8601_matches_known_instants() {
        for (millis, expected) in [
            (0, "1970-01-01T00:00:00.000Z"),
            (951_782_400_500, "2000-02-29T00:00:00.500Z"),
            (1_681_505_088_715, "2023-04-14T20:44:48.715Z"),
            (4_102_444_799_999, "2099-12-31T23:59:59.999Z"),
        ] {
            assert_eq!(iso8601(Duration::from_millis(millis)), expected);
        }
    }

    #[test]
    fn ids_have_the_documented_shape() {
        let id = dfns_id("sig");
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts[0], "sig");
        assert_eq!(
            parts[1..].iter().map(|p| p.len()).collect::<Vec<_>>(),
            [5, 5, 16]
        );
        assert!(id[4..]
            .bytes()
            .all(|b| b == b'-' || b.is_ascii_lowercase() || b.is_ascii_digit()));
    }

    #[test]
    fn hex_body_accepts_the_documented_patterns() {
        assert_eq!(hex_body("0xabCD"), Some("abCD"));
        assert_eq!(hex_body("abcd"), Some("abcd"));
        assert_eq!(hex_body(""), Some(""));
        assert_eq!(hex_body("0xabc"), None);
        assert_eq!(hex_body("0xzz"), None);
    }
}
