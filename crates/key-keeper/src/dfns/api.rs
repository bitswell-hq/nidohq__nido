//! Wire types of the Dfns endpoints this crate uses, as the Dfns `OpenAPI`
//! document (`https://docs.dfns.co/openapi.yaml`, version 2.0.368) defines
//! them:
//!
//! - `POST /keys/{keyId}/signatures` (Generate Signature): request
//!   [`GenerateSignatureRequest`], response [`SignatureRequest`].
//! - `GET /keys/{keyId}/signatures/{signatureId}` (Get Signature): response
//!   [`SignatureRequest`].
//! - `POST /keys` (Create Key): request [`CreateKeyRequest`], response
//!   [`Key`].
//! - `POST /auth/action/init` (Create User Action Challenge): request
//!   [`UserActionChallengeRequest`], response [`UserActionChallenge`].
//! - `POST /auth/action` (Create User Action Signature): request
//!   [`UserActionSignatureRequest`], response [`UserActionSignature`].
//! - Every error: [`ErrorBody`].
//!
//! Request types reject unknown fields (the schemas set
//! `additionalProperties: false`). Response types accept them, so a client
//! keeps working when Dfns adds response fields.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Generate Signature request body. Only the kinds an Ed25519 Stellar key can
/// use are typed here; [`SIGNATURE_KINDS`] lists every documented kind.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields, rename_all_fields = "camelCase")]
pub enum GenerateSignatureRequest {
    /// `hash`: 32 bytes, hex (`^(0x)?[0-9a-fA-F]{64}$`).
    Hash {
        hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        taproot_merkle_root: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blockchain_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_id: Option<String>,
    },
    /// `message`: arbitrary bytes, hex (`^(0x)?([0-9a-fA-F][0-9a-fA-F])*$`).
    Message {
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blockchain_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_id: Option<String>,
    },
    /// `transaction`: the unsigned transaction, hex, or a JSON object on the
    /// networks that take one (Concordium, Starknet, EVM). For Stellar it is
    /// the hex `TransactionEnvelope` XDR and `network` names the network.
    Transaction {
        transaction: Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blockchain_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_id: Option<String>,
    },
    /// Documented with field names and types only.
    StellarFeeBumpTransaction {
        inner_transaction: String,
        transaction_reference: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        network: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blockchain_kind: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        external_id: Option<String>,
    },
}

impl GenerateSignatureRequest {
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Hash { .. } => "Hash",
            Self::Message { .. } => "Message",
            Self::Transaction { .. } => "Transaction",
            Self::StellarFeeBumpTransaction { .. } => "StellarFeeBumpTransaction",
        }
    }

    #[must_use]
    pub fn network(&self) -> Option<&str> {
        match self {
            Self::Hash { network, .. }
            | Self::Message { network, .. }
            | Self::Transaction { network, .. }
            | Self::StellarFeeBumpTransaction { network, .. } => network.as_deref(),
        }
    }

    #[must_use]
    pub fn blockchain_kind(&self) -> Option<&str> {
        match self {
            Self::Hash {
                blockchain_kind, ..
            }
            | Self::Message {
                blockchain_kind, ..
            }
            | Self::Transaction {
                blockchain_kind, ..
            }
            | Self::StellarFeeBumpTransaction {
                blockchain_kind, ..
            } => blockchain_kind.as_deref(),
        }
    }

    #[must_use]
    pub fn external_id(&self) -> Option<&str> {
        match self {
            Self::Hash { external_id, .. }
            | Self::Message { external_id, .. }
            | Self::Transaction { external_id, .. }
            | Self::StellarFeeBumpTransaction { external_id, .. } => external_id.as_deref(),
        }
    }
}

/// `SignatureRequest.status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureStatus {
    Pending,
    Executing,
    Signed,
    Confirmed,
    Failed,
    Rejected,
}

/// A signature, hex-encoded components. For Ed25519, `encoded` is the raw
/// 64-byte `r || s`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignatureComponents {
    pub r: String,
    pub s: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recid: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoded: Option<String>,
}

/// `Requester`: who created the request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Requester {
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
}

/// `SignatureRequest`: the Generate Signature and Get Signature response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureRequest {
    pub id: String,
    pub key_id: String,
    pub requester: Requester,
    pub request_body: Value,
    pub status: SignatureStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureComponents>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures: Option<Vec<SignatureComponents>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    pub date_requested: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_policy_resolved: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_signed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_confirmed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Create Key request body.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateKeyRequest {
    /// `ECDSA`, `EdDSA` or `Schnorr`.
    pub scheme: String,
    /// `ed25519`, `secp256k1` or `stark`.
    pub curve: String,
    /// At most 100 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_key: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derive_from: Option<DeriveFrom>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegate_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_delegation: Option<bool>,
}

impl CreateKeyRequest {
    /// An Ed25519 key (`EdDSA` over `ed25519`), the kind Stellar accounts use.
    #[must_use]
    pub fn ed25519(name: Option<&str>) -> Self {
        Self {
            scheme: "EdDSA".to_owned(),
            curve: "ed25519".to_owned(),
            name: name.map(str::to_owned),
            ..Self::default()
        }
    }
}

/// `deriveFrom`: hierarchical derivation from a master key.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeriveFrom {
    pub key_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// `Key`: the Create Key response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Key {
    pub id: String,
    pub scheme: String,
    pub curve: String,
    /// Hex-encoded public key.
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub master_key: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `Active` or `Archived`.
    pub status: String,
    pub custodial: bool,
    pub date_created: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub imported: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exported: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_exported: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub date_deleted: Option<String>,
}

/// Create User Action Challenge request: the exact call the user action
/// token will authorize.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserActionChallengeRequest {
    /// `POST`, `PUT`, `DELETE` or `GET`.
    pub user_action_http_method: String,
    pub user_action_http_path: String,
    /// The request body, as the exact string that will be sent.
    pub user_action_payload: String,
    /// `Api` when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_action_server_kind: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AllowedCredential {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowCredentials {
    pub key: Vec<AllowedCredential>,
    pub webauthn: Vec<AllowedCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_protected_key: Option<Vec<Value>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedCredentialKind {
    pub kind: String,
    pub factor: String,
    pub requires_second_factor: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RelyingParty {
    pub id: String,
    pub name: String,
}

/// Create User Action Challenge response.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserActionChallenge {
    pub challenge: String,
    pub challenge_identifier: String,
    pub supported_credential_kinds: Vec<SupportedCredentialKind>,
    pub user_verification: String,
    pub attestation: String,
    pub allow_credentials: AllowCredentials,
    pub external_authentication_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rp: Option<RelyingParty>,
}

/// A `Key` credential assertion: `signature` (base64url) over the
/// `clientData` bytes (base64url).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyAssertion {
    pub cred_id: String,
    pub client_data: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
}

/// The first factor of a user action signature. Only `Key` (the credential
/// kind of service accounts and personal access tokens) is typed.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields, rename_all_fields = "camelCase")]
pub enum FirstFactor {
    Key { credential_assertion: KeyAssertion },
}

/// Create User Action Signature request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UserActionSignatureRequest {
    pub challenge_identifier: String,
    pub first_factor: FirstFactor,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub second_factor: Option<Value>,
}

/// Create User Action Signature response: the value of the
/// `X-DFNS-USERACTION` header.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserActionSignature {
    pub user_action: String,
}

/// Every Dfns error response: `{"error": {...}}`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub id: String,
    pub status: u16,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

// The enums below are copied from the `OpenAPI` document (version 2.0.368).

/// Every documented Generate Signature `kind`.
pub const SIGNATURE_KINDS: &[&str] = &[
    "Hash",
    "Message",
    "Transaction",
    "Eip191",
    "Eip712",
    "Eip7702",
    "Snip12",
    "Psbt",
    "Bip322",
    "SignDocDirect",
    "SignerPayload",
    "Cip8",
    "DfnsSmartAccountTransaction",
    "StellarFeeBumpTransaction",
];

/// Every documented `Network` value.
pub const NETWORKS: &[&str] = &[
    "Algorand",
    "AlgorandTestnet",
    "Aptos",
    "AptosTestnet",
    "ArbitrumOne",
    "ArbitrumSepolia",
    "Arc",
    "ArcTestnet",
    "Areum",
    "AvalancheC",
    "AvalancheCFuji",
    "Base",
    "BaseSepolia",
    "Berachain",
    "BerachainBepolia",
    "Bitcoin",
    "BitcoinSignet",
    "BitcoinTestnet4",
    "BitcoinCash",
    "Bob",
    "BobSepolia",
    "Bsc",
    "BscTestnet",
    "Canton",
    "CantonTestnet",
    "Cardano",
    "CardanoPreprod",
    "Concordium",
    "ConcordiumTestnet",
    "Celo",
    "CeloSepolia",
    "Codex",
    "CodexSepolia",
    "CosmosHub4",
    "CosmosIcsTestnet",
    "Dogecoin",
    "DogecoinTestnet",
    "Ethereum",
    "EthereumClassic",
    "EthereumClassicMordor",
    "EthereumSepolia",
    "EthereumHoodi",
    "FlareC",
    "FlareCCoston2",
    "FlowEvm",
    "FlowEvmTestnet",
    "Hedera",
    "HederaTestnet",
    "HyperEvm",
    "HyperEvmTestnet",
    "Ink",
    "InkSepolia",
    "InternetComputer",
    "Ion",
    "IonTestnet",
    "Iota",
    "IotaTestnet",
    "Kusama",
    "KusamaAssetHub",
    "Litecoin",
    "LitecoinTestnet",
    "Monad",
    "MonadTestnet",
    "Movement",
    "MovementTestnet",
    "Near",
    "NearTestnet",
    "Optimism",
    "OptimismSepolia",
    "Origyn",
    "Plasma",
    "PlasmaTestnet",
    "Plume",
    "PlumeSepolia",
    "Paseo",
    "PaseoAssetHub",
    "Polkadot",
    "PolkadotAssetHub",
    "Polygon",
    "PolygonAmoy",
    "Polymesh",
    "PolymeshTestnet",
    "Rayls",
    "RaylsTestnet",
    "Robinhood",
    "RobinhoodSepolia",
    "SeiAtlantic2",
    "SeiPacific1",
    "Solana",
    "SolanaDevnet",
    "Sonic",
    "SonicTestnet",
    "Starknet",
    "StarknetSepolia",
    "Stellar",
    "StellarTestnet",
    "Sui",
    "SuiTestnet",
    "Tezos",
    "TezosShadownet",
    "Tempo",
    "TempoModerato",
    "Tsc",
    "TscTestnet1",
    "Ton",
    "TonTestnet",
    "Tron",
    "TronNile",
    "Westend",
    "WestendAssetHub",
    "Xdc",
    "XdcApothem",
    "XLayer",
    "XLayerSepolia",
    "XrpLedger",
    "XrpLedgerTestnet",
];

/// Every documented `BlockchainKind` value.
pub const BLOCKCHAIN_KINDS: &[&str] = &[
    "Algorand",
    "Aptos",
    "Bitcoin",
    "BitcoinCash",
    "Canton",
    "Cardano",
    "Concordium",
    "Cosmos",
    "Evm",
    "Hedera",
    "Icp",
    "Iota",
    "Kaspa",
    "Near",
    "Polymesh",
    "Solana",
    "Starknet",
    "Stellar",
    "Substrate",
    "Sui",
    "Tezos",
    "Ton",
    "Tron",
    "Xrpl",
];

/// Every documented `KeyScheme`.
pub const KEY_SCHEMES: &[&str] = &["ECDSA", "EdDSA", "Schnorr"];

/// Every documented `KeyCurve`.
pub const KEY_CURVES: &[&str] = &["ed25519", "secp256k1", "stark"];
