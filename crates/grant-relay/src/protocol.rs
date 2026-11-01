//! The `/relay` wire protocol: the request bodies Nido's browser client
//! (`packages/passkey-sdk/src/relayer.ts`) sends, and the response bodies it
//! reads.
//!
//! Requests are `{"params": …}` with one of two shapes:
//!
//! ```json
//! {"params": {"func": "<HostFunction XDR, base64>", "auth": ["<SorobanAuthorizationEntry XDR, base64>"], "skipWait": true}}
//! {"params": {"getTransaction": {"transactionId": "<id>"}}}
//! ```
//!
//! A success is `{"success": true, "data": {"transactionId", "hash", "status"}, "error": null}`.
//! A failure is `{"success": false, "data": {"code", "details"}, "error": "<message>"}`
//! with a non-2xx status. The client throws `RelayerError(error, code, details)`
//! on a failure and polls `getTransaction` until `status` is `confirmed`,
//! `failed` or `expired`.

use serde::Serialize;
use serde_json::{json, Map, Value};
use stellar_xdr::{HostFunction, Limits, ReadXdr, SorobanAuthorizationEntry};

use crate::RelayError;

/// XDR decoding limits for request fields: nesting depth and total length.
pub const XDR_LIMITS: Limits = Limits {
    depth: 200,
    len: MAX_BODY_BYTES,
};

/// The largest request body the relay reads.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// A parsed `/relay` request.
#[derive(Debug)]
pub enum Request {
    /// Relay this host function with these authorization entries.
    Submit {
        func: HostFunction,
        auth: Vec<SorobanAuthorizationEntry>,
        /// Answer once the transaction is submitted instead of once it
        /// settles. Absent means `false`.
        skip_wait: bool,
    },
    /// Report the status of a transaction this agent submitted.
    GetTransaction { transaction_id: String },
}

/// The status of a relayed transaction, as the client names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Sent to the network and not yet settled.
    Submitted,
    /// Included in a ledger and successful.
    Confirmed,
    /// Included in a ledger and failed.
    Failed,
    /// Its validity window closed before any ledger included it.
    Expired,
}

impl Status {
    /// Whether the status is final.
    #[must_use]
    pub fn is_terminal(self) -> bool {
        !matches!(self, Status::Submitted)
    }
}

/// The `data` of a successful response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxResponse {
    pub transaction_id: String,
    /// The transaction hash, hex.
    pub hash: String,
    pub status: Status,
}

/// Parse a request body.
///
/// # Errors
///
/// `INVALID_PARAMS` for anything but the two documented shapes, with the
/// same strictness as the Channels plugin: unknown keys are refused.
pub fn parse_request(body: &[u8]) -> Result<Request, RelayError> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|e| RelayError::invalid(format!("Request body is not JSON: {e}")))?;
    let Some(params) = value.get("params").and_then(Value::as_object) else {
        return Err(RelayError::invalid(
            "Invalid request: params must be an object",
        ));
    };
    if let Some(gt) = params.get("getTransaction") {
        only_keys(params, &["getTransaction"])?;
        let id = gt
            .as_object()
            .filter(|o| o.len() == 1)
            .and_then(|o| o.get("transactionId"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                RelayError::invalid(
                    "`getTransaction` must be {\"transactionId\": <non-empty string>}",
                )
            })?;
        return Ok(Request::GetTransaction {
            transaction_id: id.to_owned(),
        });
    }
    if params.contains_key("xdr") {
        return Err(RelayError::invalid(
            "Signed-XDR submission is not supported: send `func` and `auth`",
        ));
    }
    if params.contains_key("func") || params.contains_key("auth") {
        only_keys(params, &["func", "auth", "skipWait"])?;
        let func = params
            .get("func")
            .and_then(Value::as_str)
            .ok_or_else(|| RelayError::invalid("`func` and `auth` are both required"))?;
        let auth = params
            .get("auth")
            .and_then(Value::as_array)
            .ok_or_else(|| RelayError::invalid("`auth` must be an array of base64 strings"))?;
        let skip_wait = match params.get("skipWait") {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return Err(RelayError::invalid("`skipWait` must be a boolean")),
        };
        let func = HostFunction::from_xdr_base64(func, XDR_LIMITS)
            .map_err(|e| RelayError::invalid(format!("Invalid `func` encoding: {e}")))?;
        let auth = auth
            .iter()
            .map(|a| {
                let a = a.as_str().ok_or_else(|| {
                    RelayError::invalid("`auth` must be an array of base64 strings")
                })?;
                SorobanAuthorizationEntry::from_xdr_base64(a, XDR_LIMITS)
                    .map_err(|e| RelayError::invalid(format!("Invalid `auth` encoding: {e}")))
            })
            .collect::<Result<_, _>>()?;
        return Ok(Request::Submit {
            func,
            auth,
            skip_wait,
        });
    }
    Err(RelayError::invalid(
        "Must pass `func` and `auth`, or `getTransaction`",
    ))
}

fn only_keys(params: &Map<String, Value>, allowed: &[&str]) -> Result<(), RelayError> {
    let unknown: Vec<&String> = params
        .keys()
        .filter(|k| !allowed.contains(&k.as_str()))
        .collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(
            RelayError::invalid(format!("Unexpected parameters: {unknown:?}"))
                .with_details(json!({ "unknown": unknown })),
        )
    }
}

/// The body of a successful response.
#[must_use]
pub fn success_body(data: &TxResponse) -> Value {
    json!({ "success": true, "data": data, "error": null })
}

/// The body of a failed response.
#[must_use]
pub fn error_body(error: &RelayError) -> Value {
    json!({
        "success": false,
        "data": { "code": error.code, "details": error.details },
        "error": error.message,
    })
}
