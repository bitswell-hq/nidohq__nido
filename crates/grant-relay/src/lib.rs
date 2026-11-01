//! A `/relay` service that enforces an agent's grants before signing.
//!
//! It accepts the requests Nido's browser client sends to `/relay` (a host
//! function and its signed authorization entries) and answers with the
//! responses that client reads ([`protocol`]). Before the custody key signs
//! anything, the requesting agent's chain grant must allow every context of
//! the call's authorization trees and its signing grant must allow the
//! signature ([`relay`]). The transaction's source is one of a pool of
//! channel accounts ([`channels`]), each with master weight 0 and the custody
//! key as its only signer; the custody key signs through a
//! [`nido_key_keeper::KeyKeeper`].

pub mod actions;
pub mod channels;
pub mod config;
pub mod local;
pub mod protocol;
pub mod relay;
pub mod rpc;
pub mod server;

use std::fmt;

use serde_json::Value;

pub use config::{Config, ConfigFile};
pub use relay::Relay;
pub use server::Server;

/// A refused or failed request: the HTTP status, a stable code, a message
/// and details, carried in the response as
/// `{"success": false, "data": {"code", "details"}, "error": message}`.
#[derive(Debug, Clone, PartialEq)]
pub struct RelayError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    pub details: Value,
}

impl RelayError {
    #[must_use]
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            details: Value::Null,
        }
    }

    #[must_use]
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }

    /// `400 INVALID_PARAMS`.
    #[must_use]
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(400, "INVALID_PARAMS", message)
    }

    /// `401 UNAUTHORIZED`.
    #[must_use]
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(401, "UNAUTHORIZED", message)
    }

    /// `502 RPC_UNAVAILABLE`.
    #[must_use]
    pub fn rpc(error: &rpc::RpcError) -> Self {
        Self::new(502, "RPC_UNAVAILABLE", format!("Soroban RPC: {error}"))
    }

    /// `500 INTERNAL`.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(500, "INTERNAL", message)
    }
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.status, self.code, self.message)
    }
}

impl std::error::Error for RelayError {}
