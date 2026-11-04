//! An agent host that enforces grants on an agent's tool calls.
//!
//! The host holds each agent's grant ([`grant::Grants`]) and is the only
//! path from the agent's tool calls to the file system ([`fs`]), the network
//! ([`net`]) and the key keeper ([`sign`]). Every check runs through the
//! grant evaluator compiled to a WebAssembly component ([`evaluator`]): the
//! `grant-eval` crate the Soroban smart account's `__check_auth` also runs,
//! built for the same `wasm32v1-none` target. `README.md` describes the
//! wiring and what is trusted.
#![forbid(unsafe_code)]

pub mod actions;
pub mod bench;
pub mod evaluator;
pub mod fs;
pub mod grant;
pub mod host;
pub mod native;
pub mod net;
pub mod sign;
pub mod workload;

pub use host::{AgentId, CallError, Host, Output, ToolCall, Vocabulary};
