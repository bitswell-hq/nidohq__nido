//! Grants as the host holds them.
//!
//! A [`Grants`] is one caveat list per vocabulary the host's tools act in.
//! The JSON form follows `grant-relay`'s configuration:
//!
//! ```json
//! {
//!   "files":   [{"path_under": "/srv/work"}, {"mode_in": ["read"]}],
//!   "network": [{"host_in": ["api.example.com"]}, {"scheme_in": ["https"]}],
//!   "signing": [{"key_in": ["key-a"]}, {"network_in": ["Test SDF Network ; September 2015"]}],
//!   "chain":   [{"contract_in": ["C…"]}, {"function_in": ["transfer"]}, {"arg_i128_at_most": [2, "1000"]}]
//! }
//! ```
//!
//! The chain list is checked when the agent asks for a transaction or an
//! authorization entry to be signed: every context the signature would
//! authorize must pass it (see [`crate::sign`]).
//!
//! An empty list allows every action of that vocabulary, as an empty grant
//! does in the evaluator.
//!
//! A `path_under` prefix goes through the same resolution as a requested
//! path ([`crate::fs::resolve`]) once, when the grant is issued or the caveat
//! is added by a delegation, so it names the directory a requested path
//! resolves into (on macOS, `/tmp/x` is `/private/tmp/x`). A delegation
//! keeps the parent's caveats as they were resolved.

use std::io;
use std::path::Path;

use grant_eval::chain;
use serde::Deserialize;

pub use grant_relay::config::{ChainCaveatFile as ChainCaveat, I128Text, ValFile};

use crate::evaluator::wit;
use crate::{fs, native};

/// The caveat lists of one agent.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grants {
    #[serde(default)]
    pub files: Vec<FileCaveat>,
    #[serde(default)]
    pub network: Vec<NetworkCaveat>,
    #[serde(default)]
    pub signing: Vec<SigningCaveat>,
    /// In `grant-relay`'s form.
    #[serde(default)]
    pub chain: Vec<ChainCaveat>,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FileCaveat {
    /// An absolute path; resolved when the grant is issued or delegated.
    PathUnder(String),
    ModeIn(Vec<Mode>),
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Scheme {
    Http,
    Https,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NetworkCaveat {
    HostIn(Vec<String>),
    PortIn(Vec<u16>),
    SchemeIn(Vec<Scheme>),
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Payload {
    Transaction,
    AuthEntry,
    Message,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SigningCaveat {
    KeyIn(Vec<String>),
    /// Network passphrases, as `grant-relay` names networks.
    NetworkIn(Vec<String>),
    PayloadIn(Vec<Payload>),
}

impl Grants {
    /// The caveats as evaluator-component values, with every `path_under`
    /// prefix resolved.
    ///
    /// # Errors
    ///
    /// If a `path_under` prefix is not absolute or does not resolve, or a
    /// chain caveat is malformed.
    pub fn lower(&self) -> io::Result<Lowered> {
        Ok(Lowered {
            files: self
                .files
                .iter()
                .map(lower_file_caveat)
                .collect::<io::Result<_>>()?,
            network: self.network.iter().map(lower_network_caveat).collect(),
            signing: self.signing.iter().map(lower_signing_caveat).collect(),
            chain: self
                .chain
                .iter()
                .map(lower_chain_caveat)
                .collect::<io::Result<_>>()?,
        })
    }
}

/// A grant as the evaluator component takes it, with paths resolved.
#[derive(Clone)]
pub struct Lowered {
    pub files: Vec<wit::files::Caveat>,
    pub network: Vec<wit::network::Caveat>,
    pub signing: Vec<wit::signing::Caveat>,
    pub chain: Vec<wit::chain::Caveat>,
}

impl Lowered {
    /// `self`'s caveats followed by `extra`'s: the grant a delegation hands
    /// a sub-agent. Every caveat of `self` is kept as it was resolved, so the
    /// result allows at most what `self` allows.
    #[must_use]
    pub fn narrowed_by(&self, extra: Lowered) -> Lowered {
        let mut out = self.clone();
        out.files.extend(extra.files);
        out.network.extend(extra.network);
        out.signing.extend(extra.signing);
        out.chain.extend(extra.chain);
        out
    }
}

fn bytes_list(list: &[String]) -> Vec<Vec<u8>> {
    list.iter().map(|s| s.as_bytes().to_vec()).collect()
}

pub(crate) fn lower_mode(m: Mode) -> wit::files::Mode {
    match m {
        Mode::Read => wit::files::Mode::Read,
        Mode::Write => wit::files::Mode::Write,
        Mode::Execute => wit::files::Mode::Execute,
    }
}

fn lower_file_caveat(c: &FileCaveat) -> io::Result<wit::files::Caveat> {
    Ok(match c {
        FileCaveat::PathUnder(prefix) => {
            wit::files::Caveat::PathUnder(fs::components(&fs::resolve(Path::new(prefix))?))
        }
        FileCaveat::ModeIn(list) => {
            wit::files::Caveat::ModeIn(list.iter().copied().map(lower_mode).collect())
        }
    })
}

pub(crate) fn lower_scheme(s: Scheme) -> wit::network::Scheme {
    match s {
        Scheme::Http => wit::network::Scheme::Http,
        Scheme::Https => wit::network::Scheme::Https,
    }
}

fn lower_network_caveat(c: &NetworkCaveat) -> wit::network::Caveat {
    match c {
        NetworkCaveat::HostIn(list) => wit::network::Caveat::HostIn(bytes_list(list)),
        NetworkCaveat::PortIn(list) => wit::network::Caveat::PortIn(list.clone()),
        NetworkCaveat::SchemeIn(list) => {
            wit::network::Caveat::SchemeIn(list.iter().copied().map(lower_scheme).collect())
        }
    }
}

pub(crate) fn lower_payload(p: Payload) -> wit::signing::Payload {
    match p {
        Payload::Transaction => wit::signing::Payload::Transaction,
        Payload::AuthEntry => wit::signing::Payload::AuthEntry,
        Payload::Message => wit::signing::Payload::Message,
    }
}

fn lower_signing_caveat(c: &SigningCaveat) -> wit::signing::Caveat {
    match c {
        SigningCaveat::KeyIn(list) => wit::signing::Caveat::KeyIn(bytes_list(list)),
        SigningCaveat::NetworkIn(list) => wit::signing::Caveat::NetworkIn(bytes_list(list)),
        SigningCaveat::PayloadIn(list) => {
            wit::signing::Caveat::PayloadIn(list.iter().copied().map(lower_payload).collect())
        }
    }
}

fn lower_chain_caveat(c: &ChainCaveat) -> io::Result<wit::chain::Caveat> {
    let caveat = crate::actions::chain_caveat(c)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(match caveat {
        chain::Caveat::ContractIn(list) => wit::chain::Caveat::ContractIn(list),
        chain::Caveat::FunctionIn(list) => wit::chain::Caveat::FunctionIn(list),
        chain::Caveat::ArgI128AtMost(index, bound) => {
            wit::chain::Caveat::ArgI128AtMost((index, native::int128(bound)))
        }
        chain::Caveat::ArgEq(index, v) => wit::chain::Caveat::ArgEq((index, lower_val(v))),
    })
}

fn lower_val(v: chain::Val) -> wit::chain::Val {
    match v {
        chain::Val::I128(n) => wit::chain::Val::Int128(native::int128(n)),
        chain::Val::U64(n) => wit::chain::Val::U64(n),
        chain::Val::Bool(b) => wit::chain::Val::Bool(b),
        chain::Val::Bytes(b) => wit::chain::Val::Bytes(b),
        chain::Val::Address(b) => wit::chain::Val::Address(b),
        chain::Val::Symbol(b) => wit::chain::Val::Symbol(b),
        chain::Val::Other(b) => wit::chain::Val::Other(b),
    }
}

/// A chain action as the evaluator component takes it.
pub(crate) fn lower_chain_action(a: chain::Action) -> wit::chain::Action {
    match a {
        chain::Action::Invoke {
            contract,
            function,
            args,
        } => wit::chain::Action::Invoke(wit::chain::Invocation {
            contract,
            function,
            args: args.into_iter().map(lower_val).collect(),
        }),
        chain::Action::CreateContract { wasm_hash } => {
            wit::chain::Action::CreateContract(wasm_hash)
        }
    }
}
