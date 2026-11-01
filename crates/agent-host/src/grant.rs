//! Grants as the host holds them.
//!
//! A [`Grants`] is one caveat list per vocabulary the host's tools act in.
//! The JSON form follows `grant-relay`'s configuration:
//!
//! ```json
//! {
//!   "files":   [{"path_under": "/srv/work"}, {"mode_in": ["read"]}],
//!   "network": [{"host_in": ["api.example.com"]}, {"scheme_in": ["https"]}],
//!   "signing": [{"key_in": ["key-a"]}, {"network_in": ["Test SDF Network ; September 2015"]}]
//! }
//! ```
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

use serde::Deserialize;

use crate::evaluator::wit;
use crate::fs;

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
    /// If a `path_under` prefix is not absolute or does not resolve.
    pub fn lower(&self) -> io::Result<Lowered> {
        Ok(Lowered {
            files: self
                .files
                .iter()
                .map(lower_file_caveat)
                .collect::<io::Result<_>>()?,
            network: self.network.iter().map(lower_network_caveat).collect(),
            signing: self.signing.iter().map(lower_signing_caveat).collect(),
        })
    }
}

/// A grant as the evaluator component takes it, with paths resolved.
#[derive(Clone)]
pub struct Lowered {
    pub files: Vec<wit::files::Caveat>,
    pub network: Vec<wit::network::Caveat>,
    pub signing: Vec<wit::signing::Caveat>,
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
