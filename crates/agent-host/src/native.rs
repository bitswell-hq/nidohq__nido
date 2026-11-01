//! The same evaluator called natively, for the agreement tests and the
//! per-check cost comparison (`agent-host bench`). The host's checks never go
//! through this module; they go through the component.
//!
//! The conversions mirror `crates/grant-component/src/lib.rs`.

use grant_eval::{chain, files, network, signing};

use crate::evaluator::wit;

fn file_mode(m: wit::files::Mode) -> files::Mode {
    match m {
        wit::files::Mode::Read => files::Mode::Read,
        wit::files::Mode::Write => files::Mode::Write,
        wit::files::Mode::Execute => files::Mode::Execute,
    }
}

#[must_use]
pub fn file_caveat(c: &wit::files::Caveat) -> files::Caveat {
    match c {
        wit::files::Caveat::PathUnder(prefix) => files::Caveat::PathUnder(prefix.clone()),
        wit::files::Caveat::ModeIn(list) => {
            files::Caveat::ModeIn(list.iter().copied().map(file_mode).collect())
        }
    }
}

#[must_use]
pub fn file_action(a: &wit::files::Action) -> files::Action {
    files::Action {
        path: a.path.clone(),
        mode: file_mode(a.mode),
    }
}

fn scheme(s: wit::network::Scheme) -> network::Scheme {
    match s {
        wit::network::Scheme::Http => network::Scheme::Http,
        wit::network::Scheme::Https => network::Scheme::Https,
    }
}

#[must_use]
pub fn network_caveat(c: &wit::network::Caveat) -> network::Caveat {
    match c {
        wit::network::Caveat::HostIn(list) => network::Caveat::HostIn(list.clone()),
        wit::network::Caveat::PortIn(list) => network::Caveat::PortIn(list.clone()),
        wit::network::Caveat::SchemeIn(list) => {
            network::Caveat::SchemeIn(list.iter().copied().map(scheme).collect())
        }
    }
}

#[must_use]
pub fn network_action(a: &wit::network::Action) -> network::Action {
    network::Action {
        host: a.host.clone(),
        port: a.port,
        scheme: scheme(a.scheme),
    }
}

fn payload(p: wit::signing::Payload) -> signing::Payload {
    match p {
        wit::signing::Payload::Transaction => signing::Payload::Transaction,
        wit::signing::Payload::AuthEntry => signing::Payload::AuthEntry,
        wit::signing::Payload::Message => signing::Payload::Message,
    }
}

#[must_use]
pub fn signing_caveat(c: &wit::signing::Caveat) -> signing::Caveat {
    match c {
        wit::signing::Caveat::KeyIn(list) => signing::Caveat::KeyIn(list.clone()),
        wit::signing::Caveat::NetworkIn(list) => signing::Caveat::NetworkIn(list.clone()),
        wit::signing::Caveat::PayloadIn(list) => {
            signing::Caveat::PayloadIn(list.iter().copied().map(payload).collect())
        }
    }
}

#[must_use]
pub fn signing_action(a: &wit::signing::Action) -> signing::Action {
    signing::Action {
        key: a.key.clone(),
        network: a.network.clone(),
        payload: payload(a.payload),
    }
}

/// The host's split of an `i128` for the component: `hi * 2^64 + lo`.
#[must_use]
pub fn int128(n: i128) -> wit::chain::Int128 {
    // Truncating casts are the split: the high half's bits, then the low's.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    wit::chain::Int128 {
        hi: (n >> 64) as i64,
        lo: n as u64,
    }
}

fn from_int128(n: &wit::chain::Int128) -> i128 {
    (i128::from(n.hi) << 64) | i128::from(n.lo)
}

fn val(v: &wit::chain::Val) -> chain::Val {
    match v {
        wit::chain::Val::Int128(n) => chain::Val::I128(from_int128(n)),
        wit::chain::Val::U64(n) => chain::Val::U64(*n),
        wit::chain::Val::Bool(b) => chain::Val::Bool(*b),
        wit::chain::Val::Bytes(b) => chain::Val::Bytes(b.clone()),
        wit::chain::Val::Address(b) => chain::Val::Address(b.clone()),
        wit::chain::Val::Symbol(b) => chain::Val::Symbol(b.clone()),
        wit::chain::Val::Other(b) => chain::Val::Other(b.clone()),
    }
}

#[must_use]
pub fn chain_caveat(c: &wit::chain::Caveat) -> chain::Caveat {
    match c {
        wit::chain::Caveat::ContractIn(list) => chain::Caveat::ContractIn(list.clone()),
        wit::chain::Caveat::FunctionIn(list) => chain::Caveat::FunctionIn(list.clone()),
        wit::chain::Caveat::ArgI128AtMost((index, bound)) => {
            chain::Caveat::ArgI128AtMost(*index, from_int128(bound))
        }
        wit::chain::Caveat::ArgEq((index, v)) => chain::Caveat::ArgEq(*index, val(v)),
    }
}

#[must_use]
pub fn chain_action(a: &wit::chain::Action) -> chain::Action {
    match a {
        wit::chain::Action::Invoke(call) => chain::Action::Invoke {
            contract: call.contract.clone(),
            function: call.function.clone(),
            args: call.args.iter().map(val).collect(),
        },
        wit::chain::Action::CreateContract(hash) => chain::Action::CreateContract {
            wasm_hash: hash.clone(),
        },
    }
}
