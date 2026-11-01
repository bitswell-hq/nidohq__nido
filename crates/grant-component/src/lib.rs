//! The grant evaluator as a WebAssembly component.
//!
//! Each export of the `evaluator` world in `wit/grant-eval.wit` converts its
//! arguments into `grant-eval` values and calls that vocabulary's `allows` or
//! `allows_all`. Nothing else runs: the component imports nothing and keeps
//! no state between calls.
//!
//! Built for `wasm32v1-none`, the target the Soroban smart account's
//! `__check_auth` compiles `grant-eval` for, then wrapped as a component by
//! the agent host's build script.
#![cfg_attr(target_arch = "wasm32", no_std)]
// The generated bindings are the only `unsafe` code: the canonical ABI glue
// `wit-bindgen` emits, allowed (with its lints) in `bindings` alone.
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

use grant_eval::{chain, files, network, signing};

#[allow(unsafe_code, clippy::pedantic)]
mod bindings {
    wit_bindgen::generate!({
        world: "evaluator",
        path: "wit",
    });

    use super::Evaluator;
    export!(Evaluator);
}

use bindings::exports::nido::grant_eval as wit;

#[cfg(target_arch = "wasm32")]
#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(target_arch = "wasm32")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    core::arch::wasm32::unreachable()
}

struct Evaluator;

fn map<A, B>(list: Vec<A>, f: fn(A) -> B) -> Vec<B> {
    list.into_iter().map(f).collect()
}

fn file_mode(m: wit::files::Mode) -> files::Mode {
    match m {
        wit::files::Mode::Read => files::Mode::Read,
        wit::files::Mode::Write => files::Mode::Write,
        wit::files::Mode::Execute => files::Mode::Execute,
    }
}

fn file_caveat(c: wit::files::Caveat) -> files::Caveat {
    match c {
        wit::files::Caveat::PathUnder(prefix) => files::Caveat::PathUnder(prefix),
        wit::files::Caveat::ModeIn(list) => files::Caveat::ModeIn(map(list, file_mode)),
    }
}

fn file_action(a: wit::files::Action) -> files::Action {
    files::Action {
        path: a.path,
        mode: file_mode(a.mode),
    }
}

impl wit::files::Guest for Evaluator {
    fn allows(grant: Vec<wit::files::Caveat>, action: wit::files::Action) -> bool {
        files::allows(&map(grant, file_caveat), &file_action(action))
    }

    fn allows_all(grant: Vec<wit::files::Caveat>, actions: Vec<wit::files::Action>) -> bool {
        files::allows_all(&map(grant, file_caveat), &map(actions, file_action))
    }
}

fn scheme(s: wit::network::Scheme) -> network::Scheme {
    match s {
        wit::network::Scheme::Http => network::Scheme::Http,
        wit::network::Scheme::Https => network::Scheme::Https,
    }
}

fn network_caveat(c: wit::network::Caveat) -> network::Caveat {
    match c {
        wit::network::Caveat::HostIn(list) => network::Caveat::HostIn(list),
        wit::network::Caveat::PortIn(list) => network::Caveat::PortIn(list),
        wit::network::Caveat::SchemeIn(list) => network::Caveat::SchemeIn(map(list, scheme)),
    }
}

fn network_action(a: wit::network::Action) -> network::Action {
    network::Action {
        host: a.host,
        port: a.port,
        scheme: scheme(a.scheme),
    }
}

impl wit::network::Guest for Evaluator {
    fn allows(grant: Vec<wit::network::Caveat>, action: wit::network::Action) -> bool {
        network::allows(&map(grant, network_caveat), &network_action(action))
    }

    fn allows_all(grant: Vec<wit::network::Caveat>, actions: Vec<wit::network::Action>) -> bool {
        network::allows_all(&map(grant, network_caveat), &map(actions, network_action))
    }
}

fn payload(p: wit::signing::Payload) -> signing::Payload {
    match p {
        wit::signing::Payload::Transaction => signing::Payload::Transaction,
        wit::signing::Payload::AuthEntry => signing::Payload::AuthEntry,
        wit::signing::Payload::Message => signing::Payload::Message,
    }
}

fn signing_caveat(c: wit::signing::Caveat) -> signing::Caveat {
    match c {
        wit::signing::Caveat::KeyIn(list) => signing::Caveat::KeyIn(list),
        wit::signing::Caveat::NetworkIn(list) => signing::Caveat::NetworkIn(list),
        wit::signing::Caveat::PayloadIn(list) => signing::Caveat::PayloadIn(map(list, payload)),
    }
}

fn signing_action(a: wit::signing::Action) -> signing::Action {
    signing::Action {
        key: a.key,
        network: a.network,
        payload: payload(a.payload),
    }
}

impl wit::signing::Guest for Evaluator {
    fn allows(grant: Vec<wit::signing::Caveat>, action: wit::signing::Action) -> bool {
        signing::allows(&map(grant, signing_caveat), &signing_action(action))
    }

    fn allows_all(grant: Vec<wit::signing::Caveat>, actions: Vec<wit::signing::Action>) -> bool {
        signing::allows_all(&map(grant, signing_caveat), &map(actions, signing_action))
    }
}

/// `hi * 2^64 + lo`, the inverse of the host's split.
fn int128(n: wit::chain::Int128) -> i128 {
    (i128::from(n.hi) << 64) | i128::from(n.lo)
}

fn val(v: wit::chain::Val) -> chain::Val {
    match v {
        wit::chain::Val::Int128(n) => chain::Val::I128(int128(n)),
        wit::chain::Val::U64(n) => chain::Val::U64(n),
        wit::chain::Val::Bool(b) => chain::Val::Bool(b),
        wit::chain::Val::Bytes(b) => chain::Val::Bytes(b),
        wit::chain::Val::Address(b) => chain::Val::Address(b),
        wit::chain::Val::Symbol(b) => chain::Val::Symbol(b),
        wit::chain::Val::Other(b) => chain::Val::Other(b),
    }
}

fn chain_caveat(c: wit::chain::Caveat) -> chain::Caveat {
    match c {
        wit::chain::Caveat::ContractIn(list) => chain::Caveat::ContractIn(list),
        wit::chain::Caveat::FunctionIn(list) => chain::Caveat::FunctionIn(list),
        wit::chain::Caveat::ArgI128AtMost((index, bound)) => {
            chain::Caveat::ArgI128AtMost(index, int128(bound))
        }
        wit::chain::Caveat::ArgEq((index, v)) => chain::Caveat::ArgEq(index, val(v)),
    }
}

fn chain_action(a: wit::chain::Action) -> chain::Action {
    match a {
        wit::chain::Action::Invoke(call) => chain::Action::Invoke {
            contract: call.contract,
            function: call.function,
            args: map(call.args, val),
        },
        wit::chain::Action::CreateContract(wasm_hash) => {
            chain::Action::CreateContract { wasm_hash }
        }
    }
}

impl wit::chain::Guest for Evaluator {
    fn allows(grant: Vec<wit::chain::Caveat>, action: wit::chain::Action) -> bool {
        chain::allows(&map(grant, chain_caveat), &chain_action(action))
    }

    fn allows_all(grant: Vec<wit::chain::Caveat>, actions: Vec<wit::chain::Action>) -> bool {
        chain::allows_all(&map(grant, chain_caveat), &map(actions, chain_action))
    }
}
