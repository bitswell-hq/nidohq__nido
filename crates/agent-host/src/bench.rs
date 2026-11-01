//! Per-check cost: one `allows` through the evaluator component against the
//! same call made natively.
//!
//! Each case is a three-caveat grant and an action it allows, so every
//! caveat is evaluated. The native column calls `grant_eval` on values built
//! once; the component column calls the component with WIT values built once,
//! so it includes copying the grant and action into the component's memory,
//! the guest's conversion to `grant_eval` values, the evaluation and the
//! return. The chain case checks a three-context authorization tree with
//! `allows_all`.

use std::hint::black_box;
use std::time::Instant;

use grant_eval::{chain, files, network, signing};

use crate::evaluator::{wit, EvalError, Evaluator};
use crate::native;

/// One row of the comparison.
#[derive(Debug, serde::Serialize)]
pub struct Row {
    pub case: &'static str,
    pub native_ns: f64,
    pub component_ns: f64,
}

/// The measurements.
#[derive(Debug, serde::Serialize)]
pub struct Report {
    pub iterations: u32,
    /// Compiling and instantiating the component, once per host.
    pub instantiate_ms: f64,
    pub rows: Vec<Row>,
}

/// Nanoseconds per call of `f`, after a warm-up of a tenth as many calls.
fn time(iterations: u32, mut f: impl FnMut() -> Result<bool, EvalError>) -> Result<f64, EvalError> {
    for _ in 0..iterations / 10 {
        black_box(f()?);
    }
    let start = Instant::now();
    for _ in 0..iterations {
        if !black_box(f()?) {
            return Err(EvalError("a benchmark action was denied".into()));
        }
    }
    Ok(start.elapsed().as_secs_f64() * 1e9 / f64::from(iterations))
}

fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn path(s: &str) -> Vec<Vec<u8>> {
    s.split('/').filter(|c| !c.is_empty()).map(bytes).collect()
}

/// Run every case `iterations` times each way.
///
/// # Errors
///
/// If the component fails to load or traps.
pub fn run(iterations: u32) -> Result<Report, EvalError> {
    let start = Instant::now();
    let mut evaluator = Evaluator::new()?;
    let instantiate_ms = start.elapsed().as_secs_f64() * 1e3;
    let rows = vec![
        files_case(&mut evaluator, iterations)?,
        network_case(&mut evaluator, iterations)?,
        signing_case(&mut evaluator, iterations)?,
        chain_case(&mut evaluator, iterations)?,
    ];
    Ok(Report {
        iterations,
        instantiate_ms,
        rows,
    })
}

fn files_case(evaluator: &mut Evaluator, iterations: u32) -> Result<Row, EvalError> {
    let grant = vec![
        wit::files::Caveat::PathUnder(path("/home/agent/work")),
        wit::files::Caveat::ModeIn(vec![wit::files::Mode::Read, wit::files::Mode::Write]),
        wit::files::Caveat::PathUnder(path("/home/agent")),
    ];
    let action = wit::files::Action {
        path: path("/home/agent/work/src/main.rs"),
        mode: wit::files::Mode::Read,
    };
    let g: Vec<_> = grant.iter().map(native::file_caveat).collect();
    let a = native::file_action(&action);
    Ok(Row {
        case: "files",
        native_ns: time(iterations, || {
            Ok(files::allows(black_box(&g), black_box(&a)))
        })?,
        component_ns: time(iterations, || evaluator.files(&grant, &action))?,
    })
}

fn network_case(evaluator: &mut Evaluator, iterations: u32) -> Result<Row, EvalError> {
    let grant = vec![
        wit::network::Caveat::HostIn(vec![bytes("api.example.com"), bytes("example.org")]),
        wit::network::Caveat::PortIn(vec![443]),
        wit::network::Caveat::SchemeIn(vec![wit::network::Scheme::Https]),
    ];
    let action = wit::network::Action {
        host: bytes("example.org"),
        port: 443,
        scheme: wit::network::Scheme::Https,
    };
    let g: Vec<_> = grant.iter().map(native::network_caveat).collect();
    let a = native::network_action(&action);
    Ok(Row {
        case: "network",
        native_ns: time(iterations, || {
            Ok(network::allows(black_box(&g), black_box(&a)))
        })?,
        component_ns: time(iterations, || evaluator.network(&grant, &action))?,
    })
}

fn signing_case(evaluator: &mut Evaluator, iterations: u32) -> Result<Row, EvalError> {
    let testnet = bytes("Test SDF Network ; September 2015");
    let grant = vec![
        wit::signing::Caveat::KeyIn(vec![bytes("key-a"), bytes("key-b")]),
        wit::signing::Caveat::NetworkIn(vec![testnet.clone()]),
        wit::signing::Caveat::PayloadIn(vec![
            wit::signing::Payload::Transaction,
            wit::signing::Payload::AuthEntry,
        ]),
    ];
    let action = wit::signing::Action {
        key: bytes("key-b"),
        network: testnet,
        payload: wit::signing::Payload::AuthEntry,
    };
    let g: Vec<_> = grant.iter().map(native::signing_caveat).collect();
    let a = native::signing_action(&action);
    Ok(Row {
        case: "signing",
        native_ns: time(iterations, || {
            Ok(signing::allows(black_box(&g), black_box(&a)))
        })?,
        component_ns: time(iterations, || evaluator.signing(&grant, &action))?,
    })
}

fn chain_case(evaluator: &mut Evaluator, iterations: u32) -> Result<Row, EvalError> {
    let contract = bytes("CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC");
    // Amounts in stroops: at most 1000 units of a 7-decimal token.
    let grant = vec![
        wit::chain::Caveat::ContractIn(vec![contract.clone()]),
        wit::chain::Caveat::FunctionIn(vec![bytes("transfer")]),
        wit::chain::Caveat::ArgI128AtMost((2, native::int128(10_000_000_000))),
    ];
    let invoke = |amount: i128| {
        wit::chain::Action::Invoke(wit::chain::Invocation {
            contract: contract.clone(),
            function: bytes("transfer"),
            args: vec![
                wit::chain::Val::Address(bytes("GFROM")),
                wit::chain::Val::Address(bytes("GTO")),
                wit::chain::Val::Int128(native::int128(amount)),
            ],
        })
    };
    let tree = vec![invoke(1), invoke(5_000_000_000), invoke(10_000_000_000)];
    let g: Vec<_> = grant.iter().map(native::chain_caveat).collect();
    let a: Vec<_> = tree.iter().map(native::chain_action).collect();
    Ok(Row {
        case: "chain (3 contexts)",
        native_ns: time(iterations, || {
            Ok(chain::allows_all(black_box(&g), black_box(&a)))
        })?,
        component_ns: time(iterations, || evaluator.chain_all(&grant, &tree))?,
    })
}
