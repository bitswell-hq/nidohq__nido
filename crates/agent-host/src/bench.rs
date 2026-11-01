//! Per-check cost: one check through the evaluator component against the
//! same check made natively, the cost of compiling and instantiating the
//! component, and a timer for whole tool calls.
//!
//! Each case is a three-caveat grant and an action it allows, so every
//! caveat is evaluated; the chain case checks a three-context authorization
//! tree with `allows_all`. Each is timed three ways: `grant-eval` on values
//! built once (native); the host's WIT values converted to `grant-eval`
//! values in the host and then evaluated (the check without WebAssembly);
//! and the component, which includes copying the grant and action into its
//! memory, the guest's conversion, the evaluation and the return.
//!
//! Method, for every measured operation:
//!
//! - **Warm-up**: the operation runs for [`WARM_UP`] before anything is
//!   recorded.
//! - **Batches**: the batch size doubles until one batch takes at least
//!   [`BATCH`], so the clock's resolution and the loop's overhead are small
//!   against what is timed. A sample is one batch's time divided by its size.
//! - **Rounds**: the variants of a case are sampled in interleaved rounds,
//!   their order rotating every round, so a change in the machine's load or
//!   clock during the run reaches every variant alike. The ratio of two
//!   variants is taken within each round.
//! - **Summary**: the median of the samples with a distribution-free 95%
//!   confidence interval for it (order statistics of the binomial), and the
//!   10th and 90th percentiles, the minimum and the maximum.

use std::hint::black_box;
use std::time::{Duration, Instant};

use grant_eval::{chain, files, network, signing};
use serde::Serialize;

use crate::evaluator::{wit, EvalError, Evaluator};
use crate::native;

pub const WARM_UP: Duration = Duration::from_millis(200);
pub const BATCH: Duration = Duration::from_millis(2);
/// Interleaved rounds per check case.
pub const ROUNDS: usize = 101;
/// Compilations and instantiations of the component.
pub const INSTANTIATIONS: usize = 21;
/// Rounds per tool call.
pub const CALL_ROUNDS: usize = 31;

/// A summary of samples.
#[derive(Clone, Debug, Serialize)]
pub struct Stats {
    pub samples: usize,
    pub median: f64,
    /// The 95% confidence interval of the median.
    pub median_ci95: [f64; 2],
    pub p10: f64,
    pub p90: f64,
    pub min: f64,
    pub max: f64,
}

/// The 1-based rank `n/2 + z·√n/2`, rounded and clamped to `1..=n`.
#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn rank(n: usize, z: f64) -> usize {
    let r = (n as f64 / 2.0 + z * (n as f64).sqrt() / 2.0).round();
    (r.max(1.0) as usize).min(n)
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn percentile(sorted: &[f64], p: f64) -> f64 {
    let at = (p * (sorted.len() - 1) as f64).round() as usize;
    sorted[at]
}

/// # Panics
/// If `samples` is empty.
#[must_use]
pub fn stats(mut samples: Vec<f64>) -> Stats {
    samples.sort_by(f64::total_cmp);
    let n = samples.len();
    let median = if n % 2 == 1 {
        samples[n / 2]
    } else {
        f64::midpoint(samples[n / 2 - 1], samples[n / 2])
    };
    Stats {
        samples: n,
        median,
        median_ci95: [samples[rank(n, -1.96) - 1], samples[rank(n, 1.96) - 1]],
        p10: percentile(&samples, 0.10),
        p90: percentile(&samples, 0.90),
        min: samples[0],
        max: samples[n - 1],
    }
}

/// Run `f` for [`WARM_UP`], then return the batch size whose batch takes at
/// least [`BATCH`].
fn calibrate(f: &mut dyn FnMut() -> Result<bool, EvalError>) -> Result<u32, EvalError> {
    let start = Instant::now();
    while start.elapsed() < WARM_UP {
        black_box(f()?);
    }
    let mut n = 1u32;
    loop {
        let t = Instant::now();
        for _ in 0..n {
            black_box(f()?);
        }
        if t.elapsed() >= BATCH || n >= 1 << 24 {
            return Ok(n);
        }
        n *= 2;
    }
}

/// Nanoseconds per call over one batch of `n`, failing if `f` returns
/// `false` (every benchmark action is allowed).
fn batch(f: &mut dyn FnMut() -> Result<bool, EvalError>, n: u32) -> Result<f64, EvalError> {
    let t = Instant::now();
    for _ in 0..n {
        if !black_box(f()?) {
            return Err(EvalError("a benchmark action was denied".into()));
        }
    }
    Ok(t.elapsed().as_secs_f64() * 1e9 / f64::from(n))
}

/// One check case, three ways.
#[derive(Debug, Serialize)]
pub struct CheckRow {
    pub case: &'static str,
    /// `grant-eval` on values built once.
    pub native_ns: Stats,
    /// The host's WIT values converted to `grant-eval` values natively, then
    /// evaluated: the check without WebAssembly.
    pub host_native_ns: Stats,
    /// The evaluator component through Wasmtime: copying the grant and
    /// action in, the guest's conversion, the evaluation and the return.
    pub component_ns: Stats,
    /// `component / native`, within each round.
    pub component_over_native: Stats,
    /// `component / host_native`, within each round.
    pub component_over_host_native: Stats,
    pub batch_sizes: [u32; 3],
}

fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn path(s: &str) -> Vec<Vec<u8>> {
    s.split('/').filter(|c| !c.is_empty()).map(bytes).collect()
}

/// Time one case: `variants` are native, host-side native and component.
fn case(
    name: &'static str,
    variants: &mut [&mut dyn FnMut() -> Result<bool, EvalError>; 3],
) -> Result<CheckRow, EvalError> {
    let mut sizes = [0u32; 3];
    for (i, v) in variants.iter_mut().enumerate() {
        sizes[i] = calibrate(*v)?;
    }
    let mut samples: [Vec<f64>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for round in 0..ROUNDS {
        for k in 0..3 {
            let i = (round + k) % 3;
            samples[i].push(batch(variants[i], sizes[i])?);
        }
    }
    let over = |a: usize, b: usize| {
        stats(
            samples[a]
                .iter()
                .zip(&samples[b])
                .map(|(x, y)| x / y)
                .collect(),
        )
    };
    Ok(CheckRow {
        case: name,
        component_over_native: over(2, 0),
        component_over_host_native: over(2, 1),
        native_ns: stats(samples[0].clone()),
        host_native_ns: stats(samples[1].clone()),
        component_ns: stats(samples[2].clone()),
        batch_sizes: sizes,
    })
}

/// Time every check case on `ev`.
///
/// # Errors
///
/// If the component traps or a benchmark action is denied.
#[allow(clippy::too_many_lines)]
pub fn checks(ev: &mut Evaluator) -> Result<Vec<CheckRow>, EvalError> {
    let mut rows = Vec::new();

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
    rows.push(case(
        "files",
        &mut [
            &mut || Ok(files::allows(black_box(&g), black_box(&a))),
            &mut || {
                let g: Vec<_> = black_box(&grant).iter().map(native::file_caveat).collect();
                Ok(files::allows(&g, &native::file_action(black_box(&action))))
            },
            &mut || ev.files(&grant, &action),
        ],
    )?);

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
    rows.push(case(
        "network",
        &mut [
            &mut || Ok(network::allows(black_box(&g), black_box(&a))),
            &mut || {
                let g: Vec<_> = black_box(&grant)
                    .iter()
                    .map(native::network_caveat)
                    .collect();
                Ok(network::allows(
                    &g,
                    &native::network_action(black_box(&action)),
                ))
            },
            &mut || ev.network(&grant, &action),
        ],
    )?);

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
    rows.push(case(
        "signing",
        &mut [
            &mut || Ok(signing::allows(black_box(&g), black_box(&a))),
            &mut || {
                let g: Vec<_> = black_box(&grant)
                    .iter()
                    .map(native::signing_caveat)
                    .collect();
                Ok(signing::allows(
                    &g,
                    &native::signing_action(black_box(&action)),
                ))
            },
            &mut || ev.signing(&grant, &action),
        ],
    )?);

    let contract = bytes("CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC");
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
    rows.push(case(
        "chain (3 contexts)",
        &mut [
            &mut || Ok(chain::allows_all(black_box(&g), black_box(&a))),
            &mut || {
                let g: Vec<_> = black_box(&grant).iter().map(native::chain_caveat).collect();
                let a: Vec<_> = black_box(&tree).iter().map(native::chain_action).collect();
                Ok(chain::allows_all(&g, &a))
            },
            &mut || ev.chain_all(&grant, &tree),
        ],
    )?);
    Ok(rows)
}

/// Milliseconds to compile and instantiate the component, [`INSTANTIATIONS`]
/// times.
///
/// # Errors
///
/// If the component does not load.
pub fn instantiation() -> Result<Stats, EvalError> {
    let mut samples = Vec::new();
    for _ in 0..INSTANTIATIONS {
        let t = Instant::now();
        black_box(Evaluator::new()?);
        samples.push(t.elapsed().as_secs_f64() * 1e3);
    }
    Ok(stats(samples))
}

/// Microseconds per call of `f` (a tool call, say), over [`CALL_ROUNDS`]
/// calibrated batches after a warm-up, and the batch size.
///
/// # Errors
///
/// What `f` returns.
pub fn calls(mut f: impl FnMut() -> Result<bool, EvalError>) -> Result<(Stats, u32), EvalError> {
    let mut f: &mut dyn FnMut() -> Result<bool, EvalError> = &mut f;
    let n = calibrate(&mut f)?;
    let mut samples = Vec::new();
    for _ in 0..CALL_ROUNDS {
        samples.push(batch(&mut f, n)? / 1e3);
    }
    Ok((stats(samples), n))
}

/// What [`run`] measured, with the method's parameters.
#[derive(Debug, Serialize)]
pub struct Report {
    pub warm_up_ms: u128,
    pub min_batch_ms: u128,
    pub check_rounds: usize,
    pub instantiations: usize,
    /// Compiling and instantiating the component, milliseconds.
    pub instantiate_ms: Stats,
    pub checks: Vec<CheckRow>,
}

/// Time the component's compilation and instantiation and every check case.
///
/// # Errors
///
/// If the component fails to load or traps, or a benchmark action is denied.
pub fn run() -> Result<Report, EvalError> {
    let instantiate_ms = instantiation()?;
    let mut evaluator = Evaluator::new()?;
    Ok(Report {
        warm_up_ms: WARM_UP.as_millis(),
        min_batch_ms: BATCH.as_millis(),
        check_rounds: ROUNDS,
        instantiations: INSTANTIATIONS,
        instantiate_ms,
        checks: checks(&mut evaluator)?,
    })
}
