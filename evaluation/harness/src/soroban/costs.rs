//! Cost per check: Soroban CPU instructions and memory of the grant signer's
//! `__check_auth` against caveat count, argument size, context count and
//! membership-list length, from the wasm `just build-contracts` builds.
//!
//! Every point is measured twice on the same stored grant: `pass`, where every
//! caveat holds for every context, and `fail`, where the first context calls
//! another instance of the same dApp (an address of the same length), so the
//! first caveat, a `ContractIn`, fails and the evaluator stops. Loading the
//! grant, verifying the signature and mapping the contexts are the same in
//! both, so `pass - fail` is the evaluator's own work, which the Lean step
//! counter counts for the same grant and actions.

use nido_integration_tests::grants::{Arg, Caveat};
use serde::Serialize;
use serde_json::Value;
use soroban_sdk::auth::{Context, ContractContext};
use soroban_sdk::xdr::SorobanAuthorizedInvocation;
use soroban_sdk::{Bytes, IntoVal, Symbol, Val, Vec};

use super::fixture::{agent, Fixture};
use crate::chain;

#[derive(Debug, Serialize)]
pub struct Point {
    pub id: String,
    pub sweep: &'static str,
    /// `pass` or `fail`.
    pub variant: &'static str,
    pub caveats: usize,
    pub contexts: usize,
    /// Length of the byte-string argument each context carries.
    pub arg_bytes: usize,
    /// Entries of the `ContractIn` list the context's contract is last in.
    pub list_len: usize,
    pub allowed: bool,
    pub cpu_instructions: u64,
    pub mem_bytes: u64,
}

struct Shape {
    sweep: &'static str,
    caveats: std::vec::Vec<Caveat>,
    contexts: usize,
    arg_bytes: usize,
    list_len: usize,
}

/// A contract id that is not any deployed contract, for padding lists.
fn decoy(i: usize) -> String {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&(i as u64 + 1).to_be_bytes());
    stellar_strkey::Contract(id).to_string()
}

fn shapes(f: &Fixture) -> std::vec::Vec<Shape> {
    let e = f.env();
    let d0 = &f.dapps[0];
    let kinds = [
        f.contract_in(&[d0]),
        f.function_in(&["probe"]),
        f.arg_address(0, &f.account.address),
    ];
    let data = |n: usize| Bytes::from_slice(e, &std::vec![0xab; n]);
    let mut out = std::vec::Vec::new();
    for n in [0usize, 1, 2, 4, 8, 16, 32, 64] {
        out.push(Shape {
            sweep: "caveats",
            caveats: (0..n).map(|i| kinds[i % kinds.len()].clone()).collect(),
            contexts: 1,
            arg_bytes: 32,
            list_len: 1,
        });
    }
    for n in [0usize, 64, 256, 1024, 4096, 16384] {
        out.push(Shape {
            sweep: "arg_bytes_compared",
            caveats: std::vec![
                kinds[0].clone(),
                kinds[1].clone(),
                Caveat::ArgEq(1, Arg::Bytes(data(n))),
            ],
            contexts: 1,
            arg_bytes: n,
            list_len: 1,
        });
        out.push(Shape {
            sweep: "arg_bytes_uncompared",
            caveats: std::vec![kinds[0].clone(), kinds[1].clone()],
            contexts: 1,
            arg_bytes: n,
            list_len: 1,
        });
    }
    for m in [1usize, 2, 4, 8, 16] {
        out.push(Shape {
            sweep: "contexts",
            caveats: std::vec![
                kinds[0].clone(),
                kinds[1].clone(),
                kinds[2].clone(),
                kinds[0].clone()
            ],
            contexts: m,
            arg_bytes: 32,
            list_len: 1,
        });
    }
    for k in [1usize, 4, 16, 64] {
        let mut list: Vec<Bytes> = Vec::new(e);
        for i in 0..k - 1 {
            list.push_back(Bytes::from_slice(e, decoy(i).as_bytes()));
        }
        list.push_back(f.id(d0));
        out.push(Shape {
            sweep: "contract_list",
            caveats: std::vec![Caveat::ContractIn(list)],
            contexts: 1,
            arg_bytes: 32,
            list_len: k,
        });
    }
    out
}

fn probe_args(f: &Fixture, n: usize) -> Vec<Val> {
    let e = f.env();
    Vec::from_array(
        e,
        [
            f.account.address.into_val(e),
            Bytes::from_slice(e, &std::vec![0xab; n]).into_val(e),
        ],
    )
}

fn context(f: &Fixture, dapp: usize, n: usize) -> Context {
    Context::Contract(ContractContext {
        contract: f.dapps[dapp].clone(),
        fn_name: Symbol::new(f.env(), "probe"),
        args: probe_args(f, n),
    })
}

fn invocation(f: &Fixture, dapp: usize, n: usize) -> SorobanAuthorizedInvocation {
    f.node(&f.dapps[dapp], "probe", &probe_args(f, n), std::vec![])
}

/// Run every sweep. Returns the points and the Lean cases for them (one per
/// point, with the same id).
#[must_use]
pub fn run(f: &Fixture) -> (std::vec::Vec<Point>, std::vec::Vec<Value>) {
    let key = agent(200);
    let mut points = std::vec::Vec::new();
    let mut cases = std::vec::Vec::new();
    // One unmeasured check first, so every measured one finds the contract
    // in the same state of the host's module cache.
    let warm = f.issue(&key, &[], 0);
    assert!(f
        .verdict(warm, &key, &[context(f, 0, 32)])
        .expect("the simulation calls __check_auth")
        .is_ok());
    for (i, s) in shapes(f).into_iter().enumerate() {
        let grant = f.issue(&key, &s.caveats, 0);
        let eval_caveats: std::vec::Vec<_> = s.caveats.iter().map(chain::caveat).collect();
        for variant in ["pass", "fail"] {
            if variant == "fail" && s.caveats.is_empty() {
                continue;
            }
            let first = usize::from(variant == "fail");
            let dapps: std::vec::Vec<usize> = (0..s.contexts)
                .map(|c| if c == 0 { first } else { 0 })
                .collect();
            let contexts: std::vec::Vec<Context> =
                dapps.iter().map(|d| context(f, *d, s.arg_bytes)).collect();
            let actions: std::vec::Vec<_> = dapps
                .iter()
                .map(|d| chain::authorized_function(&invocation(f, *d, s.arg_bytes).function))
                .collect();
            let mut budget = f.env().cost_estimate().budget();
            budget.reset_unlimited();
            let verdict = f
                .verdict(grant, &key, &contexts)
                .expect("the simulation calls __check_auth");
            let point = Point {
                id: format!("cost-{i:02}-{}-{variant}", s.sweep),
                sweep: s.sweep,
                variant,
                caveats: s.caveats.len(),
                contexts: s.contexts,
                arg_bytes: s.arg_bytes,
                list_len: s.list_len,
                allowed: verdict.is_ok(),
                cpu_instructions: budget.cpu_instruction_cost(),
                mem_bytes: budget.memory_bytes_cost(),
            };
            assert_eq!(
                point.allowed,
                variant == "pass",
                "{}: the grant signer's verdict is {verdict:?}",
                point.id
            );
            cases.push(chain::lean_case(&point.id, &eval_caveats, &actions));
            points.push(point);
        }
    }
    (points, cases)
}
