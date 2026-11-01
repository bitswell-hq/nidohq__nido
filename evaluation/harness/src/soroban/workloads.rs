//! The workloads of `crate::workloads`, replayed in the Soroban host.

use std::collections::BTreeMap;

use nido_grant_signer::{Arg, Caveat};
use serde::Serialize;
use soroban_sdk::xdr::SorobanAuthorizedInvocation;
use soroban_sdk::Address;

use super::attacks::delegate;
use super::fixture::{agent, Fixture};
use crate::outcome::Outcome;
use crate::workloads::{Call, CaveatSpec, Expect, Step, Target, Who, Workload};

#[derive(Debug, Serialize)]
pub struct Row {
    pub workload: &'static str,
    pub step: usize,
    pub agent: &'static str,
    pub action: String,
    pub expected: String,
    #[serde(flatten)]
    pub outcome: Outcome,
    pub as_expected: bool,
    /// Contexts in the call's authorization tree.
    pub contexts: usize,
    pub cpu_instructions: i64,
    pub mem_bytes: i64,
    pub state_unchanged_if_refused: Option<bool>,
}

fn target(f: &Fixture, t: Target) -> Address {
    match t {
        Target::Asset => f.asset.clone(),
        Target::Other => f.other.clone(),
        Target::Dapp(i) => f.dapps[i].clone(),
    }
}

fn who(f: &Fixture, w: Who) -> Address {
    match w {
        Who::Bob => f.bob.clone(),
        Who::Carol => f.carol.clone(),
    }
}

fn caveats(f: &Fixture, specs: &[CaveatSpec]) -> std::vec::Vec<Caveat> {
    specs
        .iter()
        .map(|c| match c {
            CaveatSpec::ContractIn(list) => {
                let addrs: std::vec::Vec<Address> = list.iter().map(|t| target(f, *t)).collect();
                f.contract_in(&addrs.iter().collect::<std::vec::Vec<_>>())
            }
            CaveatSpec::FunctionIn(list) => f.function_in(list),
            CaveatSpec::ArgIs(i, w) => Caveat::ArgEq(*i, Arg::Address(f.id(&who(f, *w)))),
            CaveatSpec::AmountAtMost(i, n) => Caveat::ArgI128AtMost(*i, *n),
        })
        .collect()
}

/// Contexts in a tree.
#[must_use]
pub fn count(node: &SorobanAuthorizedInvocation) -> usize {
    1 + node.sub_invocations.iter().map(count).sum::<usize>()
}

/// The expectation as the grant signer reports it.
#[must_use]
pub fn expected(e: Expect) -> Outcome {
    match e {
        Expect::Allowed => Outcome::Allowed,
        Expect::NotAllowed => Outcome::refused("grant-signer", "NotAllowed (#6)"),
        Expect::Overdrawn => Outcome::refused("grant-signer", "Overdrawn (#7)"),
    }
}

/// Run `w` on a fresh account.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run(wasm: &[u8], w: &Workload) -> std::vec::Vec<Row> {
    let f = Fixture::new(&format!("workload/{}", w.name), wasm, 3, None);
    let mut grants: BTreeMap<&str, u32> = BTreeMap::new();
    let mut rows = std::vec::Vec::new();
    for (step, s) in w.steps.iter().enumerate() {
        match s {
            Step::Issue {
                agent: name,
                caveats: specs,
                allowance,
            } => {
                let id = f.issue(
                    &agent(crate::workloads::seed(name)),
                    &caveats(&f, specs),
                    *allowance,
                );
                grants.insert(name, id);
            }
            Step::Delegate {
                from,
                agent: name,
                caveats: specs,
                allowance,
            } => {
                let parent = grants[from];
                let id = f.next_id();
                let out = delegate(
                    &f,
                    parent,
                    &agent(crate::workloads::seed(from)),
                    parent,
                    &agent(crate::workloads::seed(name)),
                    &caveats(&f, specs),
                    *allowance,
                );
                assert_eq!(out, Outcome::Allowed, "{}: delegation", w.name);
                grants.insert(name, id);
            }
            Step::Call {
                agent: name,
                call,
                expect,
            } => {
                let (contract, func, args, tree, action) = match call {
                    Call::Transfer { token, to, amount } => {
                        let token = target(&f, *token);
                        let args = f.transfer_args(&who(&f, *to), *amount);
                        let tree = f.node(&token, "transfer", &args, std::vec![]);
                        (
                            token,
                            "transfer",
                            args,
                            tree,
                            format!("transfer {amount} to {to:?}"),
                        )
                    }
                    Call::Forward {
                        dapp,
                        token,
                        to,
                        amount,
                    } => {
                        let token_addr = target(&f, *token);
                        let (contract, args) =
                            f.forward_args(*dapp, &token_addr, &who(&f, *to), *amount);
                        let tree = f.node(
                            &contract,
                            "forward",
                            &args,
                            std::vec![f.transfer_node(&token_addr, &who(&f, *to), *amount)],
                        );
                        (
                            contract,
                            "forward",
                            args,
                            tree,
                            format!("forward {amount} of {token:?} to {to:?}"),
                        )
                    }
                    Call::Hop {
                        path,
                        token,
                        to,
                        amount,
                    } => {
                        let (contract, args, tree) =
                            f.hop(path, &target(&f, *token), &who(&f, *to), *amount);
                        (
                            contract,
                            "hop",
                            args,
                            tree,
                            format!("hop through {path:?}, {amount} to {to:?}"),
                        )
                    }
                };
                let contexts = count(&tree);
                let before = f.snapshot();
                let entry = f.agent_entry(
                    grants[name],
                    &agent(crate::workloads::seed(name)),
                    None,
                    tree,
                );
                let outcome = f.call(&[entry], &contract, func, &args);
                let r = f.env().cost_estimate().resources();
                let unchanged =
                    (!outcome.is_allowed()).then(|| f.snapshot().diff(&before).is_empty());
                let want = expected(*expect);
                rows.push(Row {
                    workload: w.name,
                    step,
                    agent: name,
                    action,
                    expected: format!("{expect:?}"),
                    as_expected: outcome == want,
                    outcome,
                    contexts,
                    cpu_instructions: r.instructions,
                    mem_bytes: r.mem_bytes,
                    state_unchanged_if_refused: unchanged,
                });
            }
        }
    }
    rows
}
