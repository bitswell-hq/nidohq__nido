//! The chain vocabulary as a `rule_eval` rule set, and the check that the
//! two evaluators agree on it.
//!
//! A grant that names its contracts (has a `ContractIn` caveat) lowers to one
//! rule per contract in the intersection of its `ContractIn` caveats, each
//! matching the intersection of its `FunctionIn` caveats (every function
//! when there is none), with its argument caveats as conditions, no signers
//! and a threshold of 0. Values and actions map one to one onto `rule_eval`'s
//! constructors of the same name. This is the lowering the relay
//! (`grant_relay::config::chain_rules`) and the integration tests
//! (`nido_integration_tests::grants`) apply to chain grants. A grant with no
//! `ContractIn` has no lowering: `rule_eval` has no rule that matches every
//! contract.
//!
//! Each test file uses part of this module.
#![allow(dead_code)]

use grant_eval::chain::{self, Action, Caveat, Val};
use rule_eval::{Cond, Context, Functions, Rule};

fn val(v: &Val) -> rule_eval::Val {
    match v {
        Val::I128(n) => rule_eval::Val::I128(*n),
        Val::U64(n) => rule_eval::Val::U64(*n),
        Val::Bool(b) => rule_eval::Val::Bool(*b),
        Val::Bytes(b) => rule_eval::Val::Bytes(b.clone()),
        Val::Address(b) => rule_eval::Val::Address(b.clone()),
        Val::Symbol(b) => rule_eval::Val::Symbol(b.clone()),
        Val::Other(b) => rule_eval::Val::Other(b.clone()),
    }
}

/// `action` as a `rule_eval` context.
pub fn context(action: &Action) -> Context {
    match action {
        Action::Invoke {
            contract,
            function,
            args,
        } => Context::Call {
            contract: contract.clone(),
            function: function.clone(),
            args: args.iter().map(val).collect(),
        },
        Action::CreateContract { wasm_hash } => Context::Create {
            wasm_hash: wasm_hash.clone(),
        },
    }
}

fn cond(c: &Caveat) -> Option<Cond> {
    match c {
        Caveat::ContractIn(_) | Caveat::FunctionIn(_) => None,
        Caveat::ArgI128AtMost(index, bound) => Some(Cond::ArgI128AtMost(*index, *bound)),
        Caveat::ArgEq(index, v) => Some(Cond::ArgEq(*index, val(v))),
    }
}

/// `list` restricted to the entries of `before`, when there is one, without
/// repeats.
fn within(before: Option<&[Vec<u8>]>, list: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    for x in list {
        if before.is_none_or(|b| b.contains(x)) && !out.contains(x) {
            out.push(x.clone());
        }
    }
    out
}

/// The rule set `grant` lowers to, or `None` when it names no contract.
pub fn rules(grant: &[Caveat]) -> Option<Vec<Rule>> {
    let mut contracts: Option<Vec<Vec<u8>>> = None;
    let mut functions: Option<Vec<Vec<u8>>> = None;
    for c in grant {
        match c {
            Caveat::ContractIn(list) => contracts = Some(within(contracts.as_deref(), list)),
            Caveat::FunctionIn(list) => functions = Some(within(functions.as_deref(), list)),
            _ => {}
        }
    }
    Some(
        contracts?
            .into_iter()
            .map(|contract| Rule {
                contract,
                functions: match &functions {
                    Some(list) => Functions::Only(list.clone()),
                    None => Functions::AnyExcept(Vec::new()),
                },
                conds: grant.iter().filter_map(cond).collect(),
                signers: Vec::new(),
                threshold: 0,
                cap: None,
                valid_until: None,
                generation: None,
            })
            .collect(),
    )
}

/// What the differential saw.
#[derive(Debug, Default)]
pub struct Seen {
    /// Batches checked on a grant that names its contracts.
    pub compared: usize,
    pub allowed: usize,
    pub denied: usize,
    /// Batches on a grant with no `ContractIn`, which has no lowering.
    pub skipped: usize,
}

/// `grant_eval::chain::allows_all(grant, actions)`, after asserting that
/// `rule_eval::allows_all` over `grant`'s rule set agrees with it, and
/// `rule_eval::allows` with `chain::allows` on each action, when `grant`
/// names its contracts.
pub fn agree(grant: &[Caveat], actions: &[Action], seen: &mut Seen) -> bool {
    let expected = chain::allows_all(grant, actions);
    let Some(rules) = rules(grant) else {
        seen.skipped += 1;
        return expected;
    };
    let contexts: Vec<Context> = actions.iter().map(context).collect();
    assert_eq!(
        rule_eval::allows_all(&rules, &contexts, &[]),
        expected,
        "allows_all on a grant of {} caveats and {} actions",
        grant.len(),
        actions.len()
    );
    for (a, c) in actions.iter().zip(&contexts) {
        assert_eq!(rule_eval::allows(&rules, c, &[]), chain::allows(grant, a));
    }
    seen.compared += 1;
    if expected {
        seen.allowed += 1;
    } else {
        seen.denied += 1;
    }
    expected
}

/// `chain::allows`, checked against `rule_eval` ([`agree`]).
pub fn allows(grant: &[Caveat], action: &Action) -> bool {
    agree(grant, std::slice::from_ref(action), &mut Seen::default())
}

/// `chain::allows_all`, checked against `rule_eval` ([`agree`]).
pub fn allows_all(grant: &[Caveat], actions: &[Action]) -> bool {
    agree(grant, actions, &mut Seen::default())
}
