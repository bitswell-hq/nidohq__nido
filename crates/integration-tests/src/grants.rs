//! Grants written as chain caveats, lowered onto the grant signer's rule sets
//! (`contracts/grant-signer`).
//!
//! The tests and the evaluation write a grant as the relay's configuration
//! writes a chain grant: a list of [`Caveat`]s naming contracts and
//! functions by their text and argument values as [`Arg`]s. [`root`] lowers
//! a root grant's caveats to the rule set `issue` takes, and [`steps`] a
//! delegation's added caveats to the attenuation steps `delegate` takes, as
//! the relay lowers a chain grant (`grant_relay::config::chain_rules`):
//!
//! - one rule per contract every `ContractIn` names (in the first one's
//!   order, without repeats); a later `ContractIn` drops the rules on the
//!   contracts it leaves out;
//! - each rule matches the functions every `FunctionIn` names, or every
//!   function when there is none; a later `FunctionIn` restricts each rule
//!   to the functions it names;
//! - every argument caveat is a condition on every rule.
//!
//! So a lowered grant allows a context exactly when every caveat holds for
//! it, as `grant_eval::chain::allows` decides on the caveats themselves
//! (`crates/grant-eval/tests/rule_eval.rs` checks this lowering's meaning
//! against the chain evaluator, and `grant_signer_corpus` this module against
//! a recorded run of a grant signer that stored the caveats). Every rule is
//! signed by the grant signer alone, with a threshold of 1, as an agent's
//! scoped rule is.

use nido_grant_signer::{Step, StoredCond, StoredFunctions, StoredRule, StoredVal};
use soroban_sdk::xdr::FromXdr;
use soroban_sdk::{Address, Bytes, Env, MuxedAddress, Symbol, Val, Vec};
use stellar_accounts::smart_account::Signer;

/// A contract-call argument value, as the relay's configuration writes one:
/// an address by its strkey, a symbol by its text, and `Other` the full
/// `ScVal` XDR of an argument of a type the other variants do not model (a
/// string's included).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Arg {
    I128(i128),
    U64(u64),
    Bool(bool),
    Bytes(Bytes),
    Address(Bytes),
    Symbol(Bytes),
    Other(Bytes),
}

/// A chain caveat. Contracts are named by their strkey (`C…`) and functions
/// by their symbol's text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Caveat {
    ContractIn(Vec<Bytes>),
    FunctionIn(Vec<Bytes>),
    ArgI128AtMost(u32, i128),
    ArgEq(u32, Arg),
}

fn text(b: &Bytes) -> std::string::String {
    std::string::String::from_utf8(b.to_alloc_vec()).expect("stored as text")
}

fn address(e: &Env, b: &Bytes) -> Address {
    Address::from_str(e, &text(b))
}

fn symbols(e: &Env, list: &Vec<Bytes>) -> Vec<Symbol> {
    Vec::from_iter(e, list.iter().map(|f| Symbol::new(e, &text(&f))))
}

/// The host value an argument with value `a` holds.
///
/// # Panics
///
/// For an `Other` that is not the XDR of a value.
#[must_use]
pub fn host_value(e: &Env, a: &Arg) -> Val {
    use soroban_sdk::IntoVal;
    match a {
        Arg::I128(n) => n.into_val(e),
        Arg::U64(n) => n.into_val(e),
        Arg::Bool(b) => b.into_val(e),
        Arg::Bytes(b) => b.into_val(e),
        Arg::Address(b) if text(b).starts_with('M') => {
            MuxedAddress::from(Address::from_str(e, &text(b))).into_val(e)
        }
        Arg::Address(b) => address(e, b).into_val(e),
        Arg::Symbol(b) => Symbol::new(e, &text(b)).into_val(e),
        Arg::Other(b) => Val::from_xdr(e, b).expect("the XDR of a value"),
    }
}

/// The condition value an argument with value `a` matches: the grant
/// signer's reading of that argument (`perch_rule_eval::convert::val`), in
/// its stored form.
///
/// # Panics
///
/// For a value with no stored form, a muxed address.
#[must_use]
pub fn value(e: &Env, a: &Arg) -> StoredVal {
    let v = perch_rule_eval::convert::val(e, host_value(e, a)).expect("a value the facade reads");
    StoredVal::from_val(e, &v).expect("a value with a stored form")
}

/// The condition an argument caveat stands for.
fn cond(e: &Env, c: &Caveat) -> Option<StoredCond> {
    match c {
        Caveat::ContractIn(_) | Caveat::FunctionIn(_) => None,
        Caveat::ArgI128AtMost(i, bound) => Some(StoredCond::ArgI128AtMost(*i, *bound)),
        Caveat::ArgEq(i, a) => Some(StoredCond::ArgEq(*i, value(e, a))),
    }
}

/// `list` restricted to the entries of `before`, when there is one, without
/// repeats.
fn within(before: Option<&Vec<Bytes>>, list: &Vec<Bytes>) -> Vec<Bytes> {
    let mut out = Vec::new(list.env());
    for x in list.iter() {
        if before.is_none_or(|b| b.contains(&x)) && !out.contains(&x) {
            out.push_back(x);
        }
    }
    out
}

/// The rule set a root grant with `caveats` lowers to, signed by the grant
/// signer `signer`, with no cap, last ledger or generation.
///
/// # Panics
///
/// If no caveat is `ContractIn`: a rule set names the contracts it allows.
#[must_use]
pub fn root(e: &Env, signer: &Address, caveats: &[Caveat]) -> Vec<StoredRule> {
    let mut contracts = None;
    let mut functions = None;
    for c in caveats {
        match c {
            Caveat::ContractIn(list) => contracts = Some(within(contracts.as_ref(), list)),
            Caveat::FunctionIn(list) => functions = Some(within(functions.as_ref(), list)),
            _ => {}
        }
    }
    let contracts = contracts.expect("a root grant names its contracts");
    let functions = match functions {
        Some(list) => StoredFunctions::Only(symbols(e, &list)),
        None => StoredFunctions::AnyExcept(Vec::new(e)),
    };
    let conds = Vec::from_iter(e, caveats.iter().filter_map(|c| cond(e, c)));
    Vec::from_iter(
        e,
        contracts.iter().map(|c| StoredRule {
            contract: address(e, &c),
            functions: functions.clone(),
            conds: conds.clone(),
            signers: Vec::from_array(e, [Signer::Delegated(signer.clone())]),
            threshold: 1,
            cap: Vec::new(e),
            valid_until: None,
            generation: None,
        }),
    )
}

/// The attenuation steps that add `added` to a grant whose rule set is
/// `parent`: a `ContractIn` drops every rule on a contract it leaves out
/// (from the last), a `FunctionIn` restricts every rule to its functions,
/// and an argument caveat adds its condition to every rule.
#[must_use]
pub fn steps(e: &Env, parent: &Vec<StoredRule>, added: &[Caveat]) -> Vec<Step> {
    let mut contracts: std::vec::Vec<Address> = parent.iter().map(|r| r.contract).collect();
    let mut out = Vec::new(e);
    for c in added {
        let cond = cond(e, c);
        match c {
            Caveat::ContractIn(list) => {
                let named: std::vec::Vec<Address> = list.iter().map(|b| address(e, &b)).collect();
                for i in (0..contracts.len()).rev() {
                    if !named.contains(&contracts[i]) {
                        out.push_back(Step::DropRule(index(i)));
                        contracts.remove(i);
                    }
                }
            }
            Caveat::FunctionIn(list) => {
                for i in 0..contracts.len() {
                    out.push_back(Step::RestrictFunctions(index(i), symbols(e, list)));
                }
            }
            Caveat::ArgI128AtMost(..) | Caveat::ArgEq(..) => {
                for i in 0..contracts.len() {
                    out.extend(cond.iter().map(|c| Step::AddCond(index(i), c.clone())));
                }
            }
        }
    }
    out
}

fn index(i: usize) -> u32 {
    u32::try_from(i).expect("a rule index")
}
