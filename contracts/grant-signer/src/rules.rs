//! A grant's rule set, as `rule_eval` reads it: the root grant's stored
//! rules, with every delegation's attenuation steps replayed on them, root
//! first.
//!
//! Stored rules are read with `perch_rule_eval`'s one reading of a
//! `StoredRule` (`StoredRule::to_rule`), and a step's addresses, symbols and
//! signers with its conversions of host values (`perch_rule_eval::convert`),
//! so a rule names a contract, an address argument or a signer by its
//! `ScAddress` XDR, as the contexts `__check_auth` reads through
//! `soroban-facade` do.

use alloc::vec::Vec as AVec;
use perch_rule_eval::{convert, StoredCap, StoredCond, StoredRule, StoredVal};
use rule_eval::{AttenuationError, Cap, Cond, Context, Rule, Signer};
use soroban_sdk::{Env, Symbol, Vec};

use crate::error::GrantError as Error;
use crate::{Grant, Step};

/// `rules` as `rule_eval` reads them.
///
/// # Errors
///
/// [`Error::InvalidRules`] if a rule holds more than one cap.
fn read(e: &Env, rules: &Vec<StoredRule>) -> Result<AVec<Rule>, Error> {
    rules
        .iter()
        .map(|r| r.to_rule(e).ok_or(Error::InvalidRules))
        .collect()
}

/// Whether `rules` may be a root grant's rule set: every rule holds at most
/// one cap, every cap is valid (`rule_eval::cap_valid`, which
/// `rule_eval::authorize` leaves to the shell that installs a root), and
/// every rule carries the same generation.
///
/// # Errors
///
/// [`Error::InvalidRules`] if they may not.
pub fn check_root(e: &Env, rules: &Vec<StoredRule>) -> Result<(), Error> {
    let read = read(e, rules)?;
    let first = read.first().map(|r| r.generation);
    for r in &read {
        if r.cap.as_ref().is_some_and(|c| !rule_eval::cap_valid(c)) || Some(r.generation) != first {
            return Err(Error::InvalidRules);
        }
    }
    Ok(())
}

/// The rule set of the last grant of `lineage`, a grant and its ancestors,
/// root first: the root's rules with each later grant's steps replayed on
/// them in order.
///
/// # Errors
///
/// [`Error::InvalidRules`] or [`Error::InvalidStep`] for a rule or step that
/// does not read or apply, which no grant `issue` or `delegate` stored holds.
pub fn of_lineage(e: &Env, lineage: &[(u32, Grant)]) -> Result<AVec<Rule>, Error> {
    let mut rules = AVec::new();
    for (_, grant) in lineage {
        if grant.parent.is_none() {
            rules = read(e, &grant.rules)?;
        }
        rules = attenuate(e, rules, &grant.steps)?;
    }
    Ok(rules)
}

/// `rules` with every step of `steps` applied in order.
///
/// # Errors
///
/// [`Error::InvalidStep`] if `rule_eval` refuses a step, or a step names an
/// address, symbol or signer with no `rule_eval` form.
pub fn attenuate(e: &Env, rules: AVec<Rule>, steps: &Vec<Step>) -> Result<AVec<Rule>, Error> {
    let mut rules = rules;
    for s in steps.iter() {
        rules = step(e, &rules, &s)
            .ok_or(Error::InvalidStep)?
            .map_err(|_: AttenuationError| Error::InvalidStep)?;
    }
    Ok(rules)
}

/// `rule_eval`'s attenuation step `s` on `rules`, or `None` when `s` names a
/// value with no `rule_eval` form.
fn step(e: &Env, rules: &[Rule], s: &Step) -> Option<Result<AVec<Rule>, AttenuationError>> {
    Some(match s {
        Step::DropRule(i) => rule_eval::drop_rule(rules, *i),
        Step::AddCond(i, c) => rule_eval::add_cond(rules, *i, &cond(e, c)?),
        Step::RemoveFunctions(i, f) => rule_eval::remove_functions(rules, *i, &symbols(e, f)?),
        Step::RestrictFunctions(i, f) => rule_eval::restrict_functions(rules, *i, &symbols(e, f)?),
        Step::RemoveSigners(i, list) => {
            let list: AVec<Signer> = convert::signers(e, list)?;
            rule_eval::remove_signers(rules, *i, &list)
        }
        Step::RaiseThreshold(i, t) => rule_eval::raise_threshold(rules, *i, *t),
        Step::AddCap(i, c) => rule_eval::add_cap(rules, *i, &cap(c)),
        Step::LowerCapLimit(i, limit) => rule_eval::lower_cap_limit(rules, *i, *limit),
        Step::LengthenCapPeriod(i, period) => rule_eval::lengthen_cap_period(rules, *i, *period),
        Step::LowerValidUntil(i, last) => rule_eval::lower_valid_until(rules, *i, *last),
    })
}

fn symbols(e: &Env, list: &Vec<Symbol>) -> Option<AVec<AVec<u8>>> {
    list.iter().map(|s| convert::symbol_bytes(e, &s)).collect()
}

fn cap(c: &StoredCap) -> Cap {
    Cap {
        limit: c.limit,
        period: c.period,
        amount_arg: c.amount_arg,
    }
}

fn cond(e: &Env, c: &StoredCond) -> Option<Cond> {
    Some(match c {
        StoredCond::ArgEq(i, v) => Cond::ArgEq(*i, val(e, v)?),
        StoredCond::ArgI128AtMost(i, bound) => Cond::ArgI128AtMost(*i, *bound),
        StoredCond::ArgIn(i, list) => Cond::ArgIn(
            *i,
            list.iter()
                .map(|v| val(e, &v))
                .collect::<Option<AVec<_>>>()?,
        ),
        StoredCond::ArgStrPrefix(i, prefix) => {
            Cond::ArgStrPrefix(*i, convert::string_bytes(prefix))
        }
    })
}

fn val(e: &Env, v: &StoredVal) -> Option<rule_eval::Val> {
    Some(match v {
        StoredVal::I128(n) => rule_eval::Val::I128(*n),
        StoredVal::U64(n) => rule_eval::Val::U64(*n),
        StoredVal::Bool(b) => rule_eval::Val::Bool(*b),
        StoredVal::Bytes(b) => rule_eval::Val::Bytes(b.to_alloc_vec()),
        StoredVal::Address(a) => rule_eval::Val::Address(convert::address(e, a)?),
        StoredVal::Symbol(s) => rule_eval::Val::Symbol(convert::symbol_bytes(e, s)?),
        StoredVal::String(s) => rule_eval::Val::String(convert::string_bytes(s)),
        StoredVal::Other(b) => rule_eval::Val::Other(b.to_alloc_vec()),
    })
}

/// `rules` as stored rules, for the `rules` view.
///
/// # Errors
///
/// [`Error::InvalidRules`] if a rule names an address or symbol with no host
/// form, which no rule read from a stored rule or a step does.
pub fn stored(e: &Env, rules: &[Rule]) -> Result<Vec<StoredRule>, Error> {
    let mut out = Vec::new(e);
    for r in rules {
        out.push_back(StoredRule::from_rule(e, r).ok_or(Error::InvalidRules)?);
    }
    Ok(out)
}

/// The generation every rule of `rules` carries, or 0 when none carries
/// one. `rule_eval::authorize` then refuses no rule of the set as stale: the
/// account's own check of the rule chosen there holds the generation.
#[must_use]
pub fn generation(rules: &[Rule]) -> u64 {
    rules.iter().find_map(|r| r.generation).unwrap_or(0)
}

/// For each context, the index of the first rule of `rules` that allows it
/// under `authenticated` (`rule_eval::rule_allows`); `None` if some context
/// has none.
#[must_use]
pub fn choices(
    rules: &[Rule],
    contexts: &[Context],
    authenticated: &[Signer],
) -> Option<AVec<u32>> {
    contexts
        .iter()
        .map(|c| {
            let i = rules
                .iter()
                .position(|r| rule_eval::rule_allows(r, c, authenticated))?;
            u32::try_from(i).ok()
        })
        .collect()
}
