//! The `rule-eval` and `soroban-facade` this contract links against every
//! vector rule-core carries at the same rev that covers what it calls: the
//! rule-set and attenuation vectors (`conformance/vectors/*.json`), the cap
//! and authorization traces (`caps`, `authorize`), the budget traces
//! (`budget`), and the facade's Soroban value and context vectors
//! (`soroban/values`, `soroban/contexts`). The Lean model computes every
//! expected result, so a failure here is a difference between the linked
//! code and the model it is proven against.
//!
//! The vectors are read from `rule_eval_conformance::vectors_dir()`: the
//! `conformance/vectors` directory of cargo's checkout of the same rev, or
//! the directory `CONFORMANCE_VECTORS` names.

use std::path::PathBuf;

use rule_eval_conformance::{authorize, budget, caps, soroban};

/// Every failure of `check` over `vectors`, one line each; panics when there
/// are no vectors, so a moved directory cannot pass as an empty one.
fn failures<T>(
    kind: &str,
    vectors: Result<Vec<(PathBuf, T)>, String>,
    check: impl Fn(&T) -> Result<(), String>,
) -> Vec<String> {
    let vectors = vectors.unwrap_or_else(|e| panic!("{kind}: {e}"));
    assert!(!vectors.is_empty(), "{kind}: no vectors found");
    println!("{kind}: {} vectors agree", vectors.len());
    vectors
        .iter()
        .filter_map(|(path, v)| check(v).err().map(|e| format!("{}: {e}", path.display())))
        .collect()
}

fn assert_none(failed: &[String]) {
    assert!(failed.is_empty(), "{}", failed.join("\n"));
}

fn root() -> PathBuf {
    rule_eval_conformance::vectors_dir()
}

#[test]
fn rule_eval_agrees_with_every_rule_and_attenuation_vector() {
    assert_none(&failures(
        "rules",
        rule_eval_conformance::load_dir(&root()),
        rule_eval_conformance::check,
    ));
}

#[test]
fn rule_eval_agrees_with_every_cap_trace() {
    assert_none(&failures(
        "caps",
        caps::load_dir(&root().join("caps")),
        caps::check,
    ));
}

#[test]
fn rule_eval_agrees_with_every_authorization_trace() {
    assert_none(&failures(
        "authorize",
        authorize::load_dir(&root().join("authorize")),
        authorize::check,
    ));
}

#[test]
fn rule_eval_agrees_with_every_budget_trace() {
    assert_none(&failures(
        "budget",
        budget::load_dir(&root().join("budget")),
        budget::check,
    ));
}

#[test]
fn soroban_facade_agrees_with_every_value_and_context_vector() {
    let mut failed = failures(
        "soroban values",
        soroban::load_dir(&soroban::vectors_dir("values")),
        soroban::check_values,
    );
    failed.extend(failures(
        "soroban contexts",
        soroban::load_dir(&soroban::vectors_dir("contexts")),
        soroban::check_context,
    ));
    assert_none(&failed);
}
