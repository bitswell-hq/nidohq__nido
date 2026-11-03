//! The `rule-eval` this contract links against rule-core's budget traces of
//! the same rev (`conformance/vectors/budget`, or the `budget` directory
//! under the one `CONFORMANCE_VECTORS` names): every spend, delegation and
//! refill outcome the Lean model computes.

use rule_eval_conformance::budget::{check, load_dir};

#[test]
fn rule_eval_agrees_with_every_budget_trace() {
    let dir = rule_eval_conformance::vectors_dir().join("budget");
    let traces = load_dir(&dir).unwrap_or_else(|e| panic!("{e}"));
    assert!(!traces.is_empty(), "no budget traces in {}", dir.display());
    let failures: Vec<String> = traces
        .iter()
        .filter_map(|(path, t)| check(t).err().map(|e| format!("{}: {e}", path.display())))
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    println!("{} budget traces agree", traces.len());
}
