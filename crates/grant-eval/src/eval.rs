//! The generic grant evaluator, re-exported at the crate root.
//!
//! Each vocabulary's `allows` / `allows_all` calls these through
//! `crate::allows` and `crate::allows_all`. The Lean translation names an item
//! by its definition path relative to the crate, and Lean resolves a bare
//! `allows` inside `def chain.allows` to `chain.allows` itself; defining the
//! generic functions in their own module makes the translated calls
//! `eval.allows` and `eval.allows_all`, which resolve to these.

/// A caveat over actions of type `A`: a predicate a grant requires to hold.
pub trait Check<A> {
    /// Whether this caveat holds for `action`.
    fn holds(&self, action: &A) -> bool;
}

/// Whether `grant` allows `action`: every caveat in `grant` holds for it.
#[must_use]
pub fn allows<A, C: Check<A>>(grant: &[C], action: &A) -> bool {
    let mut i = 0;
    while i < grant.len() {
        if !grant[i].holds(action) {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `grant` allows every action in `actions`.
///
/// A Soroban authorization tree is checked by passing every context in the
/// tree, so one disallowed nested call denies the whole tree.
#[must_use]
pub fn allows_all<A, C: Check<A>>(grant: &[C], actions: &[A]) -> bool {
    let mut i = 0;
    while i < actions.len() {
        if !allows(grant, &actions[i]) {
            return false;
        }
        i += 1;
    }
    true
}
