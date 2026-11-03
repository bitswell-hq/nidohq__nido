//! The budget path over `rule_eval`'s budget tree.
//!
//! Grants store `u128` allowances and spent amounts; `rule_eval` counts in
//! `i128`. Every allowance this contract stores is at most `i128::MAX`
//! ([`amount`] refuses a larger one at `issue`, `delegate` and `refill`),
//! and a grant's spent amount never exceeds its allowance, so each stored
//! value is a `rule_eval` amount. No Stellar Asset Contract transfer moves
//! more than `i128::MAX`, so the bound refuses no reachable spend.
//!
//! The functions are pure: the contract loads the lineage, passes its
//! allowances and spent amounts in, and stores what they return only on
//! `Ok`. The unit tests check them against `grant_eval::budget` on lineage
//! ledgers.

use alloc::vec::Vec;
use rule_eval::{BudgetError, Node};

use crate::error::GrantError as Error;

/// `amount` as a `rule_eval` amount.
///
/// # Errors
///
/// [`Error::AllowanceTooLarge`] if `amount` is above `i128::MAX`.
pub fn amount(amount: u128) -> Result<i128, Error> {
    i128::try_from(amount).map_err(|_| Error::AllowanceTooLarge)
}

/// A non-negative `rule_eval` amount as stored.
fn stored(amount: i128) -> u128 {
    // `rule_eval` refuses negative amounts and keeps every node's allowance
    // and spent amount non-negative.
    amount.unsigned_abs()
}

/// The budget tree of a lineage, from each grant's allowance and spent
/// amount, root first: node `k`'s parent is node `k - 1` (`Ledger.chain` in
/// `formal/`).
///
/// # Errors
///
/// [`Error::AllowanceTooLarge`] if a value is above `i128::MAX`, which no
/// grant this contract stored holds.
pub fn chain(grants: &[(u128, u128)]) -> Result<Vec<Node>, Error> {
    let mut out = Vec::new();
    let mut parent = None;
    for (i, &(allowance, spent)) in grants.iter().enumerate() {
        out.push(Node {
            parent,
            allowance: amount(allowance)?,
            spent: amount(spent)?,
        });
        // A lineage holds at most one grant per `u32` id.
        parent = Some(u32::try_from(i).map_err(|_| Error::Overflow)?);
    }
    Ok(out)
}

/// The spent amount of each node of `tree` after spending every amount of
/// `amounts`, in order, at its last node: `Ledger.spendAll` in `formal/`.
/// All or nothing: the first refusal refuses the whole batch.
///
/// # Errors
///
/// [`Error::Overdrawn`] if a spend would take a node past its allowance.
pub fn spend_all(tree: Vec<Node>, amounts: &[u128]) -> Result<Vec<u128>, Error> {
    let spender = last(&tree);
    let mut tree = tree;
    for &amount in amounts {
        // A transfer's amount is a non-negative `i128`, so this converts.
        let amount = self::amount(amount).map_err(|_| Error::Overdrawn)?;
        tree = rule_eval::spend(&tree, spender, amount).map_err(|_| Error::Overdrawn)?;
    }
    Ok(tree.iter().map(|n| stored(n.spent)).collect())
}

/// The index of the nearest node of `tree`, from its last node toward the
/// root, that cannot take a spend of `amount`; `None` if the spend fits.
#[must_use]
pub fn overdrawn_at(tree: &[Node], amount: u128) -> Option<usize> {
    let spender = last(tree);
    let Ok(amount) = i128::try_from(amount) else {
        // Above every allowance, so the spender's own node refuses it first.
        return Some(spender as usize);
    };
    match rule_eval::spend(tree, spender, amount) {
        Err(BudgetError::Overdrawn(i)) => Some(i as usize),
        // A tree built by `chain` is well formed and the amount is
        // non-negative, so `spend` refuses only with `Overdrawn`.
        _ => None,
    }
}

/// A grant's allowance after a refill of `extra`, on a tree of the one grant
/// (`Ledger.refillGrant` in `formal/`).
///
/// # Errors
///
/// [`Error::AllowanceTooLarge`] if `extra` or the raised allowance is above
/// `i128::MAX`.
pub fn refill(allowance: u128, spent: u128, extra: u128) -> Result<u128, Error> {
    let tree = chain(&[(allowance, spent)])?;
    match rule_eval::refill(&tree, 0, amount(extra)?) {
        Ok(tree) => Ok(stored(tree[0].allowance)),
        Err(_) => Err(Error::AllowanceTooLarge),
    }
}

/// The index of `tree`'s last node, the signing grant's.
fn last(tree: &[Node]) -> u32 {
    // `chain` gives each node a `u32` index, and a lineage has its signing
    // grant, so the tree is not empty.
    u32::try_from(tree.len().saturating_sub(1)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests;
