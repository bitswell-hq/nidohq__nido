//! Budgets: allowances along the delegation tree.
//!
//! The ledger holds one [`Node`] per grant: its allowance, the amount spent
//! at or under it, and a link to its parent toward the root. A parent
//! precedes its children, so every parent link points to a smaller index.
//!
//! Children's allowances may sum to more than their parent's. A spend
//! charges the spender and every ancestor up to the root as one transaction:
//! [`check_spend`] walks the chain and fails at the first node, counting
//! from the spender, that would be overdrawn; only if no node fails does
//! [`spend`] charge them. A failed spend changes nothing, and its error names
//! the node a refill request goes to. [`refill`] raises one node's allowance
//! and is an admin-document action, never an agent's.
//!
//! The tree grows by [`append`]: delegating a grant adds a node under the
//! delegator's, with any allowance, and issuing a new root grant (an
//! admin-document action) adds a node with no parent. A new node has nothing
//! spent and the next index, so parents still precede their children.
//!
//! The readable Lean model is `formal/AttenuatingGrants/Budget.lean`.

use alloc::vec::Vec;

/// One grant's allowance.
pub struct Node {
    /// The parent's index, or `None` for a root.
    pub parent: Option<usize>,
    pub allowance: u128,
    /// Every successful spend at or under this node.
    pub spent: u128,
}

/// Why a spend failed. The ledger is unchanged.
pub enum SpendError {
    /// No node has this index.
    NoSuchNode(usize),
    /// This node's parent link does not point to a smaller index.
    BadParent(usize),
    /// Charging this node would take its spent past its allowance.
    Overdrawn(usize),
}

/// Why a refill failed. The ledger is unchanged.
pub enum RefillError {
    /// No node has this index.
    NoSuchNode(usize),
    /// The raised allowance would not fit in a `u128`.
    Overflow(usize),
}

/// Why an append failed. The ledger is unchanged.
pub enum AppendError {
    /// No node has the parent's index.
    NoSuchNode(usize),
}

/// Whether `node` can take `amount`: `spent + amount` exists and is at most
/// the allowance. An overflowing sum exceeds every `u128` allowance.
#[must_use]
pub fn fits(node: &Node, amount: u128) -> bool {
    match node.spent.checked_add(amount) {
        Some(total) => total <= node.allowance,
        None => false,
    }
}

/// Whether a spend of `amount` at `node` would succeed: walks from `node`
/// to its root and returns the first failure.
///
/// # Errors
///
/// [`SpendError::Overdrawn`] names the first node on the chain, counting from
/// `node`, that cannot take `amount`. [`SpendError::NoSuchNode`] and
/// [`SpendError::BadParent`] report a malformed ledger.
pub fn check_spend(ledger: &[Node], node: usize, amount: u128) -> Result<(), SpendError> {
    let mut current = node;
    let mut step = 0;
    while step < ledger.len() {
        let Some(n) = ledger.get(current) else {
            return Err(SpendError::NoSuchNode(current));
        };
        if !fits(n, amount) {
            return Err(SpendError::Overdrawn(current));
        }
        match n.parent {
            None => return Ok(()),
            Some(parent) => {
                if parent >= current {
                    return Err(SpendError::BadParent(current));
                }
                current = parent;
            }
        }
        step += 1;
    }
    // Every step moves to a smaller index, so a walk from an existing node
    // ends inside the loop; this is reached only on an empty ledger.
    Err(SpendError::NoSuchNode(current))
}

/// Add `amount` to `node` and every ancestor. Called only after
/// [`check_spend`] succeeded for the same ledger, node and amount.
fn charge(ledger: &mut [Node], node: usize, amount: u128) {
    let mut current = node;
    let mut step = 0;
    while step < ledger.len() {
        let Some(n) = ledger.get_mut(current) else {
            return;
        };
        // Cannot overflow: `check_spend` found `n.spent + amount` within
        // `n.allowance`, and this walk visits each node of that chain once.
        n.spent += amount;
        match n.parent {
            None => return,
            Some(parent) => current = parent,
        }
        step += 1;
    }
}

/// Spend `amount` at `node`, charging it and every ancestor up to the root.
///
/// # Errors
///
/// The error [`check_spend`] returns. On error the ledger is unchanged.
pub fn spend(ledger: &mut [Node], node: usize, amount: u128) -> Result<(), SpendError> {
    match check_spend(ledger, node, amount) {
        Ok(()) => {
            charge(ledger, node, amount);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Raise `node`'s allowance by `extra`. An admin-document action.
///
/// # Errors
///
/// [`RefillError::NoSuchNode`] if `node` is out of range,
/// [`RefillError::Overflow`] if the new allowance would not fit in a `u128`.
/// On error the ledger is unchanged.
pub fn refill(ledger: &mut [Node], node: usize, extra: u128) -> Result<(), RefillError> {
    let Some(n) = ledger.get_mut(node) else {
        return Err(RefillError::NoSuchNode(node));
    };
    match n.allowance.checked_add(extra) {
        Some(allowance) => {
            n.allowance = allowance;
            Ok(())
        }
        None => Err(RefillError::Overflow(node)),
    }
}

/// Add a node with `allowance` and nothing spent under `parent`, or as a new
/// root for `None`, and return its index. The allowance may exceed the
/// parent's: delegation can oversubscribe.
///
/// `Vec::push` allocates, and a failed allocation aborts; every other path
/// returns.
///
/// # Errors
///
/// [`AppendError::NoSuchNode`] if `parent` is out of range. The ledger is
/// then unchanged.
pub fn append(
    ledger: &mut Vec<Node>,
    parent: Option<usize>,
    allowance: u128,
) -> Result<usize, AppendError> {
    let index = ledger.len();
    if let Some(p) = parent {
        if p >= index {
            return Err(AppendError::NoSuchNode(p));
        }
    }
    ledger.push(Node {
        parent,
        allowance,
        spent: 0,
    });
    Ok(index)
}
