//! The key tree: depth 16, interior nodes `P2(left, right)`, empty leaf `0`,
//! empty subtrees `Z_0 = 0`, `Z_{i+1} = P2(Z_i, Z_i)` (spec §7.2).
//!
//! Every non-empty node below the root is a persistent entry
//! `Node(level, index)`; a missing entry is the empty subtree `Z_level`.
//! Changing one leaf rewrites the 16 nodes on its path from the 16 siblings,
//! so an update costs the same 16 hashes whatever the tree holds. The root
//! itself lives in the registry state.
//!
//! The empty-subtree table is Perch's (`perch_zk_primitives::ZERO_HASHES`,
//! the depth-32 pool's), whose first 17 entries are this tree's; the tests
//! recompute them.

use crate::hash::Hasher;
use perch_zk_primitives::ZERO_HASHES;
use soroban_sdk::{contracttype, BytesN, Env, Vec};

/// `REGISTRY_DEPTH` (spec §7.2).
pub const REGISTRY_DEPTH: u32 = 16;
/// Leaves a depth-16 tree holds.
pub const REGISTRY_CAPACITY: u32 = 1 << REGISTRY_DEPTH;

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeKey {
    /// A node below the root: level 0 is the leaves.
    Node(u32, u32),
}

fn zero(e: &Env, level: u32) -> BytesN<32> {
    BytesN::from_array(e, &ZERO_HASHES[level as usize])
}

/// `Z_16`, the root of the empty tree. It is never an acceptable root: no
/// key could be proven under it.
#[must_use]
pub fn empty_root(e: &Env) -> BytesN<32> {
    zero(e, REGISTRY_DEPTH)
}

fn bump(e: &Env, key: &TreeKey) {
    let max = e.storage().max_ttl();
    e.storage().persistent().extend_ttl(key, max, max);
}

fn bump_if_present(e: &Env, key: &TreeKey) {
    if e.storage().persistent().has(key) {
        bump(e, key);
    }
}

/// The node at `level`, `index`.
#[must_use]
pub fn node(e: &Env, level: u32, index: u32) -> BytesN<32> {
    e.storage()
        .persistent()
        .get(&TreeKey::Node(level, index))
        .unwrap_or_else(|| zero(e, level))
}

/// Set leaf `index` to `leaf` (`0` empties it) and return the new root.
/// Entries equal to their empty subtree are removed rather than stored.
pub fn set_leaf(e: &Env, h: &mut Hasher, index: u32, leaf: &BytesN<32>) -> BytesN<32> {
    let storage = e.storage().persistent();
    let mut cur = leaf.clone();
    let mut at = index;
    for level in 0..REGISTRY_DEPTH {
        let key = TreeKey::Node(level, at);
        if cur == zero(e, level) {
            storage.remove(&key);
        } else {
            storage.set(&key, &cur);
            bump(e, &key);
        }
        let sibling_key = TreeKey::Node(level, at ^ 1);
        bump_if_present(e, &sibling_key);
        let sibling = node(e, level, at ^ 1);
        cur = if at & 1 == 0 {
            h.node(&cur, &sibling)
        } else {
            h.node(&sibling, &cur)
        };
        at >>= 1;
    }
    cur
}

/// The 16 siblings of leaf `index`'s path in the current tree, from the leaf
/// level up: the Merkle witness the circuit takes (spec §6.2 C6).
#[must_use]
pub fn siblings(e: &Env, index: u32) -> Vec<BytesN<32>> {
    let mut out = Vec::new(e);
    let mut at = index;
    for level in 0..REGISTRY_DEPTH {
        out.push_back(node(e, level, at ^ 1));
        at >>= 1;
    }
    out
}

/// The root of a depth-16 tree whose leaves `0..leaves.len()` are `leaves`
/// and whose other leaves are empty, computed in memory. For trees built off
/// chain with the registry's hashing, such as a guardian's key pin tree
/// (spec §7.4).
///
/// # Panics
/// If there are more than [`REGISTRY_CAPACITY`] leaves.
#[must_use]
pub fn root_of(e: &Env, leaves: &[BytesN<32>]) -> BytesN<32> {
    assert!(
        leaves.len() <= REGISTRY_CAPACITY as usize,
        "too many leaves"
    );
    let mut h = Hasher::new(e);
    let mut cur: Vec<BytesN<32>> = Vec::new(e);
    for leaf in leaves {
        cur.push_back(leaf.clone());
    }
    for level in 0..REGISTRY_DEPTH {
        if cur.is_empty() {
            return empty_root(e);
        }
        let mut next = Vec::new(e);
        let mut i = 0;
        while i < cur.len() {
            let left = cur.get_unchecked(i);
            let right = cur.get(i + 1).unwrap_or_else(|| zero(e, level));
            next.push_back(h.node(&left, &right));
            i += 2;
        }
        cur = next;
    }
    cur.get(0).unwrap_or_else(|| empty_root(e))
}

/// Extend leaf `index`'s path and its siblings to the network's maximum TTL.
pub fn renew_path(e: &Env, index: u32) {
    let mut at = index;
    for level in 0..REGISTRY_DEPTH {
        bump_if_present(e, &TreeKey::Node(level, at));
        bump_if_present(e, &TreeKey::Node(level, at ^ 1));
        at >>= 1;
    }
}
