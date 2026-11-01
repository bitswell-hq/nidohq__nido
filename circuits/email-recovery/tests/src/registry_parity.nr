//! The circuit's key hash, registry leaf and Merkle root against the DKIM key
//! registry contract's host-side Poseidon2 (`soroban-poseidon`).
//!
//! The moduli are the registry's fixture keys
//! (`contracts/dkim-registry/vectors/src/inputs.nr`, converted to limbs by
//! the test-vector generator). Every expected value below is one that
//! `contracts/dkim-registry/src/test.rs::noir_vectors` asserts the contract
//! computes, so equality here means the circuit and the chain hash the same
//! way (spec sections 7.1 and 7.2).

use crate::vectors::{REGISTRY_MODULUS_A, REGISTRY_MODULUS_B, REGISTRY_MODULUS_C};
use email_recovery::pack::key_hash;
use email_recovery::registry::{empty_subtree, merkle_root, registry_leaf};
use poseidon::poseidon2::Poseidon2;

global KEY_A: Field = 0x25a7dd9c7d1722237f60c18f7e981754bacb873259d63ffc9114caacdb4bcdae;
global KEY_B: Field = 0x0612361cdce4d414bbcb22c64e24fe37a2e1e546d506d19176c5a0237d0aaa00;
global KEY_C: Field = 0x12abba657357fe88dfc265e30573e1924ba02888c9338454f097b739c9519115;
global LEAF_A: Field = 0x27f86eaf8edb3e0731742dcb5d4224053934a67a158915aef1cceaaf0d769169;
global LEAF_B: Field = 0x13507fa59f3214cee8a827a2b87eaab25f32ac2b62e14586173376a423b953b9;
global LEAF_C: Field = 0x212a001de51855c45d590f4c72f7d7575c841fcc1cc515553e2faedcf956c9b8;
/// The root with A at index 0.
global ROOT_A: Field = 0x22da6e7490012cd3daa3edab29388c9ab80ffeea19aa956f35ad9da0600d8319;
/// The root with A, B and C at indices 0, 1 and 2.
global ROOT_ABC: Field = 0x08fd83d83b64b3be8f9af81baeca40cbd5ea0ce9960e877254df996a1d4c927c;
/// The root after B is retired (its leaf set back to 0).
global ROOT_AC: Field = 0x23cce8ab300369c2220682360665ee0218df244953b2753de7e011d716181a3c;
/// The root of the empty tree.
global ROOT_EMPTY: Field = 0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3;

fn domain<let L: u32>(bytes: [u8; L]) -> BoundedVec<u8, 62> {
    let mut storage = [0; 62];
    for i in 0..L {
        storage[i] = bytes[i];
    }
    BoundedVec::from_parts_unchecked(storage, L)
}

fn empty_siblings() -> [Field; 16] {
    let mut s = [0; 16];
    for i in 0..16 {
        s[i] = empty_subtree(i);
    }
    s
}

#[test]
fn key_hashes_match_the_registry() {
    assert(key_hash(REGISTRY_MODULUS_A) == KEY_A);
    assert(key_hash(REGISTRY_MODULUS_B) == KEY_B);
    assert(key_hash(REGISTRY_MODULUS_C) == KEY_C);
}

#[test]
fn leaves_match_the_registry() {
    assert(registry_leaf(domain("gmail.com".as_bytes()), KEY_A) == LEAF_A);
    assert(registry_leaf(domain("outlook.com".as_bytes()), KEY_B) == LEAF_B);
    assert(registry_leaf(domain("fastmail.com".as_bytes()), KEY_C) == LEAF_C);
}

#[test]
fn roots_match_the_registry() {
    assert(empty_subtree(16) == ROOT_EMPTY);
    let mut siblings = empty_siblings();
    assert(merkle_root(LEAF_A, 0, siblings) == ROOT_A);
    // C at index 2: its sibling at level 0 is the empty index 3, at level 1
    // the node over A and B.
    siblings[1] = Poseidon2::hash([LEAF_A, LEAF_B], 2);
    assert(merkle_root(LEAF_C, 2, siblings) == ROOT_ABC);
    siblings[1] = Poseidon2::hash([LEAF_A, 0], 2);
    assert(merkle_root(LEAF_C, 2, siblings) == ROOT_AC);
}
