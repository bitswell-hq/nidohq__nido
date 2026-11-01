//! Packing and the spec's P2 hashes: the address commitment, the key hash,
//! the registry leaf and Merkle root.

use crate::vectors::{KEY_A_MODULUS, KEY_B_MODULUS};
use email_recovery::pack::{address_commitment, key_hash, pack_bytes};
use email_recovery::registry::{empty_subtree, merkle_root, registry_leaf};
use poseidon::poseidon2::Poseidon2;

#[test]
fn packing_is_big_endian_31_bytes_per_element() {
    let mut bytes = [0; 33];
    for i in 0..33 {
        bytes[i] = (i + 1) as u8;
    }
    let packed = pack_bytes(bytes);
    assert(packed.len() == 2);
    let mut first: Field = 0;
    for i in 0..31 {
        first = first * 256 + (i + 1) as Field;
    }
    assert(packed[0] == first);
    // Element 1 holds bytes 31 and 32, then 29 zero bytes.
    let mut shift: Field = 1;
    for _ in 0..29 {
        shift *= 256;
    }
    assert(packed[1] == (32 * 256 + 33) * shift);
}

fn vec_of<let L: u32, let M: u32>(bytes: [u8; L], len: u32) -> BoundedVec<u8, M> {
    let mut storage = [0; M];
    for i in 0..L {
        storage[i] = bytes[i];
    }
    BoundedVec::from_parts_unchecked(storage, len)
}

/// C = P2(DOM_COMMIT, len, pack(address, 124), account_code), spelled out.
#[test]
fn commitment_follows_the_spec_formula() {
    let address: BoundedVec<u8, 124> = vec_of("alice@gmail.com".as_bytes(), 15);
    let a = pack_bytes(address.storage());
    let expected = Poseidon2::hash(
        [email_recovery::spec::DOM_COMMIT, 15, a[0], a[1], a[2], a[3], 7],
        7,
    );
    assert(address_commitment(address, 7) == expected);
}

#[test]
fn commitment_binds_address_code_and_length() {
    let a: BoundedVec<u8, 124> = vec_of("alice@gmail.com".as_bytes(), 15);
    let b: BoundedVec<u8, 124> = vec_of("alice@gmail.con".as_bytes(), 15);
    let c = address_commitment(a, 7);
    assert(c != address_commitment(a, 8));
    assert(c != address_commitment(b, 7));
    // Same storage, one more zero byte inside the length.
    assert(c != address_commitment(vec_of("alice@gmail.com".as_bytes(), 16), 7));
}

#[test(should_fail_with = "pack: bytes past the length must be zero")]
fn commitment_refuses_bytes_past_the_length() {
    let _ = address_commitment(vec_of("alice@gmail.com".as_bytes(), 14), 7);
}

#[test(should_fail_with = "pack: length out of bounds")]
fn commitment_refuses_an_empty_address() {
    let _ = address_commitment(vec_of([], 0), 7);
}

/// key_hash = P2(DOM_KEY, n_0, .., n_17), spelled out.
#[test]
fn key_hash_follows_the_spec_formula() {
    let mut input = [0; 19];
    input[0] = email_recovery::spec::DOM_KEY;
    for i in 0..18 {
        input[i + 1] = KEY_A_MODULUS[i] as Field;
    }
    assert(key_hash(KEY_A_MODULUS) == Poseidon2::hash(input, 19));
    assert(key_hash(KEY_A_MODULUS) != key_hash(KEY_B_MODULUS));
}

/// leaf = P2(DOM_LEAF, len, pack(domain, 62), key_hash), spelled out.
#[test]
fn leaf_follows_the_spec_formula() {
    let domain: BoundedVec<u8, 62> = vec_of("gmail.com".as_bytes(), 9);
    let d = pack_bytes(domain.storage());
    let expected = Poseidon2::hash([email_recovery::spec::DOM_LEAF, 9, d[0], d[1], 5], 5);
    assert(registry_leaf(domain, 5) == expected);
}

/// The only leaf of an otherwise empty tree, at index 0 and at the last
/// index: its siblings are the empty subtrees.
#[test]
fn merkle_root_of_a_single_leaf() {
    let leaf = registry_leaf(vec_of("gmail.com".as_bytes(), 9), key_hash(KEY_A_MODULUS));
    let mut siblings = [0; 16];
    for i in 0..16 {
        siblings[i] = empty_subtree(i);
    }
    // Index 0: the leaf is always the left child.
    let mut left = leaf;
    // Index 2^16 - 1: always the right child.
    let mut right = leaf;
    for i in 0..16 {
        left = Poseidon2::hash([left, siblings[i]], 2);
        right = Poseidon2::hash([siblings[i], right], 2);
    }
    assert(merkle_root(leaf, 0, siblings) == left);
    assert(merkle_root(leaf, 0xffff, siblings) == right);
    assert(merkle_root(leaf, 1, siblings) != left);
    assert(empty_subtree(1) == Poseidon2::hash([0, 0], 2));
}

/// The index has 16 bits; a larger one has no decomposition.
#[test(should_fail)]
fn merkle_index_past_the_tree_is_refused() {
    let _ = merkle_root(1, 0x10000, [0; 16]);
}
