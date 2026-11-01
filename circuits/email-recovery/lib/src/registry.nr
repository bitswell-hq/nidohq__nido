//! The DKIM key registry's leaf and Merkle conventions (spec section 7.2).
//!
//! ```text
//! leaf       = P2(DOM_LEAF, len(domain), d_0, d_1, key_hash)
//! (d_0, d_1) = pack(domain, 62)          ; the lowercase d= value, 1..62 bytes
//! node       = P2(left, right)            ; untagged, as Perch's pool
//! ```
//!
//! The tree has depth 16. The leaf index is decomposed into 16 little-endian
//! bits; bit `i` set means the node at level `i` is a right child. The leaf is
//! always computed here from a domain and a key hash, so an interior node or
//! an empty value cannot stand in for it without a `P2` collision.

use crate::pack::{assert_zero_padded, pack_bytes};
use crate::spec::{DOM_LEAF, DOMAIN_MAX, REGISTRY_DEPTH};
use poseidon::poseidon2::Poseidon2;

pub fn registry_leaf(domain: BoundedVec<u8, DOMAIN_MAX>, key_hash: Field) -> Field {
    assert_zero_padded(domain);
    let d = pack_bytes(domain.storage());
    Poseidon2::hash([DOM_LEAF, domain.len() as Field, d[0], d[1], key_hash], 5)
}

/// The root reached from `leaf` at `index` through `siblings`, lowest level
/// first. `index` must be below 2^16.
pub fn merkle_root(leaf: Field, index: Field, siblings: [Field; REGISTRY_DEPTH]) -> Field {
    let bits: [u1; REGISTRY_DEPTH] = index.to_le_bits();
    let mut node = leaf;
    for i in 0..REGISTRY_DEPTH {
        let right = bits[i] == 1;
        let (l, r) = if right {
            (siblings[i], node)
        } else {
            (node, siblings[i])
        };
        node = Poseidon2::hash([l, r], 2);
    }
    node
}

/// The root of a tree whose leaves are all empty below level `level`:
/// `Z_0 = 0`, `Z_{i+1} = P2(Z_i, Z_i)`.
pub fn empty_subtree(level: u32) -> Field {
    let mut z = 0;
    for i in 0..REGISTRY_DEPTH {
        if i < level {
            z = Poseidon2::hash([z, z], 2);
        }
    }
    z
}
