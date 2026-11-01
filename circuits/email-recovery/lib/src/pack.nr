//! Bytes and keys as BN254 field elements, hashed with `P2` (spec sections
//! 2, 5.3 and 7.1).
//!
//! `P2(x_1, .., x_n)` is `Poseidon2::hash([x_1, .., x_n], n)` from
//! noir-lang/poseidon v0.2.0 as vendored by Perch, which Soroban's
//! `soroban-poseidon` reproduces on the host.
//!
//! `pack(bytes, max)` right-pads the bytes with zeros to `max` and reads each
//! 31-byte chunk as a big-endian integer, so every element is below 2^248. A
//! `BoundedVec` is zero past its length, which `assert_zero_padded` checks,
//! so packing its storage is exactly this padding.

use crate::rsa::{assert_2048_bit_limbs, RSA_LIMBS};
use crate::spec::{ADDR_MAX, DOM_COMMIT, DOM_KEY};
use poseidon::poseidon2::Poseidon2;

/// Packs bytes 31 per element, big-endian within an element.
pub fn pack_bytes<let N: u32>(bytes: [u8; N]) -> [Field; (N + 30) / 31] {
    let mut out: [Field; (N + 30) / 31] = [0; (N + 30) / 31];
    for j in 0..(N + 30) / 31 {
        let mut acc: Field = 0;
        for k in 0..31 {
            let i = 31 * j + k;
            let b = if i < N { bytes[i] as Field } else { 0 };
            acc = acc * 256 + b;
        }
        out[j] = acc;
    }
    out
}

/// Constrains `bytes` to hold 1 to `N` bytes and zeros past its length.
pub fn assert_zero_padded<let N: u32>(bytes: BoundedVec<u8, N>) {
    let len = bytes.len();
    assert((len >= 1) & (len <= N), "pack: length out of bounds");
    let storage = bytes.storage();
    for i in 0..N {
        assert((i < len) | (storage[i] == 0), "pack: bytes past the length must be zero");
    }
}

/// `C = P2(DOM_COMMIT, len, a_0, a_1, a_2, a_3, account_code)` with
/// `(a_0, .., a_3) = pack(address, 124)` (section 5.3).
pub fn address_commitment(address: BoundedVec<u8, ADDR_MAX>, account_code: Field) -> Field {
    assert_zero_padded(address);
    let a = pack_bytes(address.storage());
    Poseidon2::hash(
        [DOM_COMMIT, address.len() as Field, a[0], a[1], a[2], a[3], account_code],
        7,
    )
}

/// `key_hash = P2(DOM_KEY, n_0, .., n_17)` over the modulus's 120-bit
/// little-endian limbs (section 7.1). The limbs are range-checked, so each
/// key has one encoding.
pub fn key_hash(modulus: [u128; RSA_LIMBS]) -> Field {
    assert_2048_bit_limbs(modulus);
    let mut input: [Field; RSA_LIMBS + 1] = [0; RSA_LIMBS + 1];
    input[0] = DOM_KEY;
    for i in 0..RSA_LIMBS {
        input[i + 1] = modulus[i] as Field;
    }
    Poseidon2::hash(input, RSA_LIMBS + 1)
}
