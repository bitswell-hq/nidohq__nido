//! RSA-2048 PKCS#1 v1.5 signature verification with SHA-256 (RFC 8017 section 8.2.2,
//! EMSA-PKCS1-v1_5 in section 9.2), public exponent 65537.
//!
//! Integers are 18 little-endian limbs of 120 bits; the top limb holds bits
//! 2040..2047, so it has at most 8 bits. The checks:
//!
//! - the modulus is range-checked limb by limb and its bit 2047 is set, so a
//!   key shorter than 2048 bits is refused;
//! - the signature is range-checked and strictly below the modulus, so `sig`
//!   and `sig + N` cannot both verify;
//! - `sig^65537 mod N` equals the full 256-byte encoded message
//!   `0x00 0x01 PS 0x00 DigestInfo(SHA-256) H`: every padding byte, the
//!   DigestInfo prefix and the digest.
//!
//! Modular multiplication is noir-bignum's `RuntimeBigNum` (vendored
//! v0.7.5). Its `evaluate_quadratic_expression` does not range-check its
//! operands in that version, so every operand and every product here is
//! range-checked by this module. The Barrett parameter `redc` is read only by
//! noir-bignum's unconstrained witness code, never by a constraint: a wrong
//! value makes honest proving fail and cannot make a false statement provable.
//! It is therefore a prover hint and is not part of the key hash.

use bignum::params::BigNumParams;
use bignum::RuntimeBigNum;

pub global RSA_LIMBS: u32 = 18;
pub global RSA_MODULUS_BITS: u32 = 2048;
global TWO_POW_120: Field = 0x1000000000000000000000000000000;

/// DigestInfo for SHA-256 (RFC 8017 section 9.2, note 1), big-endian.
global SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

type Params = BigNumParams<RSA_LIMBS, RSA_MODULUS_BITS>;
type Rsa2048 = RuntimeBigNum<RSA_LIMBS, RSA_MODULUS_BITS>;

/// Constrains `limbs` to encode an integer below 2^2048: limbs 0..16 below
/// 2^120 and limb 17 below 2^8.
pub fn assert_2048_bit_limbs(limbs: [u128; RSA_LIMBS]) {
    for i in 0..RSA_LIMBS - 1 {
        (limbs[i] as Field).assert_max_bit_size::<120>();
    }
    (limbs[RSA_LIMBS - 1] as Field).assert_max_bit_size::<8>();
}

/// Constrains `modulus` to be a well-formed integer of exactly 2048 bits.
pub fn assert_rsa2048_modulus(modulus: [u128; RSA_LIMBS]) {
    assert_2048_bit_limbs(modulus);
    assert(modulus[RSA_LIMBS - 1] >= 128, "RSA: modulus is shorter than 2048 bits");
}

/// Borrows of the limb-wise subtraction `b - a - 1`: entry `i` is the borrow
/// out of limb `i`.
unconstrained fn borrows_of_b_minus_a_minus_one(
    a: [u128; RSA_LIMBS],
    b: [u128; RSA_LIMBS],
) -> [bool; RSA_LIMBS] {
    let mut borrows = [false; RSA_LIMBS];
    let mut borrow_in: u128 = 1;
    for i in 0..RSA_LIMBS {
        let need = a[i] + borrow_in;
        borrows[i] = b[i] < need;
        borrow_in = borrows[i] as u128;
    }
    borrows
}

/// Constrains `a < b` for range-checked 2048-bit limb arrays, by showing that
/// `b - a - 1` has a limb decomposition with no borrow out of the top limb.
pub fn assert_less_than(a: [u128; RSA_LIMBS], b: [u128; RSA_LIMBS]) {
    // Safety: each limb of b - a - 1 is reconstructed from the borrows below
    // and range-checked, which fixes every borrow uniquely.
    let borrows = unsafe { borrows_of_b_minus_a_minus_one(a, b) };
    let mut borrow_in: Field = 1;
    for i in 0..RSA_LIMBS - 1 {
        let diff = b[i] as Field - a[i] as Field - borrow_in + borrows[i] as Field * TWO_POW_120;
        diff.assert_max_bit_size::<120>();
        borrow_in = borrows[i] as Field;
    }
    let top = b[RSA_LIMBS - 1] as Field - a[RSA_LIMBS - 1] as Field - borrow_in
        + borrows[RSA_LIMBS - 1] as Field * 256;
    top.assert_max_bit_size::<8>();
    assert(!borrows[RSA_LIMBS - 1], "RSA: signature is not below the modulus");
}

/// The EMSA-PKCS1-v1_5 encoding of a SHA-256 `digest` for a 2048-bit key, as
/// 120-bit little-endian limbs.
pub fn pkcs1v15_sha256_encoding(digest: [u8; 32]) -> [Field; RSA_LIMBS] {
    // Byte j of `le` is byte 255 - j of the big-endian encoded message
    // 0x00 0x01 [0xff x 202] 0x00 DigestInfo[19] digest[32].
    let mut le: [Field; 256] = [0; 256];
    for j in 0..32 {
        le[j] = digest[31 - j] as Field;
    }
    for j in 0..19 {
        le[32 + j] = SHA256_DIGEST_INFO[18 - j] as Field;
    }
    // le[51] is the 0x00 separator.
    for j in 52..254 {
        le[j] = 0xff;
    }
    le[254] = 0x01;
    // le[255] is the leading 0x00.
    let mut limbs: [Field; RSA_LIMBS] = [0; RSA_LIMBS];
    for i in 0..RSA_LIMBS {
        let mut acc: Field = 0;
        for k in 0..15 {
            let j = 15 * i + 14 - k;
            if j < 256 {
                acc = acc * 256 + le[j];
            }
        }
        limbs[i] = acc;
    }
    limbs
}

/// `base^65537` modulo `modulus`, as range-checked limbs. The result is
/// congruent to the power but not necessarily below the modulus.
pub fn pow_65537(
    modulus: [u128; RSA_LIMBS],
    redc: [u128; RSA_LIMBS],
    base: [u128; RSA_LIMBS],
) -> [u128; RSA_LIMBS] {
    assert_2048_bit_limbs(modulus);
    assert_2048_bit_limbs(base);
    let params: Params = BigNumParams::new(false, modulus, redc);
    let s: Rsa2048 = RuntimeBigNum::from_array(params, base);
    let mut x = s;
    for _ in 0..16 {
        x = x * x;
        assert_2048_bit_limbs(x.get_limbs());
    }
    x = x * s;
    let limbs = x.get_limbs();
    assert_2048_bit_limbs(limbs);
    limbs
}

/// Verifies an RSA-2048 PKCS#1 v1.5 SHA-256 signature over a message whose
/// SHA-256 is `digest`.
pub fn verify_pkcs1v15_sha256(
    modulus: [u128; RSA_LIMBS],
    redc: [u128; RSA_LIMBS],
    signature: [u128; RSA_LIMBS],
    digest: [u8; 32],
) {
    assert_rsa2048_modulus(modulus);
    assert_2048_bit_limbs(signature);
    assert_less_than(signature, modulus);
    let recovered = pow_65537(modulus, redc, signature);
    let expected = pkcs1v15_sha256_encoding(digest);
    for i in 0..RSA_LIMBS {
        assert(recovered[i] as Field == expected[i], "RSA: signature does not verify");
    }
}
