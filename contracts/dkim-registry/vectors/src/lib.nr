//! The DKIM key registry's formulas (docs/email-recovery/spec.md sections 7.1, 7.2,
//! and 7.4), recomputed with the Poseidon2 the email circuit uses
//! (noir-lang/poseidon v0.2.0) and written independently of the contract:
//! limbs are read byte by byte from the modulus, and roots are folded level
//! by level instead of through the contract's stored nodes.
//!
//! `contracts/dkim-registry/src/test.rs::noir_vectors` asserts the same
//! values from the contract's host-side hashing. Run with Perch's pinned
//! nargo: `just dkim-registry-vectors`.

mod inputs;

use inputs::{
    DOMAIN_A, DOMAIN_A_LEN, DOMAIN_B, DOMAIN_B_LEN, DOMAIN_C, DOMAIN_C_LEN, MODULUS_A, MODULUS_B,
    MODULUS_C,
};
use poseidon::poseidon2::Poseidon2;

global DOM_KEY: Field = 0x1f6d4c7ed15d3b9480457cf9ff55d0ffff201158605d66399703659bf4d765f5;
global DOM_LEAF: Field = 0x1ddd7b4c7e2eba95d7da44139642c575589aa685188088b0555d3d4fbb5b1f7e;
global DOM_PIN_SALT: Field = 0x03d73ecb3a706d8271405c0c77fb8020c22717b7db10c5eb91f480ea1456bff6;
global DEPTH: u32 = 16;

/// n = sum of n_i * 2^(120 i): limb i holds bytes 15 i .. 15 i + 14 counted from
/// the least significant end, most significant first.
pub fn limbs(n: [u8; 256]) -> [Field; 18] {
    let mut out = [0; 18];
    for i in 0..18 {
        let mut limb: Field = 0;
        for j in 0..15 {
            let from_end = 15 * i + 14 - j;
            if from_end < 256 {
                limb = limb * 256 + n[255 - from_end] as Field;
            }
        }
        out[i] = limb;
    }
    out
}

pub fn key_hash(n: [u8; 256]) -> Field {
    let l = limbs(n);
    let mut input = [0; 19];
    input[0] = DOM_KEY;
    for i in 0..18 {
        input[i + 1] = l[i];
    }
    Poseidon2::hash(input, 19)
}

/// pack(domain, 62): two 31-byte big-endian chunks of the zero-padded bytes.
pub fn pack62(d: [u8; 62]) -> [Field; 2] {
    let mut out = [0; 2];
    for c in 0..2 {
        let mut x: Field = 0;
        for j in 0..31 {
            x = x * 256 + d[31 * c + j] as Field;
        }
        out[c] = x;
    }
    out
}

pub fn leaf(domain: [u8; 62], len: u32, kh: Field) -> Field {
    let p = pack62(domain);
    Poseidon2::hash([DOM_LEAF, len as Field, p[0], p[1], kh], 5)
}

pub fn node(left: Field, right: Field) -> Field {
    Poseidon2::hash([left, right], 2)
}

/// The depth-16 root of a tree whose leaves 0..3 are `leaves` and every
/// other leaf is empty (0).
pub fn root4(leaves: [Field; 4]) -> Field {
    let mut cur = node(node(leaves[0], leaves[1]), node(leaves[2], leaves[3]));
    let z1 = node(0, 0);
    let mut z = node(z1, z1);
    for _ in 2..DEPTH {
        cur = node(cur, z);
        z = node(z, z);
    }
    cur
}

pub fn empty_root() -> Field {
    let mut z = 0;
    for _ in 0..DEPTH {
        z = node(z, z);
    }
    z
}

global ACCOUNT_CODE: Field = 0x0102030405060708090a0b0c0d0e0f10;

/// The values `noir_vectors` in the contract's tests asserts too.
#[test]
fn vectors() {
    let ka = key_hash(MODULUS_A);
    let kb = key_hash(MODULUS_B);
    let kc = key_hash(MODULUS_C);
    assert(ka == 0x25a7dd9c7d1722237f60c18f7e981754bacb873259d63ffc9114caacdb4bcdae);
    assert(kb == 0x0612361cdce4d414bbcb22c64e24fe37a2e1e546d506d19176c5a0237d0aaa00);
    assert(kc == 0x12abba657357fe88dfc265e30573e1924ba02888c9338454f097b739c9519115);

    let la = leaf(DOMAIN_A, DOMAIN_A_LEN, ka);
    let lb = leaf(DOMAIN_B, DOMAIN_B_LEN, kb);
    let lc = leaf(DOMAIN_C, DOMAIN_C_LEN, kc);
    assert(la == 0x27f86eaf8edb3e0731742dcb5d4224053934a67a158915aef1cceaaf0d769169);
    assert(lb == 0x13507fa59f3214cee8a827a2b87eaab25f32ac2b62e14586173376a423b953b9);
    assert(lc == 0x212a001de51855c45d590f4c72f7d7575c841fcc1cc515553e2faedcf956c9b8);

    // A added; then B and C; then B retired (its leaf emptied).
    assert(
        root4([la, 0, 0, 0]) == 0x22da6e7490012cd3daa3edab29388c9ab80ffeea19aa956f35ad9da0600d8319,
    );
    assert(
        root4([la, lb, lc, 0])
            == 0x08fd83d83b64b3be8f9af81baeca40cbd5ea0ce9960e877254df996a1d4c927c,
    );
    assert(
        root4([la, 0, lc, 0]) == 0x23cce8ab300369c2220682360665ee0218df244953b2753de7e011d716181a3c,
    );

    // A key pin over A, salted with ACCOUNT_CODE (spec 7.4).
    let pin_salt = Poseidon2::hash([DOM_PIN_SALT, ACCOUNT_CODE], 2);
    assert(
        root4([pin_salt, la, 0, 0])
            == 0x06809f5b34b6b7e95400ba494bbf58b9e2e7e5c9457bbc537560af4b3cb36a1f,
    );

    // Z_16, also Perch's ZERO_HASHES[16].
    assert(empty_root() == 0x14f44d672eb357739e42463497f9fdac46623af863eea4d947ca00a497dcdeb3);
}
