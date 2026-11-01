//! The registry's Poseidon2 formulas (spec §7.1, §7.2, §7.4).
//!
//! ```text
//! key_hash = P2(DOM_KEY, n_0, ..., n_17)                 n = Σ n_i · 2^(120 i)
//! leaf     = P2(DOM_LEAF, len(domain), d_0, d_1, key_hash)   (d_0, d_1) = pack(domain, 62)
//! node     = P2(left, right)
//! pin salt = P2(DOM_PIN_SALT, account_code)              leaf 0 of a guardian's pin tree
//! ```
//!
//! `P2` is `soroban-poseidon`'s `Poseidon2Sponge::<4, Bn254Fr>` over the
//! host's `poseidon2_permutation`, the sponge Perch's pool hashes with and
//! the one noir-lang/poseidon v0.2.0's `Poseidon2::hash(inputs, len)`
//! matches. `contracts/dkim-registry/vectors/` recomputes every formula here
//! in Noir with that library, and both suites assert the same values.

use soroban_poseidon::Poseidon2Sponge;
use soroban_sdk::crypto::bn254::Bn254Fr;
use soroban_sdk::{vec, Bytes, BytesN, Env, U256};

/// `BE(sha256("nido/email-recovery/v1/key")) mod r`.
pub const DOM_KEY: [u8; 32] =
    hex32(b"1f6d4c7ed15d3b9480457cf9ff55d0ffff201158605d66399703659bf4d765f5");
/// `BE(sha256("nido/email-recovery/v1/leaf")) mod r`.
pub const DOM_LEAF: [u8; 32] =
    hex32(b"1ddd7b4c7e2eba95d7da44139642c575589aa685188088b0555d3d4fbb5b1f7e");
/// `BE(sha256("nido/email-recovery/v1/pin-salt")) mod r`.
pub const DOM_PIN_SALT: [u8; 32] =
    hex32(b"03d73ecb3a706d8271405c0c77fb8020c22717b7db10c5eb91f480ea1456bff6");

/// An RSA-2048 modulus: 256 big-endian bytes, top bit set.
pub const MODULUS_BYTES: usize = 256;
/// Limbs of 120 bits (15 bytes) the modulus is cut into, least significant
/// first; the top limb holds the modulus's highest 8 bits.
pub const MODULUS_LIMBS: usize = 18;
const LIMB_BYTES: usize = 15;
/// Longest leaf domain: two 31-byte packing chunks.
pub const DOMAIN_MAX: usize = 62;

const fn hex32(s: &[u8; 64]) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("lowercase hex only"),
        }
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(s[2 * i]) << 4) | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

/// Whether `modulus` has exactly 2048 bits.
#[must_use]
pub fn is_rsa_2048(modulus: &[u8]) -> bool {
    modulus.len() == MODULUS_BYTES && modulus[0] & 0x80 != 0
}

/// The modulus's 18 limbs of 120 bits, least significant first, each as a
/// 32-byte big-endian field element.
#[must_use]
pub fn limbs(modulus: &[u8; MODULUS_BYTES]) -> [[u8; 32]; MODULUS_LIMBS] {
    let mut out = [[0u8; 32]; MODULUS_LIMBS];
    for (i, limb) in out.iter_mut().enumerate() {
        // Limb i is bytes [15 i, 15 i + 15) counted from the least
        // significant end; the top limb has only the most significant byte.
        let end = MODULUS_BYTES - LIMB_BYTES * i;
        let start = end.saturating_sub(LIMB_BYTES);
        let chunk = &modulus[start..end];
        limb[32 - chunk.len()..].copy_from_slice(chunk);
    }
    out
}

/// `pack(domain, 62)`: right-padded with zeros to 62 bytes, read as two
/// 31-byte big-endian integers.
///
/// # Panics
/// If `domain` is empty or longer than [`DOMAIN_MAX`].
#[must_use]
pub fn pack_domain(domain: &[u8]) -> [[u8; 32]; 2] {
    assert!(
        !domain.is_empty() && domain.len() <= DOMAIN_MAX,
        "domain length"
    );
    let mut padded = [0u8; DOMAIN_MAX];
    padded[..domain.len()].copy_from_slice(domain);
    let mut out = [[0u8; 32]; 2];
    out[0][1..].copy_from_slice(&padded[..31]);
    out[1][1..].copy_from_slice(&padded[31..]);
    out
}

fn length_field(len: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    // A domain is at most 62 bytes.
    out[31] = u8::try_from(len).expect("domain length");
    out
}

/// A reusable Poseidon2 sponge. Building the parameter tables is a fixed
/// per-sponge cost, so a tree update keeps one `Hasher` for all its hashes.
pub struct Hasher {
    env: Env,
    sponge: Poseidon2Sponge<4, Bn254Fr>,
}

impl Hasher {
    #[must_use]
    pub fn new(e: &Env) -> Self {
        Self {
            env: e.clone(),
            sponge: Poseidon2Sponge::<4, Bn254Fr>::new(e),
        }
    }

    fn hash(&mut self, inputs: &[[u8; 32]]) -> BytesN<32> {
        let mut v = vec![&self.env];
        for x in inputs {
            v.push_back(U256::from_be_bytes(
                &self.env,
                &Bytes::from_array(&self.env, x),
            ));
        }
        let mut out = [0u8; 32];
        self.sponge
            .compute_hash(&v)
            .to_be_bytes()
            .copy_into_slice(&mut out);
        BytesN::from_array(&self.env, &out)
    }

    /// `key_hash = P2(DOM_KEY, limbs(n))` (spec §7.1).
    pub fn key_hash(&mut self, modulus: &[u8; MODULUS_BYTES]) -> BytesN<32> {
        let mut inputs = [[0u8; 32]; 1 + MODULUS_LIMBS];
        inputs[0] = DOM_KEY;
        inputs[1..].copy_from_slice(&limbs(modulus));
        self.hash(&inputs)
    }

    /// `leaf = P2(DOM_LEAF, len(domain), pack(domain, 62), key_hash)` (spec
    /// §7.2).
    ///
    /// # Panics
    /// If `domain` is empty or longer than [`DOMAIN_MAX`].
    pub fn leaf(&mut self, domain: &[u8], key_hash: &BytesN<32>) -> BytesN<32> {
        let [d0, d1] = pack_domain(domain);
        self.hash(&[
            DOM_LEAF,
            length_field(domain.len()),
            d0,
            d1,
            key_hash.to_array(),
        ])
    }

    /// Interior node `P2(left, right)`, untagged, as in Perch's pool.
    pub fn node(&mut self, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
        self.hash(&[left.to_array(), right.to_array()])
    }

    /// Leaf 0 of a guardian's key pin tree: `P2(DOM_PIN_SALT, account_code)`
    /// (spec §7.4). The registry never stores one; wallets build pin trees
    /// with the same hashing as the registry tree.
    pub fn pin_salt(&mut self, account_code: &BytesN<32>) -> BytesN<32> {
        self.hash(&[DOM_PIN_SALT, account_code.to_array()])
    }
}
