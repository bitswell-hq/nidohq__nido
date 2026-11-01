//! Parameters and helpers shared by the tests: 1024-byte headers, a 512-byte
//! DKIM-Signature field, up to 16 tags, and the spec's 124-byte addresses and
//! recovery phrase.

use crate::vectors::{KEY_A_MODULUS, KEY_A_REDC, PHRASE};
use email_recovery::dkim::{
    DkimHeaderHints, find_hints, VerifiedHeader, verify_dkim_header, verify_dkim_header_with_hints,
};

pub global HEADER_MAX: u32 = 1024;
pub global FIELD_MAX: u32 = 512;
pub global TAGS_MAX: u32 = 16;
pub global ADDR_MAX: u32 = 124;
pub global VALUE_LEN: u32 = 64;
pub global PHRASE_LEN: u32 = 30;

pub type Verified = VerifiedHeader<ADDR_MAX, VALUE_LEN, FIELD_MAX>;
pub type Hints = DkimHeaderHints<TAGS_MAX>;

/// A header block of `bytes`, zero-padded to the bound.
pub fn header<let L: u32>(bytes: [u8; L]) -> BoundedVec<u8, HEADER_MAX> {
    let mut storage = [0; HEADER_MAX];
    for i in 0..L {
        storage[i] = bytes[i];
    }
    BoundedVec::from_parts_unchecked(storage, L)
}

/// Verifies under test key A with the prover's own hints.
pub fn verify(h: BoundedVec<u8, HEADER_MAX>, sig: [u128; 18]) -> Verified {
    verify_dkim_header::<HEADER_MAX, FIELD_MAX, TAGS_MAX, ADDR_MAX, PHRASE_LEN, VALUE_LEN>(
        h,
        KEY_A_MODULUS,
        KEY_A_REDC,
        sig,
        PHRASE.as_bytes(),
    )
}

/// Verifies under test key A with the given hints.
pub fn verify_with(h: BoundedVec<u8, HEADER_MAX>, sig: [u128; 18], hints: Hints) -> Verified {
    verify_dkim_header_with_hints::<HEADER_MAX, FIELD_MAX, TAGS_MAX, ADDR_MAX, PHRASE_LEN, VALUE_LEN>(
        h,
        KEY_A_MODULUS,
        KEY_A_REDC,
        sig,
        PHRASE.as_bytes(),
        hints,
    )
}

/// The hints an honest prover computes, as a starting point for adversarial
/// ones.
pub fn honest_hints(h: BoundedVec<u8, HEADER_MAX>) -> Hints {
    // Safety: test helper; the hints are inputs to the checks under test.
    unsafe {
        find_hints::<HEADER_MAX, TAGS_MAX>(h.storage(), h.len())
    }
}

unconstrained fn index_of_hint<let N: u32, let L: u32>(
    h: [u8; N],
    needle: [u8; L],
    from: u32,
) -> u32 {
    let mut found = N;
    for i in from..N - L {
        if found == N {
            let mut ok = true;
            for k in 0..L {
                ok &= h[i + k] == needle[k];
            }
            if ok {
                found = i;
            }
        }
    }
    found
}

/// Index of the first `needle` in `h` at or after `from`.
pub fn index_of<let N: u32, let L: u32>(h: [u8; N], needle: [u8; L], from: u32) -> u32 {
    // Safety: test helper.
    let i = unsafe { index_of_hint(h, needle, from) };
    assert(i < N, "test: needle not found");
    i
}

/// Whether `v` holds exactly `expected`.
pub fn equals<let M: u32, let L: u32>(v: BoundedVec<u8, M>, expected: [u8; L]) -> bool {
    let mut ok = v.len() == L;
    for i in 0..L {
        ok &= v.get(i) == expected[i];
    }
    ok
}

pub global BODY_MAX: u32 = 256;

/// A canonicalized body of `bytes`, zero-padded to `BODY_MAX`.
pub fn body<let L: u32>(bytes: [u8; L]) -> BoundedVec<u8, BODY_MAX> {
    let mut storage = [0; BODY_MAX];
    for i in 0..L {
        storage[i] = bytes[i];
    }
    BoundedVec::from_parts_unchecked(storage, L)
}
