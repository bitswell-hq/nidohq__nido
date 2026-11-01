//! The body hash: `bh=` must equal the base64 of the SHA-256 of the
//! canonicalized body (RFC 6376 section 3.7).
//!
//! The body is hashed whole, from its first byte, up to a bounded length;
//! there is no partial-SHA precomputation and no `l=` truncation
//! (`DkimSignature::body_hash_b64` refuses `l=`). Bytes past the body length must be
//! zero. The digest is base64-encoded in the circuit and compared with the
//! `bh=` bytes, so only the canonical encoding is accepted.

use crate::dkim_signature::DkimSignature;
use crate::tables::BASE64_ALPHABET;
use sha256::sha256_var;

/// The canonical base64 encoding (RFC 4648 section 4) of a SHA-256 digest: 43
/// alphabet characters and one `=`.
pub fn base64_sha256(digest: [u8; 32]) -> [u8; 44] {
    let mut out: [u8; 44] = [0; 44];
    // 10 full groups of 3 bytes, then 2 bytes.
    for g in 0..11 {
        let b0 = digest[3 * g];
        let b1 = digest[3 * g + 1];
        let b2 = if g < 10 { digest[3 * g + 2] } else { 0 };
        let s0 = b0 >> 2;
        let s1 = ((b0 & 3) << 4) | (b1 >> 4);
        let s2 = ((b1 & 15) << 2) | (b2 >> 6);
        let s3 = b2 & 63;
        out[4 * g] = BASE64_ALPHABET[s0 as u32];
        out[4 * g + 1] = BASE64_ALPHABET[s1 as u32];
        out[4 * g + 2] = BASE64_ALPHABET[s2 as u32];
        out[4 * g + 3] = if g < 10 {
            BASE64_ALPHABET[s3 as u32]
        } else {
            61
        };
    }
    out
}

/// Checks that `body_hash_b64` (the `bh=` value) is the hash of `body`, the
/// canonicalized body.
pub fn verify_body_hash<let MAX_BODY: u32>(
    body: BoundedVec<u8, MAX_BODY>,
    body_hash_b64: [u8; 44],
) {
    let bytes = body.storage();
    let len = body.len();
    assert(len <= MAX_BODY, "Body: length exceeds the bound");
    for i in 0..MAX_BODY {
        assert((i < len) | (bytes[i] == 0), "Body: bytes past the body length must be zero");
    }
    let expected = base64_sha256(sha256_var(bytes, len));
    assert(expected == body_hash_b64, "Body: bh= does not match the body");
}

/// Checks that `body`, the canonicalized body, is the one the verified
/// DKIM-Signature field's `bh=` names. Use where the body carries data the
/// proof relies on; the header-only recovery proof does not bind the body.
pub fn verify_body<let MAX_BODY: u32, let MAX_FIELD: u32>(
    signature: DkimSignature<MAX_FIELD>,
    body: BoundedVec<u8, MAX_BODY>,
) {
    verify_body_hash(body, signature.body_hash_b64());
}
