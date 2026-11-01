//! RSA-2048 PKCS#1 v1.5 / SHA-256 verification on its own.

use crate::vectors::{
    BAD_ENCODING_BLOCK_TYPE_2_SIG, BAD_ENCODING_NO_SEPARATOR_SIG, BAD_ENCODING_PS_BYTE_SIG,
    BAD_ENCODING_SHA1_PREFIX_SIG, GMAIL_DIGEST, GMAIL_ENCODING, GMAIL_SIG, GMAIL_SIG_BY_KEY_1024,
    GMAIL_SIG_BY_KEY_B, GMAIL_SIG_PLUS_N, KEY_1024_MODULUS, KEY_A_MODULUS, KEY_A_REDC,
    KEY_B_MODULUS, KEY_B_REDC,
};
use email_recovery::rsa::{pkcs1v15_sha256_encoding, pow_65537, verify_pkcs1v15_sha256};

#[test]
fn encoding_matches_rfc_8017() {
    let limbs = pkcs1v15_sha256_encoding(GMAIL_DIGEST);
    for i in 0..18 {
        assert(limbs[i] == GMAIL_ENCODING[i] as Field);
    }
}

#[test]
fn valid_signature_verifies() {
    verify_pkcs1v15_sha256(KEY_A_MODULUS, KEY_A_REDC, GMAIL_SIG, GMAIL_DIGEST);
}

#[test]
fn valid_signature_under_another_key_verifies() {
    verify_pkcs1v15_sha256(KEY_B_MODULUS, KEY_B_REDC, GMAIL_SIG_BY_KEY_B, GMAIL_DIGEST);
}

/// sig + N raised to 65537 is the same encoding: only the bound on the
/// signature stops it from verifying.
#[test]
fn signature_plus_modulus_has_the_same_power() {
    let x = pow_65537(KEY_A_MODULUS, KEY_A_REDC, GMAIL_SIG_PLUS_N);
    assert(x == GMAIL_ENCODING);
}

#[test(should_fail_with = "RSA: signature is not below the modulus")]
fn signature_plus_modulus_is_refused() {
    verify_pkcs1v15_sha256(KEY_A_MODULUS, KEY_A_REDC, GMAIL_SIG_PLUS_N, GMAIL_DIGEST);
}

#[test(should_fail_with = "RSA: signature is not below the modulus")]
fn signature_equal_to_modulus_is_refused() {
    verify_pkcs1v15_sha256(KEY_A_MODULUS, KEY_A_REDC, KEY_A_MODULUS, GMAIL_DIGEST);
}

/// Key A's signature checked under key B (whose modulus is larger, so the
/// signature passes the bound and the encoding check refuses it).
#[test(should_fail_with = "RSA: signature does not verify")]
fn signature_under_another_key_is_refused() {
    verify_pkcs1v15_sha256(KEY_B_MODULUS, KEY_B_REDC, GMAIL_SIG, GMAIL_DIGEST);
}

#[test(should_fail_with = "RSA: signature does not verify")]
fn signature_over_another_digest_is_refused() {
    let mut digest = GMAIL_DIGEST;
    digest[0] ^= 1;
    verify_pkcs1v15_sha256(KEY_A_MODULUS, KEY_A_REDC, GMAIL_SIG, digest);
}

#[test(should_fail_with = "RSA: modulus is shorter than 2048 bits")]
fn modulus_of_1024_bits_is_refused() {
    verify_pkcs1v15_sha256(
        KEY_1024_MODULUS,
        KEY_A_REDC,
        GMAIL_SIG_BY_KEY_1024,
        GMAIL_DIGEST,
    );
}

// Raw RSA signatures of encodings that differ from EMSA-PKCS1-v1_5 in one
// part each: every byte of the encoding is checked.

#[test(should_fail_with = "RSA: signature does not verify")]
fn padding_byte_other_than_ff_is_refused() {
    verify_pkcs1v15_sha256(
        KEY_A_MODULUS,
        KEY_A_REDC,
        BAD_ENCODING_PS_BYTE_SIG,
        GMAIL_DIGEST,
    );
}

#[test(should_fail_with = "RSA: signature does not verify")]
fn block_type_2_is_refused() {
    verify_pkcs1v15_sha256(
        KEY_A_MODULUS,
        KEY_A_REDC,
        BAD_ENCODING_BLOCK_TYPE_2_SIG,
        GMAIL_DIGEST,
    );
}

#[test(should_fail_with = "RSA: signature does not verify")]
fn digest_info_of_another_hash_is_refused() {
    verify_pkcs1v15_sha256(
        KEY_A_MODULUS,
        KEY_A_REDC,
        BAD_ENCODING_SHA1_PREFIX_SIG,
        GMAIL_DIGEST,
    );
}

#[test(should_fail_with = "RSA: signature does not verify")]
fn missing_separator_is_refused() {
    verify_pkcs1v15_sha256(
        KEY_A_MODULUS,
        KEY_A_REDC,
        BAD_ENCODING_NO_SEPARATOR_SIG,
        GMAIL_DIGEST,
    );
}
