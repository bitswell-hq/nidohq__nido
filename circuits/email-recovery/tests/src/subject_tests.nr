//! The Subject field.

use crate::common::{header, verify};
use crate::vectors::{
    DIGEST_HI, DIGEST_LO, GMAIL_HEADER, GMAIL_SIG, RHO, SUBJECT_ENCODED_WORD_HEADER,
    SUBJECT_ENCODED_WORD_SIG, SUBJECT_REPLY_HEADER, SUBJECT_REPLY_SIG, SUBJECT_TRAILING_HEADER,
    SUBJECT_TRAILING_SIG, SUBJECT_UPPER_HEX_HEADER, SUBJECT_UPPER_HEX_SIG,
};
use email_recovery::spec::{ENROLLMENT_PHRASE, RECOVERY_PHRASE};
use email_recovery::subject::{
    assert_subject_opens, assert_valid_phrase, blinded_value, hex_of_field, hex_to_bytes,
};

#[test]
fn hex_decodes() {
    let out: [u8; 4] = hex_to_bytes("00ff10ab".as_bytes());
    assert(out == [0x00, 0xff, 0x10, 0xab]);
}

#[test(should_fail_with = "Subject: value must be lowercase hex")]
fn uppercase_hex_is_refused() {
    let _ = verify(
        header(SUBJECT_UPPER_HEX_HEADER.as_bytes()),
        SUBJECT_UPPER_HEX_SIG,
    );
}

/// RFC 2047 encoded words cannot stand in for the phrase.
#[test(should_fail_with = "Subject: must start with the recovery phrase")]
fn encoded_word_is_refused() {
    let _ = verify(
        header(SUBJECT_ENCODED_WORD_HEADER.as_bytes()),
        SUBJECT_ENCODED_WORD_SIG,
    );
}

#[test(should_fail_with = "Subject: must start with the recovery phrase")]
fn reply_prefix_is_refused() {
    let _ = verify(header(SUBJECT_REPLY_HEADER.as_bytes()), SUBJECT_REPLY_SIG);
}

#[test(should_fail_with = "Subject: unexpected text after the value")]
fn trailing_text_is_refused() {
    let _ = verify(
        header(SUBJECT_TRAILING_HEADER.as_bytes()),
        SUBJECT_TRAILING_SIG,
    );
}

#[test(should_fail_with = "Subject: phrase contains =?")]
fn phrase_with_encoded_word_marker_is_refused() {
    assert_valid_phrase("APPROVE =?".as_bytes());
}

#[test(should_fail_with = "Subject: phrase has a double space")]
fn phrase_with_double_space_is_refused() {
    assert_valid_phrase("APPROVE  NIDO".as_bytes());
}

#[test]
fn spec_phrases_are_valid() {
    assert_valid_phrase(RECOVERY_PHRASE.as_bytes());
    assert_valid_phrase(ENROLLMENT_PHRASE.as_bytes());
}

#[test]
fn hex_of_field_is_64_lowercase_big_endian_digits() {
    assert(
        hex_of_field(0xab)
            == "00000000000000000000000000000000000000000000000000000000000000ab".as_bytes(),
    );
    // r - 1, the largest field element.
    assert(
        hex_of_field(-1)
            == "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000".as_bytes(),
    );
}

/// The Subject opens only with the digest and rho it was built from.
#[test(should_fail_with = "Subject: value does not open to the statement digest")]
fn subject_does_not_open_with_another_rho() {
    let out = verify(header(GMAIL_HEADER.as_bytes()), GMAIL_SIG);
    assert_subject_opens(out.subject_value, DIGEST_HI, DIGEST_LO, RHO + 1);
}

#[test(should_fail_with = "Subject: value does not open to the statement digest")]
fn subject_does_not_open_to_another_digest() {
    let out = verify(header(GMAIL_HEADER.as_bytes()), GMAIL_SIG);
    assert_subject_opens(out.subject_value, DIGEST_LO, DIGEST_HI, RHO);
}

#[test]
fn blinding_changes_with_rho() {
    assert(
        blinded_value(DIGEST_HI, DIGEST_LO, RHO) != blinded_value(DIGEST_HI, DIGEST_LO, RHO + 1),
    );
}
