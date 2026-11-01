//! Header structure, From grammar and DKIM tag checks beyond the publicly
//! documented issue classes.

use crate::common::{header, verify};
use crate::vectors::{
    ADDR_TOO_LONG_HEADER, ADDR_TOO_LONG_SIG, B_NOT_EMPTY_HEADER, BAD_LOCAL_CHAR_HEADER,
    BAD_LOCAL_CHAR_SIG, BARE_LF_HEADER, BARE_LF_SIG, DOMAIN_TOO_LONG_HEADER, DOMAIN_TOO_LONG_SIG,
    DOUBLE_DOT_HEADER, DOUBLE_DOT_SIG, HYPHEN_END_LABEL_HEADER, HYPHEN_END_LABEL_SIG,
    HYPHEN_LABEL_HEADER, HYPHEN_LABEL_SIG, LONG_LABEL_HEADER, LONG_LABEL_SIG,
    NON_ASCII_DISPLAY_NAME_HEADER, NON_ASCII_DISPLAY_NAME_SIG, RELAXED_BARE_HEADER,
    RELAXED_BARE_SIG, SHA1_HEADER, SHA1_SIG, V2_HEADER, V2_SIG,
};

#[test(should_fail_with = "header: LF not preceded by CR")]
fn bare_lf_is_refused() {
    let _ = verify(header(BARE_LF_HEADER.as_bytes()), BARE_LF_SIG);
}

#[test(should_fail_with = "header: CR not followed by LF")]
fn bare_cr_is_refused() {
    let mut bytes = B_NOT_EMPTY_HEADER.as_bytes();
    // Turn the first LF into a space: its CR is now bare.
    let mut done = false;
    for i in 0..bytes.len() {
        if !done & (bytes[i] == 10) {
            bytes[i] = 32;
            done = true;
        }
    }
    let _ = verify(header(bytes), [0; 18]);
}

#[test(should_fail_with = "From: invalid character in the local part")]
fn local_part_character_outside_the_grammar_is_refused() {
    let _ = verify(header(BAD_LOCAL_CHAR_HEADER.as_bytes()), BAD_LOCAL_CHAR_SIG);
}

#[test(should_fail_with = "From: consecutive dots")]
fn consecutive_dots_are_refused() {
    let _ = verify(header(DOUBLE_DOT_HEADER.as_bytes()), DOUBLE_DOT_SIG);
}

#[test(should_fail_with = "From: domain label starts or ends with a hyphen")]
fn hyphen_leading_label_is_refused() {
    let _ = verify(header(HYPHEN_LABEL_HEADER.as_bytes()), HYPHEN_LABEL_SIG);
}

#[test(should_fail_with = "From: domain label starts or ends with a hyphen")]
fn hyphen_ending_label_is_refused() {
    let _ = verify(
        header(HYPHEN_END_LABEL_HEADER.as_bytes()),
        HYPHEN_END_LABEL_SIG,
    );
}

#[test(should_fail_with = "From: domain label longer than 63 characters")]
fn label_of_64_characters_is_refused() {
    let _ = verify(header(LONG_LABEL_HEADER.as_bytes()), LONG_LABEL_SIG);
}

/// A 125-byte address, one past ADDR_MAX.
#[test(should_fail_with = "From: address length out of bounds")]
fn address_longer_than_124_bytes_is_refused() {
    let _ = verify(header(ADDR_TOO_LONG_HEADER.as_bytes()), ADDR_TOO_LONG_SIG);
}

/// A 63-byte domain: valid in From, but longer than the registry leaf's 62.
#[test(should_fail_with = "DKIM: d= must be at most 62 bytes")]
fn domain_longer_than_62_bytes_is_refused() {
    let _ = verify(
        header(DOMAIN_TOO_LONG_HEADER.as_bytes()),
        DOMAIN_TOO_LONG_SIG,
    );
}

/// A UTF-8 display name: the From value must be printable ASCII (an RFC 2047
/// encoded word carries such a name).
#[test(should_fail_with = "From: field value must be printable ASCII")]
fn non_ascii_display_name_is_refused() {
    let _ = verify(
        header(NON_ASCII_DISPLAY_NAME_HEADER),
        NON_ASCII_DISPLAY_NAME_SIG,
    );
}

/// `c=relaxed` alone means relaxed/simple, but the spec names only the two
/// explicit values.
#[test(should_fail_with = "DKIM: header canonicalization must be relaxed")]
fn bare_relaxed_canonicalization_is_refused() {
    let _ = verify(header(RELAXED_BARE_HEADER.as_bytes()), RELAXED_BARE_SIG);
}

#[test(should_fail_with = "DKIM: a= must be rsa-sha256")]
fn rsa_sha1_is_refused() {
    let _ = verify(header(SHA1_HEADER.as_bytes()), SHA1_SIG);
}

#[test(should_fail_with = "DKIM: v= must be 1")]
fn other_version_is_refused() {
    let _ = verify(header(V2_HEADER.as_bytes()), V2_SIG);
}
