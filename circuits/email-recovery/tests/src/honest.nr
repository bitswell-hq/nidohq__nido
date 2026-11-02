//! Honest headers in the shapes the launch providers sign: the circuit
//! accepts them and returns exactly the signed values.

use crate::common::{equals, header, verify};
use crate::vectors::{
    ADDR_MAX_LENGTH_HEADER, ADDR_MAX_LENGTH_SIG, ATEXT_LOCAL_PART_HEADER, ATEXT_LOCAL_PART_SIG,
    BH_IN_Z_HEADER, BH_IN_Z_SIG, BODY_HASH_B64, DIGEST_HI, DIGEST_LO, DIGIT_LEADING_LABEL_HEADER,
    DIGIT_LEADING_LABEL_SIG, FROM_THEN_TO_ANGLE_HEADER, FROM_THEN_TO_ANGLE_SIG, GMAIL_HEADER,
    GMAIL_SIG, KEY_A_MODULUS, LONG_DISPLAY_NAME_HEADER, LONG_DISPLAY_NAME_SIG, NO_T_HEADER,
    NO_T_SIG, OUTLOOK_HEADER, OUTLOOK_SIG, PLUS_TAG_HEADER, PLUS_TAG_SIG, REGEX_RESET_HEADER,
    REGEX_RESET_SIG, RELAXED_SIMPLE_HEADER, RELAXED_SIMPLE_SIG, RHO, SEMICOLON_FREE_END_HEADER,
    SEMICOLON_FREE_END_SIG, UPPERCASE_D_HEADER, UPPERCASE_D_SIG, UPPERCASE_FROM_DOMAIN_HEADER,
    UPPERCASE_FROM_DOMAIN_SIG, VALUE,
};
use email_recovery::pack::key_hash;
use email_recovery::subject::assert_subject_opens;

/// Display name, `t=`, oversigned `h=` folded across lines, a Subject folded
/// by the client: everything arrives unfolded under relaxed canonicalization.
#[test]
fn gmail_shape() {
    let out = verify(header(GMAIL_HEADER.as_bytes()), GMAIL_SIG);
    assert(equals(out.from_address, "alice.example@gmail.com".as_bytes()));
    assert(equals(out.domain, "gmail.com".as_bytes()));
    assert(out.subject_value == VALUE.as_bytes());
    assert(out.key_hash == key_hash(KEY_A_MODULUS));
    assert(out.signature.body_hash_b64() == BODY_HASH_B64.as_bytes());
    assert(out.signature.timestamp() == (true, 1793448000));
}

/// The Subject opens to the statement digest with the browser's `rho`.
#[test]
fn subject_opens_to_the_digest() {
    let out = verify(header(GMAIL_HEADER.as_bytes()), GMAIL_SIG);
    assert_subject_opens(out.subject_value, DIGEST_HI, DIGEST_LO, RHO);
}

/// A bare address in From, `h=` with capitalized names, and no `t=`.
#[test]
fn outlook_shape() {
    let out = verify(header(OUTLOOK_HEADER.as_bytes()), OUTLOOK_SIG);
    assert(equals(out.from_address, "bob-smith_99@outlook.com".as_bytes()));
    assert(equals(out.domain, "outlook.com".as_bytes()));
    assert(out.subject_value == VALUE.as_bytes());
    assert(out.signature.timestamp() == (false, 0));
}

#[test]
fn address_with_plus_dots_hyphens_and_underscores() {
    let out = verify(header(PLUS_TAG_HEADER.as_bytes()), PLUS_TAG_SIG);
    assert(
        equals(
            out.from_address,
            "carol.o-neil+nido_1@fastmail.com".as_bytes(),
        ),
    );
}

/// Every RFC 5322 `atext` symbol is accepted in the local part.
#[test]
fn local_part_with_every_atext_symbol() {
    let out = verify(
        header(ATEXT_LOCAL_PART_HEADER.as_bytes()),
        ATEXT_LOCAL_PART_SIG,
    );
    assert(
        equals(
            out.from_address,
            "o'brien!#$%&*+-/=?^_`{|}~x@yahoo.com".as_bytes(),
        ),
    );
}

/// RFC 1123 host labels may start with a digit.
#[test]
fn digit_leading_domain_label() {
    let out = verify(
        header(DIGIT_LEADING_LABEL_HEADER.as_bytes()),
        DIGIT_LEADING_LABEL_SIG,
    );
    assert(equals(out.from_address, "erin@123mail.org".as_bytes()));
    assert(equals(out.domain, "123mail.org".as_bytes()));
}

/// A 124-byte address (ADDR_MAX) with a 62-byte domain.
#[test]
fn address_of_the_maximum_length() {
    let out = verify(
        header(ADDR_MAX_LENGTH_HEADER.as_bytes()),
        ADDR_MAX_LENGTH_SIG,
    );
    assert(out.from_address.len() == 124);
    assert(out.domain.len() == 62);
}

/// `d=Gmail.com` with From `@gmail.com`: equal once lowercased, and the leaf
/// domain is the lowercase value.
#[test]
fn signing_domain_compared_lowercase() {
    let out = verify(header(UPPERCASE_D_HEADER.as_bytes()), UPPERCASE_D_SIG);
    assert(equals(out.domain, "gmail.com".as_bytes()));
}

/// From `@GMAIL.com` with `d=gmail.com`: the address keeps its spelling and
/// the domain is lowercased.
#[test]
fn from_domain_compared_lowercase_and_address_kept() {
    let out = verify(
        header(UPPERCASE_FROM_DOMAIN_HEADER.as_bytes()),
        UPPERCASE_FROM_DOMAIN_SIG,
    );
    assert(equals(out.from_address, "alice.example@GMAIL.com".as_bytes()));
    assert(equals(out.domain, "gmail.com".as_bytes()));
}

/// A 300-byte display name is fine: its length never affects which address
/// is read.
#[test]
fn long_display_name() {
    let out = verify(
        header(LONG_DISPLAY_NAME_HEADER.as_bytes()),
        LONG_DISPLAY_NAME_SIG,
    );
    assert(equals(out.from_address, "alice.example@gmail.com".as_bytes()));
}

/// A signed field after From that holds an address in angle brackets.
#[test]
fn angle_addr_in_a_later_field_is_not_from() {
    let out = verify(
        header(FROM_THEN_TO_ANGLE_HEADER.as_bytes()),
        FROM_THEN_TO_ANGLE_SIG,
    );
    assert(equals(out.from_address, "attacker@gmail.com".as_bytes()));
}

/// A signed Cc holding `\xfffrom:<...>`: not a line start, so not a From field.
#[test]
fn from_text_inside_another_field_is_not_from() {
    let out = verify(header(REGEX_RESET_HEADER), REGEX_RESET_SIG);
    assert(equals(out.from_address, "alice.example@gmail.com".as_bytes()));
}

/// `bh=` text inside a `z=` value is not a tag; the real `bh=` is read.
#[test]
fn bh_text_inside_another_tag_is_not_bh() {
    let out = verify(header(BH_IN_Z_HEADER.as_bytes()), BH_IN_Z_SIG);
    assert(out.signature.body_hash_b64() == BODY_HASH_B64.as_bytes());
}

#[test]
fn tag_list_with_trailing_semicolon() {
    let out = verify(
        header(SEMICOLON_FREE_END_HEADER.as_bytes()),
        SEMICOLON_FREE_END_SIG,
    );
    assert(equals(out.from_address, "alice.example@gmail.com".as_bytes()));
}

#[test]
fn relaxed_header_simple_body() {
    let out = verify(header(RELAXED_SIMPLE_HEADER.as_bytes()), RELAXED_SIMPLE_SIG);
    assert(equals(out.from_address, "alice.example@gmail.com".as_bytes()));
}

#[test]
fn no_timestamp() {
    let out = verify(header(NO_T_HEADER.as_bytes()), NO_T_SIG);
    assert(out.signature.timestamp() == (false, 0));
}
