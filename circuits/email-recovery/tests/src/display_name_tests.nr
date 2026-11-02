//! The From display-name grammar (spec section 4.5): outside quoted strings
//! only `atext`, `.` and SP; quoted strings closed, with `\` only as a
//! quoted-pair inside them; no `<` or `>` before the angle-addr.
//!
//! A From value whose display name breaks this grammar can read, to an
//! RFC 5322 parser, as an address list, as a different mailbox, or as no
//! mailbox, while the circuit binds the angle-addr that ends the field. A
//! provider that authenticates only the first address of a list would sign
//! such a value for an account that does not own the last one: Chen, Paxson
//! and Jiang, "Composition Kills: A Case Study of Email Sender
//! Authentication", USENIX Security 2020, section 6.2, report Yahoo and
//! iCloud servers that "accept multiple addresses and only check the first
//! address" (https://www.usenix.org/system/files/sec20-chen-jianjun.pdf).
//!
//! Every header here is validly signed by the test key for the bound
//! address's domain, so each refusal comes from the display-name check.

use crate::common::{equals, header, verify};
use crate::vectors::{
    ADDRESS_LIKE_DISPLAY_NAME_HEADER, ADDRESS_LIKE_DISPLAY_NAME_SIG, DISPLAY_NAME_BACKSLASH_HEADER,
    DISPLAY_NAME_BACKSLASH_SIG, DISPLAY_NAME_COLON_HEADER, DISPLAY_NAME_COLON_SIG,
    DISPLAY_NAME_COMMA_HEADER, DISPLAY_NAME_COMMA_SIG, DISPLAY_NAME_COMMENT_HEADER,
    DISPLAY_NAME_COMMENT_SIG, DISPLAY_NAME_ENCODED_WORD_B_HEADER, DISPLAY_NAME_ENCODED_WORD_B_SIG,
    DISPLAY_NAME_ENCODED_WORD_Q_HEADER, DISPLAY_NAME_ENCODED_WORD_Q_SIG,
    DISPLAY_NAME_ESCAPED_CLOSING_QUOTE_HEADER, DISPLAY_NAME_ESCAPED_CLOSING_QUOTE_SIG,
    DISPLAY_NAME_GREATER_THAN_HEADER, DISPLAY_NAME_GREATER_THAN_SIG, DISPLAY_NAME_GROUP_HEADER,
    DISPLAY_NAME_GROUP_SIG, DISPLAY_NAME_MIXED_PHRASE_HEADER, DISPLAY_NAME_MIXED_PHRASE_SIG,
    DISPLAY_NAME_QUOTED_SPECIALS_HEADER, DISPLAY_NAME_QUOTED_SPECIALS_SIG,
    DISPLAY_NAME_SEMICOLON_HEADER, DISPLAY_NAME_SEMICOLON_SIG, DISPLAY_NAME_TWO_ANGLE_ADDRS_HEADER,
    DISPLAY_NAME_TWO_ANGLE_ADDRS_SIG, FROM_ADDRESS_BEFORE_ANGLE_ADDR_HEADER,
    FROM_ADDRESS_BEFORE_ANGLE_ADDR_SIG, FROM_ADDRESS_LIST_HEADER, FROM_ADDRESS_LIST_SIG,
    FROM_QUOTED_WORD_THEN_ADDRESS_HEADER, FROM_QUOTED_WORD_THEN_ADDRESS_SIG,
    FROM_UNBALANCED_QUOTE_HEADER, FROM_UNBALANCED_QUOTE_SIG, GMAIL_HEADER, GMAIL_SIG,
    OUTLOOK_HEADER, OUTLOOK_SIG, QUOTE_OPEN_IN_EARLIER_FIELD_HEADER,
    QUOTE_OPEN_IN_EARLIER_FIELD_SIG,
};

// ----------------------------------------------------------------------------
// Values an RFC 5322 reader does not read as exactly the bound mailbox.

/// `b4ionwm6.ajw@yahoo.com, x <t5w6.i9otz@yahoo.com>`: a valid address list
/// whose first mailbox is not the angle-addr.
#[test(should_fail_with = "From: invalid display name")]
fn address_list_is_refused() {
    let _ = verify(
        header(FROM_ADDRESS_LIST_HEADER.as_bytes()),
        FROM_ADDRESS_LIST_SIG,
    );
}

/// `b4ionwm6.ajw@yahoo.com <t5w6.i9otz@yahoo.com>`: an unquoted address
/// before the angle-addr, which lenient readers take as the mailbox.
#[test(should_fail_with = "From: invalid display name")]
fn address_before_the_angle_addr_is_refused() {
    let _ = verify(
        header(FROM_ADDRESS_BEFORE_ANGLE_ADDR_HEADER.as_bytes()),
        FROM_ADDRESS_BEFORE_ANGLE_ADDR_SIG,
    );
}

/// `"q97" b4ionwm6.ajw@yahoo.com <t5w6.i9otz@yahoo.com>`: read as the
/// mailbox `"q97 b4ionwm6.ajw"@yahoo.com`.
#[test(should_fail_with = "From: invalid display name")]
fn quoted_word_then_address_is_refused() {
    let _ = verify(
        header(FROM_QUOTED_WORD_THEN_ADDRESS_HEADER.as_bytes()),
        FROM_QUOTED_WORD_THEN_ADDRESS_SIG,
    );
}

/// `"x <t5w6.i9otz@yahoo.com>`: the angle-addr is inside an unclosed quoted
/// string, so there is no mailbox.
#[test(should_fail_with = "From: invalid display name")]
fn unbalanced_quote_is_refused() {
    let _ = verify(
        header(FROM_UNBALANCED_QUOTE_HEADER.as_bytes()),
        FROM_UNBALANCED_QUOTE_SIG,
    );
}

// ----------------------------------------------------------------------------
// One RFC 5322 special outside a quoted string.

/// `victim@gmail.com <attacker@gmail.com>`: an unquoted `@`.
#[test(should_fail_with = "From: invalid display name")]
fn unquoted_at_sign_is_refused() {
    let _ = verify(
        header(ADDRESS_LIKE_DISPLAY_NAME_HEADER.as_bytes()),
        ADDRESS_LIKE_DISPLAY_NAME_SIG,
    );
}

/// `Doe, John <victim@gmail.com>`: an unquoted `,` separates two list
/// entries.
#[test(should_fail_with = "From: invalid display name")]
fn unquoted_comma_is_refused() {
    let _ = verify(
        header(DISPLAY_NAME_COMMA_HEADER.as_bytes()),
        DISPLAY_NAME_COMMA_SIG,
    );
}

#[test(should_fail_with = "From: invalid display name")]
fn unquoted_semicolon_is_refused() {
    let _ = verify(
        header(DISPLAY_NAME_SEMICOLON_HEADER.as_bytes()),
        DISPLAY_NAME_SEMICOLON_SIG,
    );
}

#[test(should_fail_with = "From: invalid display name")]
fn unquoted_colon_is_refused() {
    let _ = verify(
        header(DISPLAY_NAME_COLON_HEADER.as_bytes()),
        DISPLAY_NAME_COLON_SIG,
    );
}

/// `friends: attacker <victim@gmail.com>`: shaped as a group.
#[test(should_fail_with = "From: invalid display name")]
fn group_shaped_value_is_refused() {
    let _ = verify(
        header(DISPLAY_NAME_GROUP_HEADER.as_bytes()),
        DISPLAY_NAME_GROUP_SIG,
    );
}

#[test(should_fail_with = "From: invalid display name")]
fn unquoted_backslash_is_refused() {
    let _ = verify(
        header(DISPLAY_NAME_BACKSLASH_HEADER.as_bytes()),
        DISPLAY_NAME_BACKSLASH_SIG,
    );
}

/// `x (y) <victim@gmail.com>`: a comment.
#[test(should_fail_with = "From: invalid display name")]
fn parentheses_are_refused() {
    let _ = verify(
        header(DISPLAY_NAME_COMMENT_HEADER.as_bytes()),
        DISPLAY_NAME_COMMENT_SIG,
    );
}

/// `"x\" <victim@gmail.com>`: the quoted-pair `\"` does not close the
/// string, so the `<` is inside it.
#[test(should_fail_with = "From: invalid display name")]
fn escaped_closing_quote_leaves_the_string_open() {
    let _ = verify(
        header(DISPLAY_NAME_ESCAPED_CLOSING_QUOTE_HEADER.as_bytes()),
        DISPLAY_NAME_ESCAPED_CLOSING_QUOTE_SIG,
    );
}

#[test(should_fail_with = "From: invalid display name")]
fn greater_than_in_display_name_is_refused() {
    let _ = verify(
        header(DISPLAY_NAME_GREATER_THAN_HEADER.as_bytes()),
        DISPLAY_NAME_GREATER_THAN_SIG,
    );
}

/// `<attacker@gmail.com> <victim@gmail.com>`: two angle-addrs.
#[test(should_fail_with = "From: invalid display name")]
fn second_angle_addr_is_refused() {
    let _ = verify(
        header(DISPLAY_NAME_TWO_ANGLE_ADDRS_HEADER.as_bytes()),
        DISPLAY_NAME_TWO_ANGLE_ADDRS_SIG,
    );
}

// ----------------------------------------------------------------------------
// Accepted display names.

/// `"Alice Example" <alice.example@gmail.com>`.
#[test]
fn quoted_display_name() {
    let out = verify(header(GMAIL_HEADER.as_bytes()), GMAIL_SIG);
    assert(equals(out.from_address, "alice.example@gmail.com".as_bytes()));
}

/// `"Doe, John (x) a@b; c:d \"JD\" \\" <alice.example@gmail.com>`: specials
/// are text inside a quoted string, and `\"` and `\\` are quoted-pairs.
#[test]
fn quoted_display_name_with_specials_and_quoted_pairs() {
    let out = verify(
        header(DISPLAY_NAME_QUOTED_SPECIALS_HEADER.as_bytes()),
        DISPLAY_NAME_QUOTED_SPECIALS_SIG,
    );
    assert(equals(out.from_address, "alice.example@gmail.com".as_bytes()));
}

/// RFC 2047 encoded-words are `atext` with `=?` and `?=`.
#[test]
fn encoded_word_display_name_b() {
    let out = verify(
        header(DISPLAY_NAME_ENCODED_WORD_B_HEADER.as_bytes()),
        DISPLAY_NAME_ENCODED_WORD_B_SIG,
    );
    assert(equals(out.from_address, "alice.example@gmail.com".as_bytes()));
}

#[test]
fn encoded_word_display_name_q() {
    let out = verify(
        header(DISPLAY_NAME_ENCODED_WORD_Q_HEADER.as_bytes()),
        DISPLAY_NAME_ENCODED_WORD_Q_SIG,
    );
    assert(equals(out.from_address, "alice.example@gmail.com".as_bytes()));
}

/// `Alice "the Great" Q. Example <alice.example@gmail.com>`: atoms, a
/// quoted string and a `.` in one phrase.
#[test]
fn mixed_phrase() {
    let out = verify(
        header(DISPLAY_NAME_MIXED_PHRASE_HEADER.as_bytes()),
        DISPLAY_NAME_MIXED_PHRASE_SIG,
    );
    assert(equals(out.from_address, "alice.example@gmail.com".as_bytes()));
}

/// `bob-smith_99@outlook.com`, no display name.
#[test]
fn bare_address() {
    let out = verify(header(OUTLOOK_HEADER.as_bytes()), OUTLOOK_SIG);
    assert(equals(out.from_address, "bob-smith_99@outlook.com".as_bytes()));
}

/// A signed To before From holding an unclosed quoted string: each line
/// starts outside a quoted string, so From is read on its own.
#[test]
fn quote_left_open_in_an_earlier_field_does_not_reach_from() {
    let out = verify(
        header(QUOTE_OPEN_IN_EARLIER_FIELD_HEADER.as_bytes()),
        QUOTE_OPEN_IN_EARLIER_FIELD_SIG,
    );
    assert(equals(out.from_address, "alice.example@gmail.com".as_bytes()));
}
