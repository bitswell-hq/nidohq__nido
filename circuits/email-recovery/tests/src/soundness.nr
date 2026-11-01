//! Negative tests for the publicly documented soundness issue classes of
//! open-source email circuits. Each test names its public source.
//!
//! Every header here is validly signed by the test key, so the RSA check
//! passes and the rejection comes from the check under test. Where an attack
//! is a choice of hints rather than of header bytes, the test starts from the
//! honest hints, changes them the way an attacker would, and expects the
//! constraint that refuses them. `should_fail_with` pins the exact assertion
//! that fails.
//!
//! Sources:
//! - Matter Labs, zkEmail audit (2024-10-25):
//!   https://docs.zk.email/files/matterlabs-zkemail-audit-report.pdf
//! - Zellic, zkEmail audit (2024-08-30):
//!   https://docs.zk.email/files/zkemail-zellic-audit-report.pdf
//! - zkSecurity, zkEmail audit (2024-05-27):
//!   https://docs.zk.email/files/zk_email_zksecurity_audit.pdf
//! - yAcademy, zkEmail audit (2023):
//!   https://docs.zk.email/files/yacademy-zkemail-audit-report.pdf
//! - Veridise, zkemail.nr audit (2024-12-03):
//!   https://github.com/zkemail/zkemail.nr/blob/main/audits/v1/veridise_v1.pdf
//! - Consensys Diligence, zkemail.nr audit (2024-12):
//!   https://github.com/zkemail/zkemail.nr/blob/main/audits/v1/consensys_diligence_v1.pdf
//! - RFC 6376 (DKIM): https://www.rfc-editor.org/rfc/rfc6376
//! - RFC 7489 (DMARC): https://www.rfc-editor.org/rfc/rfc7489

use crate::common::{body, header, HEADER_MAX, honest_hints, index_of, verify, verify_with};
use crate::vectors::{
    ADDRESS_LIKE_DISPLAY_NAME_HEADER, ADDRESS_LIKE_DISPLAY_NAME_SIG, B_NOT_EMPTY_HEADER,
    B_NOT_EMPTY_SIG, BH_ILLEGAL_CHAR_HEADER, BH_ILLEGAL_CHAR_SIG, BH_IN_Z_HEADER, BH_IN_Z_SIG, BODY,
    DECOY_IN_DISPLAY_NAME_HEADER, DECOY_IN_DISPLAY_NAME_SIG, DUPLICATE_BH_HEADER, DUPLICATE_BH_SIG,
    FOLDED_FROM_SIMPLE_HEADER, FOLDED_FROM_SIMPLE_SIG, FROM_THEN_TO_ANGLE_HEADER,
    FROM_THEN_TO_ANGLE_SIG, GMAIL_HEADER, GMAIL_SIG, GMAIL_SIG_PLUS_N, H_WITHOUT_FROM_HEADER,
    H_WITHOUT_FROM_SIG, H_WITHOUT_SUBJECT_HEADER, H_WITHOUT_SUBJECT_SIG, L_TAG_HEADER, L_TAG_SIG,
    L_TAG_SPACED_HEADER, L_TAG_SPACED_SIG, LAST_NOT_DKIM_HEADER, LAST_NOT_DKIM_SIG, NO_FROM_HEADER,
    NO_FROM_SIG, QUOTED_LOCAL_PART_HEADER, QUOTED_LOCAL_PART_SIG, REGEX_RESET_HEADER,
    REGEX_RESET_SIG, SIMPLE_CANON_HEADER, SIMPLE_CANON_SIG, SUBDOMAIN_D_HEADER, SUBDOMAIN_D_SIG,
    THIRD_PARTY_D_HEADER, THIRD_PARTY_D_SIG, TRAILING_CRLF_HEADER, TRAILING_CRLF_SIG,
    TWO_FROM_HEADER, TWO_FROM_SIG, TWO_SUBJECT_HEADER, TWO_SUBJECT_SIG, UNSIGNED_PREPENDED_HEADER,
};
use email_recovery::body::verify_body;
use email_recovery::from_address::FromHints;

global VICTIM: [u8; 16] = "victim@gmail.com".as_bytes();

/// Hints that claim `victim@gmail.com`, wherever it occurs first in `h`.
fn victim_hints(h: BoundedVec<u8, HEADER_MAX>) -> crate::common::Hints {
    let mut hints = honest_hints(h);
    hints.from =
        FromHints { addr_start: index_of(h.storage(), VICTIM, 0), addr_len: 16, at_index: 6 };
    hints
}

// ----------------------------------------------------------------------------
// Long or address-like display names spoofing From.
// Matter Labs finding 1 "Email spoofing via manipulated From header" (display
// name holding an angle-addr); Consensys Diligence 5.4 "Missing Validation of
// Header Field Sequence Length" (a long display name hides the real `<`).

/// The honest reading of `"x <victim@gmail.com> AAA..." <attacker@gmail.com>`
/// is refused: the field holds two angle-addrs.
#[test(should_fail_with = "From: the field must hold exactly one angle-addr")]
fn decoy_angle_addr_in_display_name_is_refused() {
    let _ = verify(
        header(DECOY_IN_DISPLAY_NAME_HEADER.as_bytes()),
        DECOY_IN_DISPLAY_NAME_SIG,
    );
}

/// Claiming the decoy instead: it does not end the field.
#[test(should_fail_with = "From: the address must end the field")]
fn decoy_angle_addr_cannot_be_claimed() {
    let h = header(DECOY_IN_DISPLAY_NAME_HEADER.as_bytes());
    let _ = verify_with(h, DECOY_IN_DISPLAY_NAME_SIG, victim_hints(h));
}

/// Claiming the address-like display name of
/// `victim@gmail.com <attacker@gmail.com>` as a bare address.
#[test(should_fail_with = "From: the address must end the field")]
fn address_like_display_name_cannot_be_claimed() {
    let h = header(ADDRESS_LIKE_DISPLAY_NAME_HEADER.as_bytes());
    let _ = verify_with(h, ADDRESS_LIKE_DISPLAY_NAME_SIG, victim_hints(h));
}

// Zellic 3.2 "Regular expression flaw related to email in circuit": the
// quoted local part `"victim@gmail.com"@spam.co.kr` yields the victim.

#[test(should_fail_with = "From: invalid character in the local part")]
fn quoted_local_part_is_refused() {
    let _ = verify(
        header(QUOTED_LOCAL_PART_HEADER.as_bytes()),
        QUOTED_LOCAL_PART_SIG,
    );
}

#[test(should_fail_with = "From: the address must end the field")]
fn address_inside_quoted_local_part_cannot_be_claimed() {
    let h = header(QUOTED_LOCAL_PART_HEADER.as_bytes());
    let _ = verify_with(h, QUOTED_LOCAL_PART_SIG, victim_hints(h));
}

#[test(should_fail_with = "From: a bare address must be the whole field value")]
fn suffix_of_quoted_local_part_cannot_be_claimed() {
    let h = header(QUOTED_LOCAL_PART_HEADER.as_bytes());
    let mut hints = honest_hints(h);
    // `victim@gmail.com"@gmail.com`: the field value minus its first byte.
    hints.from.addr_start += 1;
    hints.from.addr_len -= 1;
    hints.from.at_index -= 1;
    let _ = verify_with(h, QUOTED_LOCAL_PART_SIG, hints);
}

// ----------------------------------------------------------------------------
// Folded From under simple canonicalization.
// Consensys Diligence 5.1 "Header Field Extraction Can Be Fooled by Passing a
// Simple-Canonicalized Header": `from: ":alice@example.net>"\r\n <bob@...>`.

#[test(should_fail_with = "header: folded header line")]
fn folded_from_under_simple_canonicalization_is_refused() {
    let _ = verify(
        header(FOLDED_FROM_SIMPLE_HEADER.as_bytes()),
        FOLDED_FROM_SIMPLE_SIG,
    );
}

/// Simple header canonicalization is refused even without a fold.
#[test(should_fail_with = "DKIM: header canonicalization must be relaxed")]
fn simple_header_canonicalization_is_refused() {
    let _ = verify(header(SIMPLE_CANON_HEADER.as_bytes()), SIMPLE_CANON_SIG);
}

// ----------------------------------------------------------------------------
// Header fields spanning lines.
// Veridise V-ZEML-VUL-006 "First header value chars not validated";
// Consensys Diligence 5.2 "First Characters of Claimed Header Field Value
// Unchecked for CRLF"; zkemail.nr issue #57,
// https://github.com/zkemail/zkemail.nr/issues/57 (`to:x\r\nsubject:<victim>`).

/// `from:attacker@gmail.com\r\nto:<victim@gmail.com>`: claiming the To
/// address as the end of the From field.
#[test(should_fail_with = "From: field value spans more than one line")]
fn from_value_cannot_span_into_the_next_field() {
    let h = header(FROM_THEN_TO_ANGLE_HEADER.as_bytes());
    let _ = verify_with(h, FROM_THEN_TO_ANGLE_SIG, victim_hints(h));
}

// ----------------------------------------------------------------------------
// RSA signature malleability.
// Veridise V-ZEML-VUL-003 "Multiple nullifiers can be generated for a
// signature" (sig + N verifies too) and V-ZEML-VUL-004 "Un-normalized
// signature/DKIM keys".

#[test(should_fail_with = "RSA: signature is not below the modulus")]
fn signature_plus_modulus_is_refused() {
    let _ = verify(header(GMAIL_HEADER.as_bytes()), GMAIL_SIG_PLUS_N);
}

// ----------------------------------------------------------------------------
// Regex and parser resets.
// Matter Labs finding 2 "FromAddrRegex circuit allows for email address
// spoofing" (a 0xff byte resets the DFA: `subject: \xfffrom: victim`);
// zkSecurity #03 "Start ('^') and end ('$') of line match does not work.";
// zk-regex issue #119, https://github.com/zkemail/zk-regex/issues/119.

/// `cc:\xfffrom:<victim@gmail.com>`: claiming the text inside the Cc field.
#[test(should_fail_with = "From: field value spans more than one line")]
fn from_text_inside_another_field_cannot_be_claimed() {
    let h = header(REGEX_RESET_HEADER);
    let _ = verify_with(h, REGEX_RESET_SIG, victim_hints(h));
}

// ----------------------------------------------------------------------------
// bh= confusion. The header-only proof does not read bh= (spec section 4.4);
// these tests bind the body, where bh= matters.
// Veridise V-ZEML-VUL-001 "bh= may occur in other DKIM tags"; Consensys
// Diligence 5.10 "Several Leniencies in get_body_hash"; zkemail.nr PR #68,
// https://github.com/zkemail/zkemail.nr/pull/68.

/// Listing the `bh=` inside `z=Subject:bh=...` as a tag.
#[test(should_fail_with = "DKIM: listed offset is not a tag start")]
fn bh_inside_another_tag_cannot_be_listed() {
    let h = header(BH_IN_Z_HEADER.as_bytes());
    let mut hints = honest_hints(h);
    let field_start = index_of(h.storage(), "dkim-signature:".as_bytes(), 0);
    let fake = index_of(h.storage(), "bh=".as_bytes(), field_start) - field_start;
    // Put the fake offset in the list, in order, in place of the next tag.
    let mut j = 0;
    for i in 0..16 {
        if (i < hints.tags.tag_count) & (hints.tags.tag_starts[i] < fake) {
            j = i + 1;
        }
    }
    hints.tags.tag_starts[j] = fake;
    let _ = verify_with(h, BH_IN_Z_SIG, hints);
}

#[test(should_fail_with = "Body: bh= must appear exactly once")]
fn duplicate_bh_is_refused() {
    let out = verify(header(DUPLICATE_BH_HEADER.as_bytes()), DUPLICATE_BH_SIG);
    verify_body(out.signature, body(BODY.as_bytes()));
}

// yAcademy issue 1 "Missing constraint for illegal characters" (base64
// lookup maps illegal characters to 0).
#[test(should_fail_with = "Body: malformed bh=")]
fn bh_with_a_non_base64_character_is_refused() {
    let out = verify(
        header(BH_ILLEGAL_CHAR_HEADER.as_bytes()),
        BH_ILLEGAL_CHAR_SIG,
    );
    verify_body(out.signature, body(BODY.as_bytes()));
}

// ----------------------------------------------------------------------------
// l= body length limit.
// RFC 6376 section 8.2 "Misuse of Body Length Limits ("l=" Tag)",
// https://www.rfc-editor.org/rfc/rfc6376#section-8.2; Veridise
// V-ZEML-VUL-013 "Ignored DKIM Tags" (item 3).
// l= limits only the body hash, which the header-only proof does not read
// (spec section 4.4); where the body is bound, l= is refused.

#[test(should_fail_with = "Body: l= is not accepted")]
fn l_tag_is_refused_where_the_body_is_bound() {
    let out = verify(header(L_TAG_HEADER.as_bytes()), L_TAG_SIG);
    verify_body(out.signature, body(BODY.as_bytes()));
}

/// `l =20`: whitespace before `=` does not hide the tag.
#[test(should_fail_with = "Body: l= is not accepted")]
fn l_tag_with_space_is_refused_where_the_body_is_bound() {
    let out = verify(header(L_TAG_SPACED_HEADER.as_bytes()), L_TAG_SPACED_SIG);
    verify_body(out.signature, body(BODY.as_bytes()));
}

/// The header-only proof binds nothing l= can change: the signed header block
/// and its From and Subject are the same with or without it.
#[test]
fn l_tag_does_not_affect_the_header_only_proof() {
    let _ = verify(header(L_TAG_HEADER.as_bytes()), L_TAG_SIG);
}

/// Leaving `l=` out of the tag list: the list must cover every tag.
#[test(should_fail_with = "DKIM: tag list does not cover every tag")]
fn l_tag_cannot_be_left_out_of_the_tag_list() {
    let h = header(L_TAG_HEADER.as_bytes());
    let mut hints = honest_hints(h);
    let field_start = index_of(h.storage(), "dkim-signature:".as_bytes(), 0);
    let l_at = index_of(h.storage(), "l=20".as_bytes(), field_start) - field_start;
    let count = hints.tags.tag_count;
    let mut out = [0; 16];
    let mut n = 0;
    for i in 0..16 {
        if (i < count) & (hints.tags.tag_starts[i] != l_at) {
            out[n] = hints.tags.tag_starts[i];
            n += 1;
        }
    }
    hints.tags.tag_starts = out;
    hints.tags.tag_count = n;
    let _ = verify_with(h, L_TAG_SIG, hints);
}

// ----------------------------------------------------------------------------
// Misaligned d= (a signing domain other than the From domain).
// Veridise V-ZEML-VUL-013 "Ignored DKIM Tags" (item 5, d= ignored); zkEmail
// email-wallet issue #80, https://github.com/zkemail/email-wallet/issues/80
// (onmicrosoft.com tenants); old.archive.zk.email issue #88,
// https://github.com/zkemail/old.archive.zk.email/issues/88 (gappssmtp.com);
// RFC 7489 section 3.1.1,
// https://www.rfc-editor.org/rfc/rfc7489#section-3.1.1.

#[test(should_fail_with = "DKIM: d= must equal the From domain")]
fn third_party_signing_domain_is_refused() {
    let _ = verify(header(THIRD_PARTY_D_HEADER.as_bytes()), THIRD_PARTY_D_SIG);
}

#[test(should_fail_with = "DKIM: d= must equal the From domain")]
fn subdomain_signing_domain_is_refused() {
    let _ = verify(header(SUBDOMAIN_D_HEADER.as_bytes()), SUBDOMAIN_D_SIG);
}

// ----------------------------------------------------------------------------
// Unsigned headers and data outside the signed length.
// RFC 6376 section 3.7 (only h= fields and the DKIM-Signature field are
// hashed), https://www.rfc-editor.org/rfc/rfc6376#section-3.7, and section 5.4
// ("The From header field MUST be signed"); zkEmail ens-contracts PR #38,
// https://github.com/zkemail/ens-contracts/pull/38 (matches past the signed
// length); zk-email-verify issue #166,
// https://github.com/zkemail/zk-email-verify/issues/166 (fake headers in the
// padding).

/// An unsigned field prepended to a signed block.
#[test(should_fail_with = "RSA: signature does not verify")]
fn unsigned_field_cannot_be_added() {
    let _ = verify(header(UNSIGNED_PREPENDED_HEADER.as_bytes()), GMAIL_SIG);
}

/// A From field placed past the signed length.
#[test(should_fail_with = "header: bytes past the signed length must be zero")]
fn bytes_past_the_signed_length_are_refused() {
    let signed = GMAIL_HEADER.as_bytes();
    let tail = "\r\nfrom:victim@gmail.com".as_bytes();
    let mut storage = [0; HEADER_MAX];
    for i in 0..signed.len() {
        storage[i] = signed[i];
    }
    for i in 0..tail.len() {
        storage[signed.len() + i] = tail[i];
    }
    let _ = verify(
        BoundedVec::from_parts_unchecked(storage, signed.len()),
        GMAIL_SIG,
    );
}

/// A signature whose h= leaves From out covers no From field.
#[test(should_fail_with = "header: exactly one signed From field is required")]
fn unsigned_from_is_refused() {
    let _ = verify(header(NO_FROM_HEADER.as_bytes()), NO_FROM_SIG);
}

#[test(should_fail_with = "DKIM: h= must list from")]
fn h_without_from_is_refused() {
    let _ = verify(header(H_WITHOUT_FROM_HEADER.as_bytes()), H_WITHOUT_FROM_SIG);
}

#[test(should_fail_with = "DKIM: h= must list subject")]
fn h_without_subject_is_refused() {
    let _ = verify(
        header(H_WITHOUT_SUBJECT_HEADER.as_bytes()),
        H_WITHOUT_SUBJECT_SIG,
    );
}

/// The verified signature's own field must be the last signed line.
#[test(should_fail_with = "DKIM: the last signed field must be the DKIM-Signature field")]
fn last_field_must_be_the_dkim_signature() {
    let _ = verify(header(LAST_NOT_DKIM_HEADER.as_bytes()), LAST_NOT_DKIM_SIG);
}

#[test(should_fail_with = "header: the block must end with the DKIM-Signature field, without CRLF")]
fn block_must_not_end_with_crlf() {
    let _ = verify(header(TRAILING_CRLF_HEADER.as_bytes()), TRAILING_CRLF_SIG);
}

/// RFC 6376 section 3.7: the verified field is hashed with an empty b=.
#[test(should_fail_with = "DKIM: b= must be empty in the signed field")]
fn signed_field_with_a_b_value_is_refused() {
    let _ = verify(header(B_NOT_EMPTY_HEADER.as_bytes()), B_NOT_EMPTY_SIG);
}

// ----------------------------------------------------------------------------
// Duplicated headers.
// RFC 6376 section 5.4.2 and section 8.15 "Attacks Involving Extra Header
// Fields", https://www.rfc-editor.org/rfc/rfc6376#section-8.15 (MUAs may
// show only the first of several From fields); Veridise V-ZEML-VUL-005
// "Non-standard Email parsing" (item 1(b), repeated header fields).

#[test(should_fail_with = "header: exactly one signed From field is required")]
fn two_from_fields_are_refused() {
    let _ = verify(header(TWO_FROM_HEADER.as_bytes()), TWO_FROM_SIG);
}

#[test(should_fail_with = "header: exactly one signed Subject field is required")]
fn two_subject_fields_are_refused() {
    let _ = verify(header(TWO_SUBJECT_HEADER.as_bytes()), TWO_SUBJECT_SIG);
}
