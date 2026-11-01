//! The Subject field: a fixed ASCII phrase followed by a fixed-length
//! lowercase hexadecimal value, and nothing else.
//!
//! After relaxed canonicalization the field is `subject:<value>\r\n` with no
//! whitespace after the colon, runs of whitespace collapsed to one SP, and
//! none at the end; a Subject folded by the sending client arrives unfolded.
//! The value must be exactly `phrase ++ hex`, so there is no room for an RFC
//! 2047 encoded word, a reply prefix or trailing text.
//!
//! The phrase must be printable ASCII with single spaces, must not start
//! with a space and must not contain `=?`, so that the canonical form of the
//! Subject a user types is the phrase itself.
//!
//! For recovery (spec section 4.2) the phrase is `RECOVERY_PHRASE` and the
//! value is `hex(T)`, `T = P2(DOM_BLIND, digest_hi, digest_lo, rho)`:
//! `assert_subject_opens` checks it.

use crate::header::{HeaderLayout, SUBJECT_NAME_LEN};
use crate::spec::{DOM_BLIND, HEX_FIELD_LEN};
use crate::tables::{CR, HEX_LOWER, SP};
use poseidon::poseidon2::Poseidon2;

/// Constrains `phrase` to the form the Subject can carry after relaxed
/// canonicalization. Free when `phrase` is a compile-time constant.
pub fn assert_valid_phrase<let L: u32>(phrase: [u8; L]) {
    assert(L >= 1, "Subject: empty phrase");
    assert(phrase[0] != SP, "Subject: phrase starts with a space");
    for k in 0..L {
        let c = phrase[k];
        assert((c >= 32) & (c <= 126), "Subject: phrase must be printable ASCII");
        if k + 1 < L {
            assert(!((c == SP) & (phrase[k + 1] == SP)), "Subject: phrase has a double space");
            assert(!((c == 61) & (phrase[k + 1] == 63)), "Subject: phrase contains =?");
        }
    }
}

/// Returns the hex value carried after `phrase`, as its ASCII bytes.
pub fn parse_subject<let N: u32, let PHRASE_LEN: u32, let VALUE_LEN: u32>(
    h: [u8; N],
    layout: HeaderLayout<N>,
    phrase: [u8; PHRASE_LEN],
) -> [u8; VALUE_LEN] {
    assert_valid_phrase(phrase);
    let start = layout.subject_start + SUBJECT_NAME_LEN;
    assert(start + PHRASE_LEN + VALUE_LEN < N, "Subject: field runs past the header bound");
    for k in 0..PHRASE_LEN {
        assert(h[start + k] == phrase[k], "Subject: must start with the recovery phrase");
    }
    let mut value: [u8; VALUE_LEN] = [0; VALUE_LEN];
    for k in 0..VALUE_LEN {
        let c = h[start + PHRASE_LEN + k];
        assert(HEX_LOWER[c as u32] == 1, "Subject: value must be lowercase hex");
        value[k] = c;
    }
    assert(h[start + PHRASE_LEN + VALUE_LEN] == CR, "Subject: unexpected text after the value");
    value
}

/// Decodes lowercase hex ASCII into bytes. The input must already be checked
/// to be lowercase hex (as `parse_subject` does).
pub fn hex_to_bytes<let L: u32, let M: u32>(hex: [u8; L]) -> [u8; M] {
    assert(L == 2 * M, "hex: length must be twice the output length");
    let mut out: [u8; M] = [0; M];
    for i in 0..M {
        out[i] = nibble(hex[2 * i]) * 16 + nibble(hex[2 * i + 1]);
    }
    out
}

fn nibble(c: u8) -> u8 {
    // '0'..'9' is 48..57 and 'a'..'f' is 97..102.
    if c >= 97 {
        c - 87
    } else {
        c - 48
    }
}

/// `T = P2(DOM_BLIND, digest_hi, digest_lo, rho)` (spec section 4.2).
pub fn blinded_value(digest_hi: Field, digest_lo: Field, rho: Field) -> Field {
    Poseidon2::hash([DOM_BLIND, digest_hi, digest_lo, rho], 4)
}

/// `hex(x)`: the 64 lowercase hex characters of the canonical 32-byte
/// big-endian encoding of `x` (`to_be_bytes` refuses any encoding of `x + r`).
pub fn hex_of_field(x: Field) -> [u8; HEX_FIELD_LEN] {
    let bytes: [u8; 32] = x.to_be_bytes();
    let mut out: [u8; HEX_FIELD_LEN] = [0; HEX_FIELD_LEN];
    for i in 0..32 {
        out[2 * i] = hex_digit(bytes[i] >> 4);
        out[2 * i + 1] = hex_digit(bytes[i] & 15);
    }
    out
}

fn hex_digit(v: u8) -> u8 {
    if v < 10 {
        v + 48
    } else {
        v + 87
    }
}

/// Constrains the Subject value to be `hex(P2(DOM_BLIND, digest_hi,
/// digest_lo, rho))`: the email carries the blinded statement digest.
pub fn assert_subject_opens(
    value: [u8; HEX_FIELD_LEN],
    digest_hi: Field,
    digest_lo: Field,
    rho: Field,
) {
    let expected = hex_of_field(blinded_value(digest_hi, digest_lo, rho));
    assert(value == expected, "Subject: value does not open to the statement digest");
}
