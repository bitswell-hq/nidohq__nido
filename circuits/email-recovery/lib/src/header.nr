//! Structure of the signed header block.
//!
//! The block is the exact byte string the DKIM signature covers (RFC 6376
//! section 3.7): each header field named in `h=`, canonicalized and ending in CRLF,
//! then the DKIM-Signature field itself with its `b=` value emptied and no
//! trailing CRLF. Only relaxed header canonicalization is accepted (checked in
//! `dkim_signature`), so a field never spans lines: unfolding removed every
//! CRLF that was followed by whitespace, and field names are lowercase.
//!
//! `scan_header` checks, over every byte of the bounded array:
//!
//! - bytes at and past `len` are zero, so nothing outside the signed length
//!   can be parsed as signed data;
//! - every CR is followed by LF and every LF is preceded by CR;
//! - no CRLF is followed by SP or HTAB (no folded line);
//! - the block does not end with CRLF, so its last line is the field whose
//!   signature is being verified, and no line is empty;
//! - exactly one line starts with `from:` and exactly one with `subject:`.
//!
//! A line starts at byte 0 or right after a CRLF; nothing else is a line
//! start, so text inside a field value can never be taken for a field. The
//! scan returns, per byte, the index of the line it belongs to and a running
//! count of display-name faults: each line is read by the display-name
//! automaton of `tables` (spec section 4.5), and a byte is a fault when it
//! breaks that grammar in the state the line has reached. The From parser
//! uses them to prove that a range stays inside one line and is a display
//! name followed by the `<` of the angle-addr.

use crate::tables::{CR, HTAB, LF, PHRASE_FAULT, PHRASE_NEXT, PHRASE_OUT, SP};

comptime fn pack_be<let L: u32>(bytes: [u8; L]) -> Field {
    let mut acc: Field = 0;
    for i in 0..L {
        acc = acc * 256 + bytes[i] as Field;
    }
    acc
}

global FROM_NAME: Field = pack_be("from:".as_bytes());
global SUBJECT_NAME: Field = pack_be("subject:".as_bytes());
pub global FROM_NAME_LEN: u32 = 5;
pub global SUBJECT_NAME_LEN: u32 = 8;

pub struct HeaderLayout<let N: u32> {
    /// `line_of[i]` is the index of the line containing byte `i`.
    pub line_of: [Field; N],
    /// `phrase_faults_upto[i]` is the number of display-name faults in
    /// `0..=i`.
    pub phrase_faults_upto: [Field; N],
    /// Start of the only `from:` line.
    pub from_start: u32,
    /// Start of the only `subject:` line.
    pub subject_start: u32,
    /// Start of the last line, the DKIM-Signature field being verified.
    pub last_line_start: u32,
}

unconstrained fn field_to_u32_hint(x: Field) -> u32 {
    x as u32
}

/// `x` as a `u32`, for an `x` known to be a small non-negative integer. The
/// result is range-checked to 32 bits by its type and tied to `x` by an
/// equality, so no truncating cast happens in constrained code.
pub fn to_u32(x: Field) -> u32 {
    // Safety: the 32-bit result is constrained to equal `x` below.
    let v = unsafe { field_to_u32_hint(x) };
    assert(v as Field == x, "header: position out of range");
    v
}

/// Packs `L` bytes of `h` starting at the constant offset `i`, big-endian.
fn window<let N: u32, let L: u32>(h: [u8; N], i: u32) -> Field {
    let mut acc: Field = 0;
    for k in 0..L {
        acc = acc * 256 + h[i + k] as Field;
    }
    acc
}

pub fn scan_header<let N: u32>(header: BoundedVec<u8, N>) -> HeaderLayout<N> {
    let h = header.storage();
    let len = header.len();
    assert(len <= N, "header: length exceeds the bound");

    let mut is_cr: [Field; N] = [0; N];
    let mut is_lf: [Field; N] = [0; N];
    let mut is_ws: [Field; N] = [0; N];
    let mut at_len: [Field; N] = [0; N];
    for i in 0..N {
        let c = h[i];
        is_cr[i] = (c == CR) as Field;
        is_lf[i] = (c == LF) as Field;
        is_ws[i] = ((c == SP) | (c == HTAB)) as Field;
        at_len[i] = (i == len) as Field;
    }

    let mut line_of: [Field; N] = [0; N];
    let mut phrase_faults_upto: [Field; N] = [0; N];
    let mut line: Field = 0;
    let mut phrase: u8 = PHRASE_OUT;
    let mut phrase_faults: Field = 0;
    let mut last_start: Field = 0;
    let mut from_count: Field = 0;
    let mut from_at: Field = 0;
    let mut subject_count: Field = 0;
    let mut subject_at: Field = 0;

    for i in 0..N {
        let c = h[i];
        assert((i < len) | (c == 0), "header: bytes past the signed length must be zero");

        let next_lf = if i + 1 < N { is_lf[i + 1] } else { 0 };
        let next_ws = if i + 1 < N { is_ws[i + 1] } else { 0 };
        let next_at_len = if i + 1 < N {
            at_len[i + 1]
        } else {
            (len == N) as Field
        };
        let prev_cr = if i > 0 { is_cr[i - 1] } else { 0 };
        assert(is_cr[i] * (1 - next_lf) == 0, "header: CR not followed by LF");
        assert(is_lf[i] * (1 - prev_cr) == 0, "header: LF not preceded by CR");
        assert(is_lf[i] * next_ws == 0, "header: folded header line");
        assert(
            is_lf[i] * next_at_len == 0,
            "header: the block must end with the DKIM-Signature field, without CRLF",
        );

        // Past `len` every byte is zero, so no line starts there.
        // Running values are kept as single witnesses: left symbolic, an
        // expression over them would grow with i, and the circuit with i^2.
        let line_start: Field = if i == 0 { 1 } else { is_lf[i - 1] };
        assert(line_start * is_cr[i] == 0, "header: empty line");
        if i > 0 {
            line += line_start;
            std::as_witness(line);
        }
        line_of[i] = line;
        last_start += line_start * (i as Field - last_start);
        std::as_witness(last_start);

        if i + FROM_NAME_LEN <= N {
            let m = line_start * (window::<N, 5>(h, i) == FROM_NAME) as Field;
            from_count += m;
            from_at += m * i as Field;
            std::as_witness(from_count);
            std::as_witness(from_at);
        }
        if i + SUBJECT_NAME_LEN <= N {
            let m = line_start * (window::<N, 8>(h, i) == SUBJECT_NAME) as Field;
            subject_count += m;
            subject_at += m * i as Field;
            std::as_witness(subject_count);
            std::as_witness(subject_at);
        }

        let k = phrase as u32 * 256 + c as u32;
        phrase_faults += PHRASE_FAULT[k];
        std::as_witness(phrase_faults);
        phrase_faults_upto[i] = phrase_faults;
        phrase = PHRASE_NEXT[k];
    }

    assert(from_count == 1, "header: exactly one signed From field is required");
    assert(subject_count == 1, "header: exactly one signed Subject field is required");

    HeaderLayout {
        line_of,
        phrase_faults_upto,
        from_start: to_u32(from_at),
        subject_start: to_u32(subject_at),
        last_line_start: to_u32(last_start),
    }
}
