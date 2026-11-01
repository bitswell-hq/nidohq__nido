//! The DKIM-Signature field whose signature is being verified (spec section
//! 4.3).
//!
//! RFC 6376 section 3.7 appends that field last, canonicalized, with its `b=`
//! value emptied and without a trailing CRLF, so it is the last line of the
//! signed block (`header::scan_header` proves the block's last line has no
//! CRLF after it). Any other DKIM-Signature field in the block is an ordinary
//! signed line and is never read here.
//!
//! The field is `dkim-signature:` followed by a tag list (RFC 6376 section
//! 3.2). A tag starts at the first byte after the colon, or after a `;` and at
//! most one SP (relaxed canonicalization collapses whitespace runs to one
//! SP). Tag starts are found by scanning every byte of the field; the prover
//! lists them, and the list must contain exactly the scanned starts in
//! increasing order. Each listed tag is then classified by name, so every tag
//! is seen, and a value can only be read at a real tag boundary (never from
//! text inside another tag's value, such as a `z=` copy of the Subject).
//!
//! `check_dkim_signature` requires, each exactly once: `v=1`,
//! `a=rsa-sha256`, `c=relaxed/relaxed` or `c=relaxed/simple`, `d=` equal to
//! the From address's domain when both are lowercased (so a third-party
//! signing domain is refused), `h=` listing `from` and `subject`
//! (case-insensitively), and an empty `b=`. The values of those tags must
//! follow their `=` directly and end at `;` or at the end of the field.
//!
//! The header-only proof does not bind the body, so `bh=`, `l=` and `t=` are
//! located and counted here but required only by the accessors that use
//! them: `body_hash_b64` (no `l=`, exactly one well-formed `bh=`) and
//! `timestamp` (at most one `t=` of 1 to 12 digits).

use crate::from_address::FromAddress;
use crate::header::{HeaderLayout, to_u32};
use crate::spec::DOMAIN_MAX;
use crate::tables::{BASE64, DIGIT, DIGIT_VALUE, LOWER, read_if, SP};

global FIELD_NAME: [u8; 15] = "dkim-signature:".as_bytes();
pub global FIELD_NAME_LEN: u32 = 15;
pub global BODY_HASH_B64_LEN: u32 = 44;
pub global MAX_TIMESTAMP_DIGITS: u32 = 12;

/// Prover-supplied positions, all checked. Offsets are relative to the start
/// of the DKIM-Signature field.
pub struct DkimTagHints<let MAX_TAGS: u32> {
    /// Offsets of every tag start, increasing; entries past `tag_count` are
    /// ignored.
    pub tag_starts: [u32; MAX_TAGS],
    pub tag_count: u32,
    /// Offset of the `from` entry in the `h=` list.
    pub h_from: u32,
    /// Offset of the `subject` entry in the `h=` list.
    pub h_subject: u32,
    /// Number of digits in `t=`, 0 when there is no `t=` tag.
    pub t_len: u32,
}

/// The checked DKIM-Signature field.
pub struct DkimSignature<let MAX_FIELD: u32> {
    /// The field's bytes, zero past `field_len`.
    pub field: [u8; MAX_FIELD],
    pub field_len: u32,
    /// The `d=` value lowercased, which equals the From domain lowercased.
    pub domain: BoundedVec<u8, DOMAIN_MAX>,
    l_count: Field,
    bh_count: Field,
    bh_at: u32,
    t_count: Field,
    t_at: u32,
    t_len: u32,
}

fn byte_at<let M: u32>(d: [u8; M], i: u32) -> u8 {
    read_if(d, i, i < M)
}

/// Whether `lit` occurs in `d` at `at`.
fn has_at<let M: u32, let L: u32>(d: [u8; M], at: u32, lit: [u8; L]) -> bool {
    let mut ok = true;
    for k in 0..L {
        ok &= byte_at(d, at + k) == lit[k];
    }
    ok
}

/// Whether a tag value ends at `q`: a `;` or the end of the field.
fn value_ends_at<let M: u32>(d: [u8; M], flen: u32, q: u32) -> bool {
    (q == flen) | (byte_at(d, q) == 59)
}

/// Whether `d` holds the header name `lower` at `at` as a complete `h=` entry,
/// compared case-insensitively.
fn is_h_entry<let M: u32, let L: u32>(d: [u8; M], flen: u32, at: u32, lower: [u8; L]) -> bool {
    let before = byte_at(d, at - 1);
    let after = byte_at(d, at + L);
    let mut ok = (before == 61) | (before == 58) | (before == SP);
    ok &= (after == 58) | (after == 59) | (after == SP) | (at + L == flen);
    for k in 0..L {
        let c = byte_at(d, at + k);
        ok &= (c == lower[k]) | (c == lower[k] - 32);
    }
    ok
}

pub fn check_dkim_signature<let N: u32, let MAX_FIELD: u32, let MAX_TAGS: u32, let MAX_ADDR: u32>(
    h: [u8; N],
    len: u32,
    layout: HeaderLayout<N>,
    from: FromAddress<MAX_ADDR>,
    hints: DkimTagHints<MAX_TAGS>,
) -> DkimSignature<MAX_FIELD> {
    let start = layout.last_line_start;
    let flen = len - start;
    assert(flen + 4 <= MAX_FIELD, "DKIM: DKIM-Signature field exceeds the bound");
    let mut d: [u8; MAX_FIELD] = [0; MAX_FIELD];
    for k in 0..MAX_FIELD {
        d[k] = read_if(h, start + k, k < flen);
    }
    for k in 0..FIELD_NAME_LEN {
        assert(
            d[k] == FIELD_NAME[k],
            "DKIM: the last signed field must be the DKIM-Signature field",
        );
    }

    // Tag starts: the first byte after the colon, or after `;` or `; `.
    let mut is_semi: [bool; MAX_FIELD] = [false; MAX_FIELD];
    let mut is_sp: [bool; MAX_FIELD] = [false; MAX_FIELD];
    for k in 0..MAX_FIELD {
        is_semi[k] = d[k] == 59;
        is_sp[k] = d[k] == SP;
    }
    let mut tag_start: [Field; MAX_FIELD] = [0; MAX_FIELD];
    let mut tag_total: Field = 0;
    for k in FIELD_NAME_LEN..MAX_FIELD {
        let after_separator = if k == FIELD_NAME_LEN {
            true
        } else if k == FIELD_NAME_LEN + 1 {
            is_semi[k - 1]
        } else {
            is_semi[k - 1] | (is_sp[k - 1] & is_semi[k - 2])
        };
        let ts = (k < flen) & after_separator & !is_sp[k] & !is_semi[k];
        tag_start[k] = ts as Field;
        tag_total += ts as Field;
        std::as_witness(tag_total);
    }

    // The prover's list must be exactly the tag starts, in increasing order.
    let count = hints.tag_count;
    assert(count <= MAX_TAGS, "DKIM: too many tags");
    assert(count as Field == tag_total, "DKIM: tag list does not cover every tag");
    let (mut n_v, mut n_a, mut n_c, mut n_d, mut n_h, mut n_t, mut n_b, mut n_l, mut n_bh) =
        (0, 0, 0, 0, 0, 0, 0, 0, 0);
    let (mut at_v, mut at_a, mut at_c, mut at_d, mut at_h, mut at_t, mut at_b, mut at_bh) =
        (0, 0, 0, 0, 0, 0, 0, 0);
    let mut h_next: Field = 0;
    let mut prev: u32 = 0;
    for j in 0..MAX_TAGS {
        let active = j < count;
        let p = if active { hints.tag_starts[j] } else { 0 };
        assert(!active | (p < flen), "DKIM: tag offset out of range");
        assert(!active | (tag_start[p] == 1), "DKIM: listed offset is not a tag start");
        if j > 0 {
            assert(!active | (p > prev), "DKIM: tag offsets must increase");
        }
        prev = p;

        let next: u32 = if j + 1 < MAX_TAGS {
            if j + 1 < count {
                hints.tag_starts[j + 1]
            } else {
                flen
            }
        } else {
            flen
        };
        let (c0, c1, c2, c3) = (d[p], d[p + 1], d[p + 2], d[p + 3]);
        // A one- or two-letter name followed by `=`, allowing one SP before it.
        let name1 = active & ((c1 == 61) | ((c1 == SP) & (c2 == 61)));
        let name2 = active & ((c2 == 61) | ((c2 == SP) & (c3 == 61)));
        let pf = p as Field;
        let is_v = (name1 & (c0 == 118)) as Field;
        let is_a = (name1 & (c0 == 97)) as Field;
        let is_c = (name1 & (c0 == 99)) as Field;
        let is_d = (name1 & (c0 == 100)) as Field;
        let is_h = (name1 & (c0 == 104)) as Field;
        let is_t = (name1 & (c0 == 116)) as Field;
        let is_b = (name1 & (c0 == 98)) as Field;
        let is_l = (name1 & (c0 == 108)) as Field;
        let is_bh = (name2 & (c0 == 98) & (c1 == 104)) as Field;
        n_v += is_v;
        n_a += is_a;
        n_c += is_c;
        n_d += is_d;
        n_h += is_h;
        n_t += is_t;
        n_b += is_b;
        n_l += is_l;
        n_bh += is_bh;
        at_v += is_v * pf;
        at_a += is_a * pf;
        at_c += is_c * pf;
        at_d += is_d * pf;
        at_h += is_h * pf;
        at_t += is_t * pf;
        at_b += is_b * pf;
        at_bh += is_bh * pf;
        h_next += is_h * next as Field;
    }
    assert(n_v == 1, "DKIM: v= must appear exactly once");
    assert(n_a == 1, "DKIM: a= must appear exactly once");
    assert(n_c == 1, "DKIM: c= must appear exactly once");
    assert(n_d == 1, "DKIM: d= must appear exactly once");
    assert(n_h == 1, "DKIM: h= must appear exactly once");
    assert(n_b == 1, "DKIM: b= must appear exactly once");

    let (pv, pa, pc, pd, ph, pb) =
        (to_u32(at_v), to_u32(at_a), to_u32(at_c), to_u32(at_d), to_u32(at_h), to_u32(at_b));

    assert(
        has_at(d, pv + 1, "=1".as_bytes()) & value_ends_at(d, flen, pv + 3),
        "DKIM: v= must be 1",
    );
    assert(
        has_at(d, pa + 1, "=rsa-sha256".as_bytes()) & value_ends_at(d, flen, pa + 12),
        "DKIM: a= must be rsa-sha256",
    );
    let relaxed_relaxed =
        has_at(d, pc + 1, "=relaxed/relaxed".as_bytes()) & value_ends_at(d, flen, pc + 17);
    let relaxed_simple =
        has_at(d, pc + 1, "=relaxed/simple".as_bytes()) & value_ends_at(d, flen, pc + 16);
    assert(relaxed_relaxed | relaxed_simple, "DKIM: header canonicalization must be relaxed");
    assert(
        (byte_at(d, pb + 1) == 61) & value_ends_at(d, flen, pb + 2),
        "DKIM: b= must be empty in the signed field",
    );

    // d= is the From domain, compared lowercase; the lowercase value is the
    // registry-leaf domain.
    let domain_len = from.domain_len();
    assert(domain_len <= DOMAIN_MAX, "DKIM: d= must be at most 62 bytes");
    let addr = from.address.storage();
    assert(byte_at(d, pd + 1) == 61, "DKIM: d= must equal the From domain");
    let mut domain: [u8; DOMAIN_MAX] = [0; DOMAIN_MAX];
    for k in 0..MAX_ADDR {
        let in_domain = k < domain_len;
        let ours = LOWER[read_if(d, pd + 2 + k, in_domain & (pd + 2 + k < MAX_FIELD)) as u32];
        let theirs = LOWER[read_if(addr, from.at_index + 1 + k, in_domain) as u32];
        assert(ours == theirs, "DKIM: d= must equal the From domain");
        if k < DOMAIN_MAX {
            domain[k] = ours;
        }
    }
    assert(value_ends_at(d, flen, pd + 2 + domain_len), "DKIM: d= must equal the From domain");

    // h= lists from and subject.
    let h_end = to_u32(h_next);
    let (hf, hs) = (hints.h_from, hints.h_subject);
    assert((hf >= ph + 2) & (hf + 4 <= h_end), "DKIM: h= must list from");
    assert(is_h_entry(d, flen, hf, "from".as_bytes()), "DKIM: h= must list from");
    assert((hs >= ph + 2) & (hs + 7 <= h_end), "DKIM: h= must list subject");
    assert(is_h_entry(d, flen, hs, "subject".as_bytes()), "DKIM: h= must list subject");

    DkimSignature {
        field: d,
        field_len: flen,
        domain: BoundedVec::from_parts_unchecked(domain, domain_len),
        l_count: n_l,
        bh_count: n_bh,
        bh_at: to_u32(at_bh),
        t_count: n_t,
        t_at: to_u32(at_t),
        t_len: hints.t_len,
    }
}

impl<let MAX_FIELD: u32> DkimSignature<MAX_FIELD> {
    /// The `bh=` value, for binding the body: refuses `l=` (RFC 6376 section
    /// 8.2: a length limit lets content be appended after the signed body),
    /// and requires exactly one `bh=` of 43 base64 characters and one `=`.
    pub fn body_hash_b64(self) -> [u8; BODY_HASH_B64_LEN] {
        let d = self.field;
        let p = self.bh_at;
        assert(self.l_count == 0, "Body: l= is not accepted");
        assert(self.bh_count == 1, "Body: bh= must appear exactly once");
        assert(
            (byte_at(d, p + 2) == 61) & value_ends_at(d, self.field_len, p + 3 + BODY_HASH_B64_LEN),
            "Body: malformed bh=",
        );
        let mut out: [u8; BODY_HASH_B64_LEN] = [0; BODY_HASH_B64_LEN];
        for k in 0..BODY_HASH_B64_LEN {
            let c = byte_at(d, p + 3 + k);
            if k + 1 < BODY_HASH_B64_LEN {
                assert(BASE64[c as u32] == 1, "Body: malformed bh=");
            } else {
                assert(c == 61, "Body: malformed bh=");
            }
            out[k] = c;
        }
        out
    }

    /// The `t=` value when present: `(true, t)` for 1 to 12 decimal digits,
    /// `(false, 0)` when there is no `t=` tag.
    pub fn timestamp(self) -> (bool, u64) {
        let d = self.field;
        let p = self.t_at;
        let t_len = self.t_len;
        assert(self.t_count * (self.t_count - 1) == 0, "DKIM: t= may appear at most once");
        let present = self.t_count == 1;
        if present {
            assert(
                (t_len >= 1)
                    & (t_len <= MAX_TIMESTAMP_DIGITS)
                    & (byte_at(d, p + 1) == 61)
                    & value_ends_at(d, self.field_len, p + 2 + t_len),
                "DKIM: malformed t=",
            );
        } else {
            assert(t_len == 0, "DKIM: malformed t=");
        }
        let mut value: Field = 0;
        for k in 0..MAX_TIMESTAMP_DIGITS {
            let in_value = k < t_len;
            let c = read_if(d, p + 2 + k, in_value & (p + 2 + k < MAX_FIELD));
            assert(!in_value | (DIGIT[c as u32] == 1), "DKIM: malformed t=");
            if in_value {
                value = value * 10 + DIGIT_VALUE[c as u32];
            }
        }
        // At most 12 digits, so the value fits in 40 bits.
        value.assert_max_bit_size::<40>();
        (present, if present { to_u64(value) } else { 0 })
    }
}

unconstrained fn field_to_u64_hint(x: Field) -> u64 {
    x as u64
}

fn to_u64(x: Field) -> u64 {
    // Safety: the 64-bit result is constrained to equal `x`.
    let v = unsafe { field_to_u64_hint(x) };
    assert(v as Field == x, "DKIM: malformed t=");
    v
}
