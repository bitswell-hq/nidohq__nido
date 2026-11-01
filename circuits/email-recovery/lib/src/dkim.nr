//! Header-only DKIM verification: the composition of the components over one
//! signed header block (spec obligations C1 and C2, and the header parts of
//! C3, C4, C5 and C6).
//!
//! An accepted call proves that `signature` is an RSA-2048 PKCS#1 v1.5
//! SHA-256 signature, under the key whose hash is `key_hash`, of a header
//! block in which:
//!
//! - the last field is the DKIM-Signature field being verified, with `v=1`,
//!   `a=rsa-sha256`, relaxed header canonicalization, `h=` covering `from`
//!   and `subject`, and a `d=` equal to the From domain when both are
//!   lowercased;
//! - exactly one From field names `from_address`, the address that closes
//!   the field;
//! - exactly one Subject field is `phrase` followed by `subject_value`.
//!
//! `domain` is the lowercase `d=`, the registry-leaf domain. The caller binds
//! the rest: the address commitment (`pack::address_commitment`), the
//! Subject opening (`subject::assert_subject_opens`), the key's registry
//! membership (`registry`), and, where the body matters, the body
//! (`body::verify_body` with `signature`).

use crate::dkim_signature::{check_dkim_signature, DkimSignature, DkimTagHints, FIELD_NAME_LEN};
use crate::from_address::{FromHints, parse_from};
use crate::header::scan_header;
use crate::pack::key_hash;
use crate::rsa::{RSA_LIMBS, verify_pkcs1v15_sha256};
use crate::spec::DOMAIN_MAX;
use crate::subject::parse_subject;
use sha256::sha256_var;

pub struct DkimHeaderHints<let MAX_TAGS: u32> {
    pub from: FromHints,
    pub tags: DkimTagHints<MAX_TAGS>,
}

pub struct VerifiedHeader<let MAX_ADDR: u32, let VALUE_LEN: u32, let MAX_FIELD: u32> {
    pub from_address: BoundedVec<u8, MAX_ADDR>,
    pub domain: BoundedVec<u8, DOMAIN_MAX>,
    pub subject_value: [u8; VALUE_LEN],
    pub key_hash: Field,
    pub signature: DkimSignature<MAX_FIELD>,
}

pub fn verify_dkim_header_with_hints<let N: u32, let MAX_FIELD: u32, let MAX_TAGS: u32, let MAX_ADDR: u32, let PHRASE_LEN: u32, let VALUE_LEN: u32>(
    header: BoundedVec<u8, N>,
    modulus: [u128; RSA_LIMBS],
    redc: [u128; RSA_LIMBS],
    signature: [u128; RSA_LIMBS],
    phrase: [u8; PHRASE_LEN],
    hints: DkimHeaderHints<MAX_TAGS>,
) -> VerifiedHeader<MAX_ADDR, VALUE_LEN, MAX_FIELD> {
    let layout = scan_header(header);
    let h = header.storage();
    let digest = sha256_var(h, header.len());
    verify_pkcs1v15_sha256(modulus, redc, signature, digest);
    let from = parse_from::<N, MAX_ADDR>(h, layout, hints.from);
    let field = check_dkim_signature::<N, MAX_FIELD, MAX_TAGS, MAX_ADDR>(
        h,
        header.len(),
        layout,
        from,
        hints.tags,
    );
    let subject_value = parse_subject::<N, PHRASE_LEN, VALUE_LEN>(h, layout, phrase);
    VerifiedHeader {
        from_address: from.address,
        domain: field.domain,
        subject_value,
        key_hash: key_hash(modulus),
        signature: field,
    }
}

/// `verify_dkim_header_with_hints` with the hints computed by the prover.
pub fn verify_dkim_header<let N: u32, let MAX_FIELD: u32, let MAX_TAGS: u32, let MAX_ADDR: u32, let PHRASE_LEN: u32, let VALUE_LEN: u32>(
    header: BoundedVec<u8, N>,
    modulus: [u128; RSA_LIMBS],
    redc: [u128; RSA_LIMBS],
    signature: [u128; RSA_LIMBS],
    phrase: [u8; PHRASE_LEN],
) -> VerifiedHeader<MAX_ADDR, VALUE_LEN, MAX_FIELD> {
    // Safety: every hint is checked by verify_dkim_header_with_hints.
    let hints = unsafe { find_hints::<N, MAX_TAGS>(header.storage(), header.len()) };
    verify_dkim_header_with_hints::<N, MAX_FIELD, MAX_TAGS, MAX_ADDR, PHRASE_LEN, VALUE_LEN>(
        header,
        modulus,
        redc,
        signature,
        phrase,
        hints,
    )
}

unconstrained fn starts_with_ci<let N: u32, let L: u32>(
    h: [u8; N],
    at: u32,
    lower: [u8; L],
) -> bool {
    let mut ok = at + L <= N;
    if ok {
        for k in 0..L {
            let c = h[at + k];
            if (c != lower[k]) & (c != lower[k] - 32) {
                ok = false;
            }
        }
    }
    ok
}

unconstrained fn is_h_entry_at<let N: u32, let L: u32>(
    h: [u8; N],
    at: u32,
    end: u32,
    lower: [u8; L],
) -> bool {
    let mut ok = (at >= 1) & (at + L <= end);
    if ok {
        let before = h[at - 1];
        let after = if at + L < N { h[at + L] } else { 0 };
        ok = ((before == 61) | (before == 58) | (before == 32))
            & ((after == 58) | (after == 59) | (after == 32) | (at + L == end))
            & starts_with_ci(h, at, lower);
    }
    ok
}

/// Computes the hints for an honest header. On a malformed header it returns
/// whatever it finds, and the constrained checks then refuse it.
pub unconstrained fn find_hints<let N: u32, let MAX_TAGS: u32>(
    h: [u8; N],
    len: u32,
) -> DkimHeaderHints<MAX_TAGS> {
    // Line starts: the From line and the last line.
    let mut from_start: u32 = 0;
    let mut last_start: u32 = 0;
    for i in 0..len {
        let is_start = if i >= 2 {
            (h[i - 2] == 13) & (h[i - 1] == 10)
        } else {
            i == 0
        };
        if is_start {
            last_start = i;
            if (i + 5 <= len)
                & (h[i] == 102)
                & (h[i + 1] == 114)
                & (h[i + 2] == 111)
                & (h[i + 3] == 109)
                & (h[i + 4] == 58) {
                from_start = i;
            }
        }
    }

    // The From value runs to the CR ending its line.
    let value_start = from_start + 5;
    let mut end = value_start;
    let mut found_end = false;
    for i in value_start..len {
        if !found_end & (h[i] == 13) {
            end = i;
            found_end = true;
        }
    }
    let mut addr_start = value_start;
    let mut addr_end = end;
    if (end > value_start) & (h[end - 1] == 62) {
        addr_end = end - 1;
        for i in value_start..end - 1 {
            if h[i] == 60 {
                addr_start = i + 1;
            }
        }
    }
    let mut at_index: u32 = 0;
    let mut found_at = false;
    for i in addr_start..addr_end {
        if !found_at & (h[i] == 64) {
            at_index = i - addr_start;
            found_at = true;
        }
    }
    let from = FromHints { addr_start, addr_len: addr_end - addr_start, at_index };

    // Tag starts in the DKIM-Signature field (the last line).
    let field_len = len - last_start;
    let mut tag_starts: [u32; MAX_TAGS] = [0; MAX_TAGS];
    let mut tag_count: u32 = 0;
    let mut h_at: u32 = 0;
    let mut h_found = false;
    let mut t_at: u32 = 0;
    let mut t_found = false;
    for k in FIELD_NAME_LEN..field_len {
        let i = last_start + k;
        let c = h[i];
        let after_separator = if k == FIELD_NAME_LEN {
            true
        } else if k == FIELD_NAME_LEN + 1 {
            h[i - 1] == 59
        } else {
            (h[i - 1] == 59) | ((h[i - 1] == 32) & (h[i - 2] == 59))
        };
        if after_separator & (c != 32) & (c != 59) {
            if tag_count < MAX_TAGS {
                tag_starts[tag_count] = k;
            }
            tag_count += 1;
            let next = if i + 1 < N { h[i + 1] } else { 0 };
            if (c == 104) & (next == 61) {
                h_at = k;
                h_found = true;
            }
            if (c == 116) & (next == 61) {
                t_at = k;
                t_found = true;
            }
        }
    }

    // The h= value runs to the next `;` or the end of the field.
    let mut h_from: u32 = 0;
    let mut h_subject: u32 = 0;
    if h_found {
        let value_start = last_start + h_at + 2;
        let mut value_end = len;
        let mut done = false;
        for i in value_start..len {
            if !done & (h[i] == 59) {
                value_end = i;
                done = true;
            }
        }
        for i in value_start..value_end {
            if is_h_entry_at(h, i, value_end, "from".as_bytes()) {
                h_from = i - last_start;
            }
            if is_h_entry_at(h, i, value_end, "subject".as_bytes()) {
                h_subject = i - last_start;
            }
        }
    }

    let mut t_len: u32 = 0;
    if t_found {
        let mut counting = true;
        for i in last_start + t_at + 2..len {
            if counting & (h[i] >= 48) & (h[i] <= 57) {
                t_len += 1;
            } else {
                counting = false;
            }
        }
    }

    DkimHeaderHints { from, tags: DkimTagHints { tag_starts, tag_count, h_from, h_subject, t_len } }
}
