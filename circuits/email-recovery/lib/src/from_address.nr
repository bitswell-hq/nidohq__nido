//! The From field and the address it names (spec section 4.5).
//!
//! After relaxed canonicalization the field is one line, `from:<value>\r\n`,
//! with no whitespace after the colon and none at the end. The value has one
//! of two forms:
//!
//! ```text
//! from-value    = addr-spec
//!               / display-name "<" addr-spec ">"     ; ">" is the last byte
//! display-name  = *( atext / "." / SP / quoted-string )
//! quoted-string = DQUOTE *( qtext / SP / quoted-pair ) DQUOTE
//! qtext         = %x21 / %x23-3B / %x3D / %x3F-5B / %x5D-7E
//!                                                    ; printable except SP " < > \
//! quoted-pair   = "\" ( %x20-3B / %x3D / %x3F-7E )  ; printable except < >
//! addr-spec     = local-part "@" domain
//! local-part    = atom *( "." atom )                 ; RFC 5322 dot-atom, no quoting
//! domain        = label 1*( "." label )
//! label         = 1 to 63 of ALPHA / DIGIT / "-", starting and ending
//!                 with ALPHA or DIGIT                ; RFC 1123 section 2.1
//! ```
//!
//! The display name is RFC 5322's phrase without comments or folding: words
//! of `atext` (RFC 2047 encoded-words among them), quoted strings, and the
//! `.` of the obsolete phrase syntax, separated by SP. Outside a quoted
//! string it holds none of `( ) , : ; @ \ [ ]` and every quoted string is
//! closed, so an RFC 5322 reader finds no address list, group, comment or
//! second mailbox in it. The scan's display-name automaton (`tables`,
//! `PHRASE_NEXT`) checks this byte by byte: the `<` that opens the angle-addr
//! is the first `<` outside a quoted string, and nothing before it breaks the
//! grammar. So the value holds
//! exactly one `<` and one `>`, the `>` is its last byte, and the address is
//! the bytes between them; or it holds neither and the whole value is the
//! address. A display name, however long or address-like, cannot become the
//! address, and the address is the one mailbox an RFC 5322 reader reads.
//! Quoted local parts, comments, groups and address lists are refused. The
//! address is at most `MAX_ADDR` bytes (the spec's `ADDR_MAX` is 124) and is
//! returned exactly as signed, without case folding or dot or plus-tag
//! normalization.

use crate::header::{FROM_NAME_LEN, HeaderLayout};
use crate::tables::{CR, DOMAIN, LOCAL_PART, read_if};

pub global MAX_LABEL_LEN: u8 = 63;

/// Prover-supplied positions, all checked by `parse_from`.
pub struct FromHints {
    /// Index in the header of the address's first byte.
    pub addr_start: u32,
    /// Address length in bytes.
    pub addr_len: u32,
    /// Index of the `@` within the address.
    pub at_index: u32,
}

pub struct FromAddress<let MAX_ADDR: u32> {
    pub address: BoundedVec<u8, MAX_ADDR>,
    /// Index of the `@` within `address`.
    pub at_index: u32,
}

impl<let MAX_ADDR: u32> FromAddress<MAX_ADDR> {
    /// Length of the domain, the bytes after the `@`.
    pub fn domain_len(self) -> u32 {
        self.address.len() - self.at_index - 1
    }
}

pub fn parse_from<let N: u32, let MAX_ADDR: u32>(
    h: [u8; N],
    layout: HeaderLayout<N>,
    hints: FromHints,
) -> FromAddress<MAX_ADDR> {
    let s = layout.from_start;
    let value_start = s + FROM_NAME_LEN;
    let a = hints.addr_start;
    let n = hints.addr_len;
    assert((n >= 1) & (n <= MAX_ADDR), "From: address length out of bounds");
    assert(a >= value_start, "From: address starts before the field value");
    assert(a + n + 1 < N, "From: address runs past the header bound");

    // The field ends right after the address, or after the `>` closing it.
    let closing = h[a + n] == 62;
    let end = a + n + closing as u32;
    assert(h[end] == CR, "From: the address must end the field");
    assert(layout.line_of[s] == layout.line_of[end], "From: field value spans more than one line");
    let opening = h[a - 1] == 60;
    assert(opening == closing, "From: unbalanced angle-addr");
    assert(closing | (a == value_start), "From: a bare address must be the whole field value");
    // In value_start..a: the display name and the `<` that opens the
    // angle-addr, or nothing for a bare address. The line is in the
    // automaton's start state at value_start (`from:` leaves it there), so no
    // fault means the display name is a phrase that ends outside a quoted
    // string and holds no `<` or `>`. The address grammar below admits no
    // `<`, `>` or unprintable byte, so the field holds exactly one
    // angle-addr or none.
    let faults = layout.phrase_faults_upto[a - 1] - layout.phrase_faults_upto[value_start - 1];
    assert(faults == 0, "From: invalid display name");

    let mut addr: [u8; MAX_ADDR] = [0; MAX_ADDR];
    for k in 0..MAX_ADDR {
        addr[k] = read_if(h, a + k, k < n);
    }

    let at = hints.at_index;
    assert(at >= 1, "From: empty local part");
    assert(at + 4 <= n, "From: domain too short");
    assert(addr[0] != 46, "From: local part starts with a dot");
    assert(addr[at - 1] != 46, "From: local part ends with a dot");
    assert(addr[at + 1] != 46, "From: domain starts with a dot");
    assert(addr[n - 1] != 46, "From: domain ends with a dot");

    let mut is_dot: [bool; MAX_ADDR] = [false; MAX_ADDR];
    for k in 0..MAX_ADDR {
        is_dot[k] = addr[k] == 46;
    }
    let mut domain_dots: Field = 0;
    let mut label_len: u8 = 0;
    for k in 0..MAX_ADDR {
        let c = addr[k];
        let in_local = k < at;
        let is_at = k == at;
        let in_domain = (k > at) & (k < n);
        assert(
            in_local as Field * (1 - LOCAL_PART[c as u32]) == 0,
            "From: invalid character in the local part",
        );
        assert(!is_at | (c == 64), "From: '@' expected");
        assert(
            in_domain as Field * (1 - DOMAIN[c as u32]) == 0,
            "From: invalid character in the domain",
        );
        if k > 0 {
            assert(!(is_dot[k] & is_dot[k - 1]), "From: consecutive dots");
        }

        // A label starts after the `@` or a dot and ends before a dot or the
        // end of the address; its first and last bytes are letters or digits.
        let label_byte = in_domain & !is_dot[k];
        let starts = if k > 0 {
            is_dot[k - 1] | (k == at + 1)
        } else {
            false
        };
        let ends = if k + 1 < MAX_ADDR {
            is_dot[k + 1] | (k + 1 == n)
        } else {
            true
        };
        assert(
            !(label_byte & (starts | ends) & (c == 45)),
            "From: domain label starts or ends with a hyphen",
        );
        label_len = if label_byte { label_len + 1 } else { 0 };
        assert(label_len <= MAX_LABEL_LEN, "From: domain label longer than 63 characters");
        domain_dots += (in_domain & is_dot[k]) as Field;
        std::as_witness(domain_dots);
    }
    assert(domain_dots != 0, "From: domain needs at least two labels");

    FromAddress { address: BoundedVec::from_parts_unchecked(addr, n), at_index: at }
}
