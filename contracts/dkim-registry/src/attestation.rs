//! The DNS attestation byte format (spec §7.5).
//!
//! ```text
//! offset  len  field
//!      0   38  TAG = "nido/email-recovery/v1/dns-attestation"
//!     38   32  registry: the registry's contract id
//!     70    1  domain length, 1..62
//!     71   62  domain, lowercase ASCII, zero-padded
//!    133    1  selector length, 1..63
//!    134   63  selector, zero-padded
//!    197   32  key_hash (spec §7.1)
//!    229    1  observed_live: 1 = published with this key, 0 = absent or p= empty
//!    230    8  observed_at: Unix seconds, big-endian
//!    238    1  resolver count, 1..4
//!    239  ...  per resolver: length (1 byte, 1..64) || identifier (printable ASCII)
//! ```
//!
//! Every byte is determined by the fields: padding must be zero and the
//! length must be exact, so each observation has one encoding. The attester
//! signs these bytes with Ed25519 (RFC 8032), which the registry checks with
//! the host's `ed25519_verify`.

/// The format's domain-separation prefix.
pub const TAG: &[u8; 38] = b"nido/email-recovery/v1/dns-attestation";
/// Longest selector.
pub const SELECTOR_MAX: usize = 63;
/// Most resolver identifiers, and the longest one.
pub const MAX_RESOLVERS: usize = 4;
pub const RESOLVER_MAX: usize = 64;
/// Length of everything before the resolver identifiers.
pub const FIXED_LEN: usize = 239;
/// Longest attestation.
pub const MAX_LEN: usize = FIXED_LEN + MAX_RESOLVERS * (1 + RESOLVER_MAX);

const REGISTRY_AT: usize = 38;
const DOMAIN_AT: usize = 70;
const SELECTOR_AT: usize = 133;
const KEY_HASH_AT: usize = 197;
const LIVE_AT: usize = 229;
const OBSERVED_AT: usize = 230;
const RESOLVER_COUNT_AT: usize = 238;

/// A parsed attestation, borrowing from the bytes it was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attestation<'a> {
    pub registry: [u8; 32],
    pub domain: &'a [u8],
    pub selector: &'a [u8],
    pub key_hash: [u8; 32],
    pub observed_live: bool,
    pub observed_at: u64,
    resolvers: [&'a [u8]; MAX_RESOLVERS],
    resolver_count: usize,
}

impl<'a> Attestation<'a> {
    /// The resolver identifiers, in order.
    #[must_use]
    pub fn resolvers(&self) -> &[&'a [u8]] {
        &self.resolvers[..self.resolver_count]
    }
}

/// A domain as leaves name it: 1 to 62 bytes of lowercase LDH labels, at
/// least two, each 1 to 63 bytes, none starting or ending with `-` (the
/// `domain` rule of spec §4.5, lowercase).
#[must_use]
pub fn is_domain(domain: &[u8]) -> bool {
    if domain.is_empty() || domain.len() > crate::hash::DOMAIN_MAX {
        return false;
    }
    let mut labels = 0;
    for label in domain.split(|&c| c == b'.') {
        let ldh = label
            .iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-');
        if label.is_empty()
            || label.len() > 63
            || !ldh
            || label[0] == b'-'
            || label[label.len() - 1] == b'-'
        {
            return false;
        }
        labels += 1;
    }
    labels >= 2
}

/// A DKIM selector (RFC 6376 §3.1, `selector = sub-domain *( "." sub-domain )`)
/// written in lowercase: 1 to 63 bytes of lowercase letters, digits, `-`,
/// `_`, and `.`.
#[must_use]
pub fn is_selector(selector: &[u8]) -> bool {
    !selector.is_empty()
        && selector.len() <= SELECTOR_MAX
        && selector.iter().all(|&c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_' | b'.')
        })
}

fn padded_field(bytes: &[u8], len_at: usize, max: usize) -> Option<&[u8]> {
    let len = usize::from(bytes[len_at]);
    if len == 0 || len > max {
        return None;
    }
    let field = &bytes[len_at + 1..len_at + 1 + max];
    if field[len..].iter().any(|&b| b != 0) {
        return None;
    }
    Some(&field[..len])
}

fn array32(bytes: &[u8], at: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[at..at + 32]);
    out
}

fn put_padded(out: &mut [u8], at: usize, field: &[u8], max: usize) -> Option<()> {
    if field.is_empty() || field.len() > max {
        return None;
    }
    out[at] = u8::try_from(field.len()).ok()?;
    out[at + 1..at + 1 + field.len()].copy_from_slice(field);
    Some(())
}

/// Encode `a` into `out`; returns the encoding's length, or `None` if a field
/// is outside the format (the same bounds [`parse`] enforces).
#[must_use]
pub fn encode(a: &Attestation<'_>, out: &mut [u8; MAX_LEN]) -> Option<usize> {
    *out = [0u8; MAX_LEN];
    out[..REGISTRY_AT].copy_from_slice(TAG);
    out[REGISTRY_AT..DOMAIN_AT].copy_from_slice(&a.registry);
    put_padded(out, DOMAIN_AT, a.domain, crate::hash::DOMAIN_MAX)?;
    put_padded(out, SELECTOR_AT, a.selector, SELECTOR_MAX)?;
    out[KEY_HASH_AT..LIVE_AT].copy_from_slice(&a.key_hash);
    out[LIVE_AT] = u8::from(a.observed_live);
    out[OBSERVED_AT..RESOLVER_COUNT_AT].copy_from_slice(&a.observed_at.to_be_bytes());
    out[RESOLVER_COUNT_AT] = u8::try_from(a.resolver_count).ok()?;
    let mut pos = FIXED_LEN;
    for r in a.resolvers() {
        if r.is_empty() || r.len() > RESOLVER_MAX {
            return None;
        }
        out[pos] = u8::try_from(r.len()).ok()?;
        out[pos + 1..pos + 1 + r.len()].copy_from_slice(r);
        pos += 1 + r.len();
    }
    parse(&out[..pos]).map(|_| pos)
}

impl<'a> Attestation<'a> {
    /// An attestation with these fields, for [`encode`]; `None` with more
    /// than [`MAX_RESOLVERS`] resolvers.
    #[must_use]
    pub fn new(
        registry: [u8; 32],
        domain: &'a [u8],
        selector: &'a [u8],
        key_hash: [u8; 32],
        observed_live: bool,
        observed_at: u64,
        resolvers: &[&'a [u8]],
    ) -> Option<Self> {
        let count = resolvers.len();
        if count > MAX_RESOLVERS {
            return None;
        }
        let mut slots: [&[u8]; MAX_RESOLVERS] = [&[]; MAX_RESOLVERS];
        slots[..count].copy_from_slice(resolvers);
        Some(Self {
            registry,
            domain,
            selector,
            key_hash,
            observed_live,
            observed_at,
            resolvers: slots,
            resolver_count: count,
        })
    }
}

/// Parse an attestation, refusing any byte string that is not exactly one
/// well-formed encoding.
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<Attestation<'_>> {
    if bytes.len() < FIXED_LEN || bytes.len() > MAX_LEN || &bytes[..REGISTRY_AT] != TAG {
        return None;
    }
    let domain = padded_field(bytes, DOMAIN_AT, crate::hash::DOMAIN_MAX)?;
    let selector = padded_field(bytes, SELECTOR_AT, SELECTOR_MAX)?;
    if !is_domain(domain) || !is_selector(selector) {
        return None;
    }
    let observed_live = match bytes[LIVE_AT] {
        0 => false,
        1 => true,
        _ => return None,
    };
    let mut at = [0u8; 8];
    at.copy_from_slice(&bytes[OBSERVED_AT..OBSERVED_AT + 8]);

    let resolver_count = usize::from(bytes[RESOLVER_COUNT_AT]);
    if resolver_count == 0 || resolver_count > MAX_RESOLVERS {
        return None;
    }
    let mut resolvers: [&[u8]; MAX_RESOLVERS] = [&[]; MAX_RESOLVERS];
    let mut pos = FIXED_LEN;
    for slot in resolvers.iter_mut().take(resolver_count) {
        let len = usize::from(*bytes.get(pos)?);
        let id = bytes.get(pos + 1..pos + 1 + len)?;
        if len == 0 || len > RESOLVER_MAX || !id.iter().all(|c| (0x21..=0x7e).contains(c)) {
            return None;
        }
        *slot = id;
        pos += 1 + len;
    }
    if pos != bytes.len() {
        return None;
    }

    Some(Attestation {
        registry: array32(bytes, REGISTRY_AT),
        domain,
        selector,
        key_hash: array32(bytes, KEY_HASH_AT),
        observed_live,
        observed_at: u64::from_be_bytes(at),
        resolvers,
        resolver_count,
    })
}
