//! A mock of the DKIM key registry's DNS attesters (`docs/email-recovery/spec.md`
//! §7.5). TEST ONLY: no live DNS, and the attester keys are derived from
//! public seeds.
//!
//! A real attester resolves `selector._domainkey.domain` through several
//! resolvers, reads the DKIM key record, and signs what it saw. This mock
//! takes the record's `TXT` strings as input instead of resolving them:
//!
//! - [`parse_txt`] reads a key record in the published format: the strings of
//!   one TXT RR concatenated (RFC 6376 §3.6.2.2), a tag-list (§3.2) with the
//!   key tags of §3.6.1 (`v=DKIM1` first if present, `k=` defaulting to `rsa`,
//!   `p=` the base64 key, empty when the key is revoked, whitespace inside it
//!   ignored, unknown tags ignored, duplicate tags refused). `p=` is accepted
//!   as either encoding found for RSA keys: the DER `RSAPublicKey` that
//!   §3.6.1's text names, and the DER `SubjectPublicKeyInfo` that §3.6.1's
//!   own example procedure (Appendix C, `openssl rsa -pubout`) produces and
//!   that RFC 6376 erratum 6674 reports providers publishing
//!   (<https://www.rfc-editor.org/errata/eid6674>).
//! - [`observe`] decides whether the record publishes a given key (by the
//!   registry's key hash, never by selector), and [`TestAttester::attest`]
//!   encodes that observation in the spec §7.5 byte format and signs it with
//!   Ed25519 (RFC 8032), as `DkimRegistry::attest` verifies.
//!
//! `testdata/records.json` holds key records for throwaway test keys in the
//! shapes RFC 6376 allows (see its README).

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use nido_dkim_registry::attestation;
use nido_dkim_registry::hash::{Hasher, MODULUS_BYTES};
use sha2::{Digest, Sha256};
use soroban_sdk::Env;

/// What a DKIM key record publishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyRecord {
    /// An RSA public key: the modulus and exponent as unsigned big-endian
    /// bytes without leading zeros.
    Rsa { modulus: Vec<u8>, exponent: Vec<u8> },
    /// `p=` is empty: the key has been revoked (RFC 6376 §3.6.1).
    Revoked,
}

/// Why a TXT record is not a usable DKIM key record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordError {
    /// Not a tag-list (RFC 6376 §3.2).
    Syntax,
    /// A tag appears twice, which invalidates the whole tag-list (§3.2).
    DuplicateTag(String),
    /// `v=` is present but not the first tag (§3.6.1).
    VersionNotFirst,
    /// `v=` is not `DKIM1`: the record must be discarded (§3.6.1).
    Version(String),
    /// No `p=` tag (§3.6.1: required).
    MissingKey,
    /// `k=` names a key type other than `rsa`.
    KeyType(String),
    /// `p=` is not base64.
    Base64,
    /// `p=` is neither a DER `SubjectPublicKeyInfo` for `rsaEncryption` nor a
    /// DER `RSAPublicKey`.
    Der,
}

fn is_wsp(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

/// Parse a DKIM key record from the strings of its TXT RR.
///
/// # Errors
/// See [`RecordError`].
pub fn parse_txt(strings: &[&str]) -> Result<KeyRecord, RecordError> {
    let record: String = strings.concat();
    let mut tags: Vec<(String, String)> = Vec::new();
    for spec in record.split(';') {
        if spec.trim_matches(is_wsp).is_empty() {
            // Only the optional trailing ";" leaves an empty tag-spec.
            continue;
        }
        let (name, value) = spec.split_once('=').ok_or(RecordError::Syntax)?;
        let name = name.trim_matches(is_wsp);
        let value = value.trim_matches(is_wsp);
        let mut chars = name.chars();
        let valid_name = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid_name {
            return Err(RecordError::Syntax);
        }
        if tags.iter().any(|(n, _)| n == name) {
            return Err(RecordError::DuplicateTag(name.to_owned()));
        }
        tags.push((name.to_owned(), value.to_owned()));
    }
    let tag = |n: &str| {
        tags.iter()
            .find(|(name, _)| name == n)
            .map(|(_, v)| v.as_str())
    };

    if let Some(v) = tag("v") {
        if tags[0].0 != "v" {
            return Err(RecordError::VersionNotFirst);
        }
        if v != "DKIM1" {
            return Err(RecordError::Version(v.to_owned()));
        }
    }
    let k = tag("k").unwrap_or("rsa");
    if k != "rsa" {
        return Err(RecordError::KeyType(k.to_owned()));
    }
    let p = tag("p").ok_or(RecordError::MissingKey)?;
    let p: String = p.chars().filter(|&c| !is_wsp(c)).collect();
    if p.is_empty() {
        return Ok(KeyRecord::Revoked);
    }
    let der = STANDARD.decode(p).map_err(|_| RecordError::Base64)?;
    let (modulus, exponent) = der::rsa_key(&der).ok_or(RecordError::Der)?;
    Ok(KeyRecord::Rsa { modulus, exponent })
}

/// Just enough DER (ITU-T X.690) for the two RSA public-key encodings.
mod der {
    const SEQUENCE: u8 = 0x30;
    const INTEGER: u8 = 0x02;
    const BIT_STRING: u8 = 0x03;
    const OID: u8 = 0x06;
    const NULL: u8 = 0x05;
    /// 1.2.840.113549.1.1.1, `rsaEncryption` (RFC 8017 Appendix A.1).
    const RSA_ENCRYPTION: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

    /// One definite-length TLV: `(tag, contents, rest)`.
    fn tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
        let (&tag, rest) = input.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = match first {
            0..=0x7f => (usize::from(first), rest),
            0x81 => {
                let (&b, rest) = rest.split_first()?;
                // DER uses the short form below 128.
                (b >= 0x80).then_some((usize::from(b), rest))?
            }
            0x82 => {
                let len = usize::from(*rest.first()?) << 8 | usize::from(*rest.get(1)?);
                (len >= 0x100).then_some((len, &rest[2..]))?
            }
            _ => return None,
        };
        (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
    }

    /// A positive INTEGER's magnitude, without its sign byte.
    fn positive_integer(input: &[u8]) -> Option<(Vec<u8>, &[u8])> {
        let (tag, v, rest) = tlv(input)?;
        if tag != INTEGER || v.is_empty() || v[0] & 0x80 != 0 {
            return None;
        }
        let v = match v {
            [0, next, ..] if *next & 0x80 != 0 => &v[1..],
            [0, _, ..] => return None, // not minimal
            _ => v,
        };
        Some((v.to_vec(), rest))
    }

    /// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
    fn rsa_public_key(input: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let (tag, body, rest) = tlv(input)?;
        if tag != SEQUENCE || !rest.is_empty() {
            return None;
        }
        let (n, body) = positive_integer(body)?;
        let (e, body) = positive_integer(body)?;
        body.is_empty().then_some((n, e))
    }

    /// `SubjectPublicKeyInfo` for `rsaEncryption` (RFC 5280 §4.1, RFC 8017
    /// Appendix A.1), or a bare `RSAPublicKey`.
    pub fn rsa_key(input: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let (tag, body, rest) = tlv(input)?;
        if tag != SEQUENCE || !rest.is_empty() {
            return None;
        }
        if body.first() == Some(&INTEGER) {
            return rsa_public_key(input);
        }
        let (tag, algorithm, body) = tlv(body)?;
        if tag != SEQUENCE {
            return None;
        }
        let (tag, oid, params) = tlv(algorithm)?;
        if tag != OID || oid != RSA_ENCRYPTION || params != [NULL, 0] {
            return None;
        }
        let (tag, bits, body) = tlv(body)?;
        if tag != BIT_STRING || !body.is_empty() || bits.first() != Some(&0) {
            return None;
        }
        rsa_public_key(&bits[1..])
    }
}

/// `key_hash` of a 2048-bit modulus (spec §7.1), through the registry's own
/// [`Hasher`] on the host's Poseidon2.
#[must_use]
pub fn key_hash(modulus: &[u8; MODULUS_BYTES]) -> [u8; 32] {
    let e = Env::default();
    Hasher::new(&e).key_hash(modulus).to_array()
}

/// The 2048-bit modulus of a published RSA key, as 256 bytes.
#[must_use]
pub fn modulus_2048(record: &KeyRecord) -> Option<[u8; MODULUS_BYTES]> {
    match record {
        KeyRecord::Rsa { modulus, .. } if nido_dkim_registry::hash::is_rsa_2048(modulus) => {
            modulus.as_slice().try_into().ok()
        }
        KeyRecord::Rsa { .. } | KeyRecord::Revoked => None,
    }
}

/// One attester's observation of `selector._domainkey.domain`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    pub domain: String,
    pub selector: String,
    pub key_hash: [u8; 32],
    /// The record publishes the key with this hash.
    pub observed_live: bool,
    /// Unix seconds.
    pub observed_at: u64,
    pub resolvers: Vec<String>,
}

/// Observe whether `txt` (the record's strings, or `None` when the name has
/// no TXT record) publishes the RSA-2048 key with `key_hash`. A record that
/// is revoked, malformed, of another key type, or holding another key counts
/// as not publishing it.
#[must_use]
pub fn observe(
    domain: &str,
    selector: &str,
    txt: Option<&[&str]>,
    key_hash_wanted: [u8; 32],
    observed_at: u64,
    resolvers: &[&str],
) -> Observation {
    let live = txt
        .and_then(|strings| parse_txt(strings).ok())
        .and_then(|record| modulus_2048(&record))
        .is_some_and(|n| key_hash(&n) == key_hash_wanted);
    Observation {
        domain: domain.to_owned(),
        selector: selector.to_owned(),
        key_hash: key_hash_wanted,
        observed_live: live,
        observed_at,
        resolvers: resolvers.iter().map(|r| (*r).to_owned()).collect(),
    }
}

/// The spec §7.5 encoding of `obs` for the registry with contract id
/// `registry` (the registry crate's own encoder).
///
/// # Panics
/// If a field is out of the format's bounds.
#[must_use]
pub fn encode(registry: &[u8; 32], obs: &Observation) -> Vec<u8> {
    let resolvers: Vec<&[u8]> = obs.resolvers.iter().map(String::as_bytes).collect();
    let a = attestation::Attestation::new(
        *registry,
        obs.domain.as_bytes(),
        obs.selector.as_bytes(),
        obs.key_hash,
        obs.observed_live,
        obs.observed_at,
        &resolvers,
    )
    .expect("at most four resolvers");
    let mut buf = [0u8; attestation::MAX_LEN];
    let len = attestation::encode(&a, &mut buf).expect("fields within the format");
    buf[..len].to_vec()
}

/// A signed attestation, as `DkimRegistry::attest` takes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAttestation {
    pub attester: [u8; 32],
    pub bytes: Vec<u8>,
    pub signature: [u8; 64],
}

/// TEST ONLY: an attester whose Ed25519 key is
/// `sha256("nido/email-recovery/test-only-attester" || index)`.
pub struct TestAttester {
    key: SigningKey,
}

impl TestAttester {
    #[must_use]
    pub fn new(index: u8) -> Self {
        let mut h = Sha256::new();
        h.update(b"nido/email-recovery/test-only-attester");
        h.update([index]);
        Self {
            key: SigningKey::from_bytes(&h.finalize().into()),
        }
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// Sign `bytes` as they are (for tests of malformed attestations).
    #[must_use]
    pub fn sign_bytes(&self, bytes: Vec<u8>) -> SignedAttestation {
        let signature = self.key.sign(&bytes).to_bytes();
        SignedAttestation {
            attester: self.public_key(),
            bytes,
            signature,
        }
    }

    /// Encode `obs` for `registry` and sign it.
    #[must_use]
    pub fn attest(&self, registry: &[u8; 32], obs: &Observation) -> SignedAttestation {
        self.sign_bytes(encode(registry, obs))
    }
}

/// One record of `testdata/records.json`.
#[derive(Clone, Debug, serde::Deserialize)]
pub struct FixtureRecord {
    pub name: String,
    pub domain: String,
    pub selector: String,
    pub note: String,
    pub strings: Vec<String>,
}

impl FixtureRecord {
    #[must_use]
    pub fn strings(&self) -> Vec<&str> {
        self.strings.iter().map(String::as_str).collect()
    }

    /// # Errors
    /// See [`RecordError`].
    pub fn parse(&self) -> Result<KeyRecord, RecordError> {
        parse_txt(&self.strings())
    }
}

/// The key records in `testdata/records.json`.
///
/// # Panics
/// If the committed fixture file does not parse.
#[must_use]
pub fn fixtures() -> Vec<FixtureRecord> {
    #[derive(serde::Deserialize)]
    struct File {
        records: Vec<FixtureRecord>,
    }
    let file: File = serde_json::from_str(include_str!("../testdata/records.json")).unwrap();
    file.records
}

/// The fixture named `name`.
///
/// # Panics
/// If there is none.
#[must_use]
pub fn fixture(name: &str) -> FixtureRecord {
    fixtures()
        .into_iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no fixture {name}"))
}

/// The 32-byte contract id of a contract strkey (`C...`).
///
/// # Panics
/// If `strkey` is not a contract address.
#[must_use]
pub fn contract_id_of(strkey: &str) -> [u8; 32] {
    let e = Env::default();
    let address = soroban_sdk::Address::from_str(&e, strkey);
    perch_zk_primitives::contract_id(&e, &address)
        .expect("a contract address")
        .to_array()
}

#[cfg(test)]
mod test;
