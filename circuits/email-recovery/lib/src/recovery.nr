//! The recovery relation (spec section 6): obligations C1 to C6 over one
//! DKIM-signed recovery email.
//!
//! Public, in this order: the address commitment `C`, the statement digest's
//! limbs `digest_hi` and `digest_lo`, and the key-tree root `key_root`.
//! Private: the signed header block `H` (at most `N` bytes; the circuit uses
//! the spec's `HEADER_MAX`), the RSA modulus (with the Barrett
//! hint `redc`), the signature, `rho`, `account_code`, and the key's leaf
//! index and Merkle siblings. Positions inside `H` are prover hints computed
//! and checked by `dkim::verify_dkim_header`.
//!
//! An accepted call proves:
//!
//! - C1, C2: `H` is a relaxed-canonical signed header block whose last field
//!   is the DKIM-Signature being verified (`v=1`, `a=rsa-sha256`, relaxed
//!   header canonicalization, `h=` with `from` and `subject`, empty `b=`),
//!   and the signature is a valid RSA-2048 PKCS#1 v1.5 SHA-256 signature of
//!   `H` under the modulus, strictly below it;
//! - C3: `H` has exactly one `from` field, its address parses under spec
//!   section 4.5, and `C = P2(DOM_COMMIT, len, pack(address, 124),
//!   account_code)`;
//! - C4: the leaf domain is the lowercase `d=` value, which equals the
//!   lowercase domain of that address;
//! - C5: `H` has exactly one `subject` field, exactly `RECOVERY_PHRASE`
//!   followed by `hex(P2(DOM_BLIND, digest_hi, digest_lo, rho))`;
//! - C6: `leaf = P2(DOM_LEAF, len(domain), pack(domain, 62),
//!   P2(DOM_KEY, limbs(n)))` sits at `key_index` (below 2^16) of a depth-16
//!   tree whose root is `key_root`.

use crate::dkim::verify_dkim_header;
use crate::pack::address_commitment;
use crate::registry::{merkle_root, registry_leaf};
use crate::rsa::RSA_LIMBS;
use crate::spec::{
    ADDR_MAX, DKIM_FIELD_MAX, DKIM_TAGS_MAX, HEX_FIELD_LEN, RECOVERY_PHRASE, RECOVERY_PHRASE_LEN,
    REGISTRY_DEPTH,
};
use crate::subject::assert_subject_opens;

pub fn verify_recovery_email<let N: u32>(
    commitment: Field,
    digest_hi: Field,
    digest_lo: Field,
    key_root: Field,
    header: BoundedVec<u8, N>,
    modulus: [u128; RSA_LIMBS],
    redc: [u128; RSA_LIMBS],
    signature: [u128; RSA_LIMBS],
    rho: Field,
    account_code: Field,
    key_index: Field,
    key_siblings: [Field; REGISTRY_DEPTH],
) {
    // C1, C2, the header parts of C3 to C5, and the key hash of C6.
    let out = verify_dkim_header::<N, DKIM_FIELD_MAX, DKIM_TAGS_MAX, ADDR_MAX, RECOVERY_PHRASE_LEN, HEX_FIELD_LEN>(
        header,
        modulus,
        redc,
        signature,
        RECOVERY_PHRASE.as_bytes(),
    );
    assert(
        address_commitment(out.from_address, account_code) == commitment,
        "recovery: the From address does not open the commitment",
    );
    assert_subject_opens(out.subject_value, digest_hi, digest_lo, rho);
    let leaf = registry_leaf(out.domain, out.key_hash);
    assert(
        merkle_root(leaf, key_index, key_siblings) == key_root,
        "recovery: the signing key is not in the key tree",
    );
}
