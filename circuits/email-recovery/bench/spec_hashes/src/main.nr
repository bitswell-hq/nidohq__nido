//! Every P2 hash the recovery circuit computes (spec sections 4.2, 5.3, 7.1
//! and 7.2): the address commitment over a 124-byte address, the key hash,
//! the registry leaf and its depth-16 Merkle root, and the Subject opening.
use email_recovery::pack::{address_commitment, key_hash};
use email_recovery::registry::{merkle_root, registry_leaf};
use email_recovery::subject::assert_subject_opens;

fn main(
    address: BoundedVec<u8, 124>,
    account_code: Field,
    modulus: [u128; 18],
    domain: BoundedVec<u8, 62>,
    index: Field,
    siblings: [Field; 16],
    digest_hi: pub Field,
    digest_lo: pub Field,
    rho: Field,
    value: [u8; 64],
) -> pub (Field, Field) {
    assert_subject_opens(value, digest_hi, digest_lo, rho);
    let leaf = registry_leaf(domain, key_hash(modulus));
    (address_commitment(address, account_code), merkle_root(leaf, index, siblings))
}
