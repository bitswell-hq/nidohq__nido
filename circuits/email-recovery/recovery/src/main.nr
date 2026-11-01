//! The email-recovery circuit (`docs/email-recovery/spec.md` section 6).
//!
//! Its four public inputs, in this order, are the ones the email guardian
//! builds and hands to the verifier as 128 bytes: the address commitment
//! `C`, the statement digest's limbs `digest_hi` and `digest_lo`, and the
//! key-tree root `key_root`. `email_recovery::recovery` states what an
//! accepted proof shows.
use email_recovery::recovery::verify_recovery_email;
use email_recovery::spec::{HEADER_MAX, REGISTRY_DEPTH};

fn main(
    commitment: pub Field,
    digest_hi: pub Field,
    digest_lo: pub Field,
    key_root: pub Field,
    header: BoundedVec<u8, HEADER_MAX>,
    modulus: [u128; 18],
    redc: [u128; 18],
    signature: [u128; 18],
    rho: Field,
    account_code: Field,
    key_index: Field,
    key_siblings: [Field; REGISTRY_DEPTH],
) {
    verify_recovery_email(
        commitment,
        digest_hi,
        digest_lo,
        key_root,
        header,
        modulus,
        redc,
        signature,
        rho,
        account_code,
        key_index,
        key_siblings,
    );
}
