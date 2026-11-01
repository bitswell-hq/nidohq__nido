//! The recovery circuit with a 1024-byte header bound instead of the spec's
//! `HEADER_MAX`, for comparison: the same relation and public inputs.
use email_recovery::recovery::verify_recovery_email;
use email_recovery::spec::REGISTRY_DEPTH;

fn main(
    commitment: pub Field,
    digest_hi: pub Field,
    digest_lo: pub Field,
    key_root: pub Field,
    header: BoundedVec<u8, 1024>,
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
