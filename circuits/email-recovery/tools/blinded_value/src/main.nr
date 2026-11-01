//! `T = P2(DOM_BLIND, digest_hi, digest_lo, rho)` for the test-vector
//! generator, which signs a Subject carrying `hex(T)`.
use email_recovery::subject::blinded_value;

fn main(digest_hi: Field, digest_lo: Field, rho: Field) -> pub Field {
    blinded_value(digest_hi, digest_lo, rho)
}
