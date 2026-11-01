//! RSA-2048 PKCS#1 v1.5 / SHA-256 verification of a given digest.
use email_recovery::rsa::verify_pkcs1v15_sha256;

fn main(modulus: [u128; 18], redc: [u128; 18], signature: [u128; 18], digest: pub [u8; 32]) {
    verify_pkcs1v15_sha256(modulus, redc, signature, digest);
}
