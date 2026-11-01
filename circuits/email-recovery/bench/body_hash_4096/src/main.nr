//! bh= against the SHA-256 of a body of at most 4096 bytes.
use email_recovery::body::verify_body_hash;

fn main(body: BoundedVec<u8, 4096>, body_hash_b64: pub [u8; 44]) {
    verify_body_hash(body, body_hash_b64);
}
