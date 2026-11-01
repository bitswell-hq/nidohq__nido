//! The body hash component.

use crate::common::{body, header, verify};
use crate::vectors::{BODY, BODY_HASH_B64, GMAIL_HEADER, GMAIL_SIG};
use email_recovery::body::{verify_body, verify_body_hash};

#[test]
fn body_matches_bh() {
    verify_body_hash(body(BODY.as_bytes()), BODY_HASH_B64.as_bytes());
}

/// The body named by the verified DKIM-Signature field.
#[test]
fn body_matches_the_signed_bh() {
    let out = verify(header(GMAIL_HEADER.as_bytes()), GMAIL_SIG);
    verify_body(out.signature, body(BODY.as_bytes()));
}

#[test]
fn empty_body_matches_the_empty_hash() {
    verify_body_hash(
        body([]),
        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=".as_bytes(),
    );
}

#[test(should_fail_with = "Body: bh= does not match the body")]
fn changed_body_is_refused() {
    let mut bytes = BODY.as_bytes();
    bytes[0] = 114; // 'r'
    let out = verify(header(GMAIL_HEADER.as_bytes()), GMAIL_SIG);
    verify_body(out.signature, body(bytes));
}

#[test(should_fail_with = "Body: bh= does not match the body")]
fn truncated_body_is_refused() {
    let bytes = BODY.as_bytes();
    let mut v = body(bytes);
    // Drop the trailing CRLF.
    let mut storage = v.storage();
    storage[bytes.len() - 1] = 0;
    storage[bytes.len() - 2] = 0;
    v = BoundedVec::from_parts_unchecked(storage, bytes.len() - 2);
    verify_body_hash(v, BODY_HASH_B64.as_bytes());
}

/// Content appended past the body length (what an `l=` limit would allow).
#[test(should_fail_with = "Body: bytes past the body length must be zero")]
fn bytes_past_the_body_length_are_refused() {
    let bytes = BODY.as_bytes();
    let mut storage = body(bytes).storage();
    storage[bytes.len()] = 65;
    verify_body_hash(
        BoundedVec::from_parts_unchecked(storage, bytes.len()),
        BODY_HASH_B64.as_bytes(),
    );
}
