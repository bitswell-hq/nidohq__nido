//! TEST-ONLY. The recovery circuit's header checks without the recovery
//! Subject's value, for running real mail and fuzzed headers through the
//! circuit's own parsing (`research/email-recovery/eval/parser/README.md`).
//!
//! This is `email_recovery::dkim::verify_dkim_header` at the recovery
//! circuit's bounds (`HEADER_MAX`, `DKIM_FIELD_MAX`, `DKIM_TAGS_MAX`,
//! `ADDR_MAX`) with one call removed: `subject::parse_subject`, which
//! requires the Subject value to be the recovery phrase followed by 64
//! lowercase hex characters. Every other check runs unchanged, from the
//! library the recovery circuit is built from: the header scan (including
//! exactly one `from:` and one `subject:` line), SHA-256 and RSA-2048, the
//! From grammar, and the DKIM-Signature tags with `d=` equal to the From
//! domain. The commitment, the Subject opening and the key-tree membership
//! are left out because they bind values a real message does not carry.
//!
//! Instead of binding them, it returns what the recovery circuit would bind:
//! the From address, the lowercase `d=` domain and the key hash, and the
//! hints the checks ran on.
//!
//! The hints are unconstrained: in a proof the prover chooses them. With
//! `hint_override` false the harness computes them with `find_hints`, as the
//! recovery circuit's honest prover does; with it true it runs the checks on
//! `given_hints` instead, so a caller can try positions an honest prover would
//! not choose (`fuzz.mjs --mutate-hints`).
use email_recovery::dkim::{DkimHeaderHints, find_hints};
use email_recovery::dkim_signature::check_dkim_signature;
use email_recovery::from_address::parse_from;
use email_recovery::header::scan_header;
use email_recovery::pack::key_hash;
use email_recovery::rsa::verify_pkcs1v15_sha256;
use email_recovery::spec::{ADDR_MAX, DKIM_FIELD_MAX, DKIM_TAGS_MAX, DOMAIN_MAX, HEADER_MAX};
use sha256::sha256_var;

fn main(
    header: BoundedVec<u8, HEADER_MAX>,
    modulus: [u128; 18],
    redc: [u128; 18],
    signature: [u128; 18],
    hint_override: bool,
    given_hints: DkimHeaderHints<DKIM_TAGS_MAX>,
) -> pub (BoundedVec<u8, ADDR_MAX>, BoundedVec<u8, DOMAIN_MAX>, Field, DkimHeaderHints<DKIM_TAGS_MAX>) {
    // Safety: every hint is checked by the calls below, as in
    // verify_dkim_header_with_hints.
    let found = unsafe { find_hints::<HEADER_MAX, DKIM_TAGS_MAX>(header.storage(), header.len()) };
    let hints = if hint_override { given_hints } else { found };
    let layout = scan_header(header);
    let h = header.storage();
    let digest = sha256_var(h, header.len());
    verify_pkcs1v15_sha256(modulus, redc, signature, digest);
    let from = parse_from::<HEADER_MAX, ADDR_MAX>(h, layout, hints.from);
    let field = check_dkim_signature::<HEADER_MAX, DKIM_FIELD_MAX, DKIM_TAGS_MAX, ADDR_MAX>(
        h,
        header.len(),
        layout,
        from,
        hints.tags,
    );
    (from.address, field.domain, key_hash(modulus), hints)
}
