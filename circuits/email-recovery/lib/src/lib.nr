//! Hardened DKIM email components for proving, in zero knowledge, that a
//! mail provider signed a recovery email.
//!
//! Each module checks one part of the email and states its grammar in its
//! own header:
//!
//! - `rsa`: RSA-2048 PKCS#1 v1.5 / SHA-256 verification, signature strictly
//!   below the modulus, full encoding check, 2048-bit moduli only;
//! - `header`: the structure of the signed header block (zero padding past
//!   the signed length, strict CRLF, no folding, unique From and Subject);
//! - `from_address`: the From field and the exact address it names;
//! - `dkim_signature`: the tags of the DKIM-Signature field being verified;
//! - `subject`: a Subject of a fixed phrase and a fixed-length hex value;
//! - `body`: `bh=` against the SHA-256 of a bounded canonicalized body;
//! - `pack`: bytes and keys to BN254 field elements with Poseidon2: the
//!   address commitment and the key hash;
//! - `registry`: the DKIM key registry's leaf and Merkle root;
//! - `dkim`: the header-only composition of all of the above;
//! - `recovery`: the recovery relation, spec obligations C1 to C6;
//! - `spec`: the constants `docs/email-recovery/spec.md` fixes.
//!
//! Every function takes the canonicalized bytes the signature covers; the
//! circuit never canonicalizes. Prover-supplied positions ("hints") are
//! inputs to the constrained checks, never trusted.

pub mod spec;
pub mod tables;
pub mod rsa;
pub mod header;
pub mod from_address;
pub mod dkim_signature;
pub mod subject;
pub mod body;
pub mod pack;
pub mod registry;
pub mod dkim;
pub mod recovery;
