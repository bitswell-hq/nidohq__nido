//! Tests of the email-recovery components, against DKIM-signed headers from
//! `scripts/gen-test-vectors.mjs`.

pub(crate) mod vectors;
pub(crate) mod common;
mod smoke;
mod honest;
mod soundness;
mod rsa_tests;
mod body_tests;
mod pack_tests;
mod registry_parity;
mod subject_tests;
mod structure_tests;
