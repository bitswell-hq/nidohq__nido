//! The verifier against the committed real proofs of the email circuit
//! (`crates/integration-tests/fixtures/email/`, `just gen-email-proofs`).

extern crate std;

use crate::{EmailVerifier, EmailVerifierClient, PROOF_BYTES, PUBLIC_INPUTS_BYTES, VERSION};
use perch_recovery_interface::zk::ProofVerifierError;
use sha2::{Digest, Sha256};
use soroban_sdk::{Bytes, Env};
use std::path::PathBuf;
use std::vec::Vec;

fn repo(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(rel)
}

fn read(rel: &str) -> Vec<u8> {
    std::fs::read(repo(rel)).unwrap_or_else(|e| panic!("{rel}: {e} (run `just gen-email-proofs`)"))
}

/// Every committed provider fixture: its proof and the public inputs bb
/// committed to.
fn fixtures() -> Vec<(std::string::String, Vec<u8>, Vec<u8>)> {
    let dir = repo("crates/integration-tests/fixtures/email");
    let mut out: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let name = e.unwrap().file_name().into_string().unwrap();
            name.starts_with("provider-").then_some(name)
        })
        .map(|name| {
            let proof = read(&std::format!(
                "crates/integration-tests/fixtures/email/{name}/proof"
            ));
            let inputs = read(&std::format!(
                "crates/integration-tests/fixtures/email/{name}/public_inputs"
            ));
            (name, proof, inputs)
        })
        .collect();
    out.sort();
    assert_eq!(out.len(), 11, "one fixture per launch domain");
    out
}

fn setup() -> (Env, EmailVerifierClient<'static>) {
    let e = Env::default();
    e.cost_estimate().budget().reset_unlimited();
    let id = e.register(EmailVerifier, ());
    let c = EmailVerifierClient::new(&e, &id);
    (e, c)
}

#[test]
fn identity() {
    let (e, c) = setup();
    let vk = read("contracts/email-verifier/vk/email_recovery.vk");
    assert_eq!(vk.len(), 1760);
    assert_eq!(c.vk(), Bytes::from_slice(&e, &vk));
    let id: [u8; 32] = Sha256::digest(&vk).into();
    assert_eq!(c.circuit_id().to_array(), id);
    assert_eq!(c.version(), VERSION);
}

#[test]
fn every_committed_proof_verifies() {
    let (e, c) = setup();
    for (name, proof, inputs) in fixtures() {
        assert_eq!(proof.len(), PROOF_BYTES as usize, "{name}");
        assert_eq!(inputs.len(), PUBLIC_INPUTS_BYTES as usize, "{name}");
        assert_eq!(
            c.try_verify_proof(
                &Bytes::from_slice(&e, &inputs),
                &Bytes::from_slice(&e, &proof)
            ),
            Ok(Ok(())),
            "{name}"
        );
    }
}

/// The Gmail fixture proved again by bb.js, the prover a browser runs
/// (`packages/email-recovery/scripts/measure-bbjs.mjs`): its proof verifies
/// like the bb CLI's.
#[test]
fn a_bbjs_proof_verifies() {
    let (e, c) = setup();
    let dir = "crates/integration-tests/fixtures/email/provider-gmail-com";
    let proof = read(&std::format!("{dir}/proof.bbjs"));
    let inputs = read(&std::format!("{dir}/public_inputs"));
    assert_ne!(
        proof,
        read(&std::format!("{dir}/proof")),
        "an independent proof"
    );
    assert_eq!(
        c.try_verify_proof(
            &Bytes::from_slice(&e, &inputs),
            &Bytes::from_slice(&e, &proof)
        ),
        Ok(Ok(()))
    );
}

#[test]
fn a_changed_public_input_is_refused() {
    let (e, c) = setup();
    let (_, proof, inputs) = fixtures().remove(0);
    let proof = Bytes::from_slice(&e, &proof);
    for i in 0..4 {
        let mut changed = inputs.clone();
        changed[32 * i + 31] ^= 1;
        assert_eq!(
            c.try_verify_proof(&Bytes::from_slice(&e, &changed), &proof),
            Err(Ok(ProofVerifierError::VerificationFailed)),
            "input {i}"
        );
    }
    // Another provider's public inputs with this proof.
    let (_, _, other) = fixtures().remove(1);
    assert_eq!(
        c.try_verify_proof(&Bytes::from_slice(&e, &other), &proof),
        Err(Ok(ProofVerifierError::VerificationFailed))
    );
}

/// `C + r` encodes the same field element as `C` but is not canonical.
#[test]
fn a_non_canonical_public_input_is_refused() {
    let (e, c) = setup();
    let (_, proof, inputs) = fixtures().remove(0);
    let r: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];
    // digest_hi < 2^128, so digest_hi + r < 2^256.
    let mut changed = inputs.clone();
    let mut carry = 0u16;
    for k in (0..32).rev() {
        let s = u16::from(changed[32 + k]) + u16::from(r[k]) + carry;
        changed[32 + k] = (s & 0xff) as u8;
        carry = s >> 8;
    }
    assert_eq!(carry, 0);
    assert_eq!(
        c.try_verify_proof(
            &Bytes::from_slice(&e, &changed),
            &Bytes::from_slice(&e, &proof)
        ),
        Err(Ok(ProofVerifierError::VerificationFailed))
    );
}

#[test]
fn a_changed_proof_is_refused() {
    let (e, c) = setup();
    let (_, proof, inputs) = fixtures().remove(0);
    let inputs = Bytes::from_slice(&e, &inputs);
    for at in [0, 31, 1000, 8000, PROOF_BYTES as usize - 1] {
        let mut changed = proof.clone();
        changed[at] ^= 1;
        assert_eq!(
            c.try_verify_proof(&inputs, &Bytes::from_slice(&e, &changed)),
            Err(Ok(ProofVerifierError::VerificationFailed)),
            "byte {at}"
        );
    }
}

/// A real zero-knowledge proof of another circuit (Perch's recovery
/// circuit) is refused under this circuit's key.
#[test]
fn a_proof_of_another_circuit_is_refused() {
    let (e, c) = setup();
    let (_, _, inputs) = fixtures().remove(0);
    let perch = read("crates/integration-tests/fixtures/zk/costs-initiate-a/proof");
    assert_eq!(perch.len(), PROOF_BYTES as usize);
    assert_eq!(
        c.try_verify_proof(
            &Bytes::from_slice(&e, &inputs),
            &Bytes::from_slice(&e, &perch)
        ),
        Err(Ok(ProofVerifierError::VerificationFailed))
    );
}

#[test]
fn wrong_lengths_are_refused() {
    let (e, c) = setup();
    let (_, proof, inputs) = fixtures().remove(0);
    let parse = Err(Ok(ProofVerifierError::ProofParseError));
    let p = Bytes::from_slice(&e, &proof);
    let i = Bytes::from_slice(&e, &inputs);
    assert_eq!(c.try_verify_proof(&i, &p.slice(..PROOF_BYTES - 32)), parse);
    let mut longer = p.clone();
    longer.extend_from_array(&[0u8; 32]);
    assert_eq!(c.try_verify_proof(&i, &longer), parse);
    assert_eq!(c.try_verify_proof(&i.slice(..96), &p), parse);
    let mut more = i.clone();
    more.extend_from_array(&[0u8; 32]);
    assert_eq!(c.try_verify_proof(&more, &p), parse);
}
