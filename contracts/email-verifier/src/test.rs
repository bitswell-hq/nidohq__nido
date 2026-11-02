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

/// The sections of a zero-knowledge proof, in order, as the vendored verifier
/// reads them (`ultrahonk_soroban_verifier::zk::load_zk_proof`): each one's
/// length in bytes and whether it holds G1 points (128 bytes each, the
/// coordinates as `(x_lo, x_hi, y_lo, y_hi)` limbs) or scalars.
const LAYOUT: [(usize, bool); 16] = [
    (16 * 32, false),     // pairing point object
    (9 * 128, true), // w1..w3, lookup counts and tags, w4, lookup inverses, z_perm, Libra concatenation
    (32, false),     // Libra sum
    (28 * 9 * 32, false), // sumcheck univariates
    (40 * 32, false), // sumcheck evaluations
    (32, false),     // Libra claimed evaluation
    (128, true),     // Libra grand sum
    (128, true),     // Libra quotient
    (128, true),     // Gemini masking polynomial
    (32, false),     // Gemini masking evaluation
    (27 * 128, true), // Gemini fold commitments
    (28 * 32, false), // Gemini evaluations
    (4 * 32, false), // Libra polynomial evaluations
    (128, true),     // Shplonk Q
    (128, true),     // KZG quotient
    (0, false),
];

/// BN254's base-field modulus `p`, big-endian.
const P: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// The offset of every G1 point in a proof.
fn point_offsets() -> Vec<usize> {
    let mut at = 0;
    let mut out = Vec::new();
    for (len, points) in LAYOUT {
        if points {
            out.extend((0..len / 128).map(|i| at + 128 * i));
        }
        at += len;
    }
    assert_eq!(at, PROOF_BYTES as usize);
    out
}

/// The proof with the G1 point at `at` replaced by its negation `(x, p - y)`,
/// encoded canonically: another point on the curve.
fn negate_point(proof: &[u8], at: usize) -> Vec<u8> {
    let mut out = proof.to_vec();
    let (lo, hi) = (at + 64, at + 96);
    let mut y = [0u8; 32];
    y[..15].copy_from_slice(&proof[hi + 17..hi + 32]);
    y[15..].copy_from_slice(&proof[lo + 15..lo + 32]);
    assert_ne!(y, [0u8; 32], "a point at infinity at {at}");
    let mut neg = [0u8; 32];
    let mut borrow = 0i16;
    for k in (0..32).rev() {
        let d = i16::from(P[k]) - i16::from(y[k]) - borrow;
        borrow = i16::from(d < 0);
        neg[k] = u8::try_from(d.rem_euclid(256)).unwrap();
    }
    assert_eq!(borrow, 0);
    out[lo..lo + 32].fill(0);
    out[lo + 15..lo + 32].copy_from_slice(&neg[15..]);
    out[hi..hi + 32].fill(0);
    out[hi + 17..hi + 32].copy_from_slice(&neg[..15]);
    out
}

/// Proofs mauled from public data alone, which an observer of an honest
/// approval can compute, are refused, with the honest proof's own public
/// inputs and with the digest of another statement under the same `C` and
/// root (spec §11.1, A4): every G1 point of the proof negated in turn, and the
/// two independent proofs of the Gmail statement (the bb CLI's and bb.js's,
/// each randomized by the zero-knowledge prover) spliced at every section
/// boundary, both ways, where the splice differs from both. Each mauled proof
/// parses (every scalar canonical, every point on the curve), so the refusal
/// comes from the verification equations, not the parser.
#[test]
fn mauled_proofs_are_refused() {
    let (e, c) = setup();
    let dir = "crates/integration-tests/fixtures/email/provider-gmail-com";
    let cli = read(&std::format!("{dir}/proof"));
    let bbjs = read(&std::format!("{dir}/proof.bbjs"));
    let inputs = read(&std::format!("{dir}/public_inputs"));
    let (_, _, other) = fixtures()
        .into_iter()
        .find(|(name, ..)| name != "provider-gmail-com")
        .unwrap();
    let mut another_digest = inputs.clone();
    another_digest[32..96].copy_from_slice(&other[32..96]);
    assert_ne!(another_digest, inputs);
    let input_sets = [inputs.clone(), another_digest.clone()];
    for proof in [&cli, &bbjs] {
        for inputs in &input_sets {
            assert_eq!(
                c.try_verify_proof(
                    &Bytes::from_slice(&e, &inputs[..]),
                    &Bytes::from_slice(&e, proof)
                )
                .is_ok(),
                *inputs == input_sets[0],
                "only the honest public inputs verify"
            );
        }
    }

    let mut mauled: Vec<(std::string::String, Vec<u8>)> = Vec::new();
    for at in point_offsets() {
        mauled.push((
            std::format!("point at {at} negated"),
            negate_point(&cli, at),
        ));
    }
    let mut at = 0;
    for (len, _) in &LAYOUT[..LAYOUT.len() - 2] {
        at += len;
        let mut a = cli[..at].to_vec();
        a.extend_from_slice(&bbjs[at..]);
        let mut b = bbjs[..at].to_vec();
        b.extend_from_slice(&cli[at..]);
        // Both proofs carry the same pairing point object, so a splice there
        // is one of the two proofs.
        for (what, spliced) in [
            (std::format!("bb CLI to {at}, then bb.js"), a),
            (std::format!("bb.js to {at}, then bb CLI"), b),
        ] {
            if spliced != cli && spliced != bbjs {
                mauled.push((what, spliced));
            }
        }
    }
    assert_eq!(mauled.len(), 41 + 2 * 13);
    for (what, proof) in &mauled {
        let proof = Bytes::from_slice(&e, proof);
        assert!(
            ultrahonk_soroban_verifier::zk::load_zk_proof(&e, &proof).is_ok(),
            "{what}: a well-formed proof"
        );
        for inputs in &input_sets {
            assert_eq!(
                c.try_verify_proof(&Bytes::from_slice(&e, inputs), &proof),
                Err(Ok(ProofVerifierError::VerificationFailed)),
                "{what}"
            );
        }
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
