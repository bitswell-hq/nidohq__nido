//! `nido-email-verifier`: the email-recovery circuit's proof verifier
//! (`docs/email-recovery/spec.md` §8.4).
//!
//! It embeds Perch's vendored `UltraHonk` verifier
//! (`vendor/perch/vendor/ultrahonk-soroban-verifier`, `UltraHonkZkVerifier`:
//! the zero-knowledge flavor with the keccak transcript) with the
//! verification key of `circuits/email-recovery/recovery` compiled in, the
//! way Perch's ZK adapter embeds its own circuit's key. It exposes Perch's
//! `ProofVerifierInterface` (`verify_proof`, with Perch's
//! `ProofVerifierError` codes) and the identity view an email guardian
//! checks at construction (`circuit_id`, `sha256` of the key).
//!
//! No constructor, no storage, no admin, no upgrade path: an instance's
//! behavior is a pure function of its wasm hash. A new circuit is a new
//! verification key, so a new wasm and a new address, and a guardian names
//! the verifier and its `circuit_id` at construction.
#![no_std]

use perch_recovery_interface::zk::ProofVerifierError;
use soroban_sdk::{contract, contractimpl, Bytes, BytesN, Env};
use ultrahonk_soroban_verifier::UltraHonkZkVerifier;

/// Version of this contract's semantics.
pub const VERSION: u32 = 1;

/// Size of a zero-knowledge `UltraHonk` proof (bb 0.87.0 `--zk`, keccak
/// transcript: 507 field elements, 16,224 bytes).
#[allow(clippy::cast_possible_truncation)] // 16,224
pub const PROOF_BYTES: u32 = ultrahonk_soroban_verifier::ZK_PROOF_BYTES as u32;

/// The circuit's public inputs, `C || digest_hi || digest_lo || key_root`,
/// each 32 bytes big-endian.
pub const PUBLIC_INPUTS_BYTES: u32 = 128;

/// `bb write_vk --scheme ultra_honk --oracle_hash keccak` of
/// `circuits/email-recovery/recovery`, as `just gen-email-proofs` writes it
/// with Perch's pinned bb 0.87.0. The ZK and non-ZK flavors share it.
const VK: &[u8] = include_bytes!("../vk/email_recovery.vk");

#[contract]
pub struct EmailVerifier;

#[contractimpl]
impl EmailVerifier {
    /// See [`VERSION`].
    #[must_use]
    pub fn version(_e: &Env) -> u32 {
        VERSION
    }

    /// The compiled-in verification key.
    #[must_use]
    pub fn vk(e: &Env) -> Bytes {
        Bytes::from_slice(e, VK)
    }

    /// `sha256` of the compiled-in verification key: the `circuit_id` an
    /// email guardian's configuration names.
    #[must_use]
    pub fn circuit_id(e: &Env) -> BytesN<32> {
        e.crypto().sha256(&Self::vk(e)).to_bytes()
    }

    /// `ProofVerifierInterface::verify_proof`: whether `proof_bytes` is a
    /// zero-knowledge proof of the email-recovery circuit for
    /// `public_inputs`.
    ///
    /// # Errors
    /// `ProofParseError` for a proof that is not [`PROOF_BYTES`] long or
    /// public inputs that are not [`PUBLIC_INPUTS_BYTES`] long,
    /// `VkParseError` if the compiled-in key does not parse, and
    /// `VerificationFailed` for any proof the verifier refuses.
    // `#[contractimpl]` entry point: the SDK ABI takes owned arguments.
    #[allow(clippy::needless_pass_by_value)]
    pub fn verify_proof(
        e: &Env,
        public_inputs: Bytes,
        proof_bytes: Bytes,
    ) -> Result<(), ProofVerifierError> {
        if proof_bytes.len() != PROOF_BYTES || public_inputs.len() != PUBLIC_INPUTS_BYTES {
            return Err(ProofVerifierError::ProofParseError);
        }
        let verifier = UltraHonkZkVerifier::new(e, &Self::vk(e))
            .map_err(|_| ProofVerifierError::VkParseError)?;
        verifier
            .verify(&proof_bytes, &public_inputs)
            .map_err(|_| ProofVerifierError::VerificationFailed)
    }
}

#[cfg(test)]
mod test;
