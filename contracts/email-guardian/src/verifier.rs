use soroban_sdk::{contractclient, BytesN, Env};

/// The identity view the guardian reads from its verifier once, at
/// construction. Proofs are checked through Perch's
/// `perch_recovery_interface::zk::ProofVerifierInterface` (`verify_proof`);
/// a verifier contract for the email circuit exposes both, as Perch's ZK
/// adapter does.
#[allow(unused)]
#[contractclient(name = "VerifierIdentityClient")]
pub trait VerifierIdentity {
    /// `sha256` of the compiled-in verification key.
    fn circuit_id(e: &Env) -> BytesN<32>;
}
