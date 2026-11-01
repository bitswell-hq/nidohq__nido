use soroban_sdk::{contractclient, BytesN, Env};

/// What the guardian asks the DKIM key registry.
///
/// The registry holds a Merkle tree of `(domain, key_hash)` leaves and
/// decides which of its roots are acceptable at the current ledger: a root
/// becomes acceptable once its timelock has passed, stays acceptable for the
/// grace period after a newer root supersedes it, and stops being acceptable
/// at once when a key it contains is revoked. A registry implementation
/// answers from its own storage and calls nothing back.
#[allow(unused)]
#[contractclient(name = "DkimRegistryClient")]
pub trait DkimRegistryInterface {
    /// Whether `root` is an acceptable key-set root at the current ledger.
    fn is_accepted_root(e: &Env, root: BytesN<32>) -> bool;
}
