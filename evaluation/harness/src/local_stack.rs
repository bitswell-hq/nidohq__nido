//! The address a Perch account built for the local network takes as its
//! `stateless.id`: the stateless deployer
//! (`evaluation/fixtures/stateless-deployer`) that a fixed deployer key
//! creates with a fixed salt on `stellar/quickstart --local`. A contract's
//! address depends only on the network id, the deployer and the salt, so it
//! is known before the network starts, and `evaluation/scripts/local-stack.sh`
//! builds the account with it.

use sha2::{Digest, Sha256};
use soroban_sdk::xdr::{
    AccountId, ContractIdPreimage, ContractIdPreimageFromAddress, Hash, HashIdPreimage,
    HashIdPreimageContractId, Limits, PublicKey, ScAddress, Uint256, WriteXdr,
};

/// `stellar/quickstart --local`.
pub const PASSPHRASE: &str = "Standalone Network ; February 2017";

/// The seed label of the deployer key and the salt it creates the stateless
/// deployer with.
pub const DEPLOYER: &str = "nido-eval/deployer";
pub const SALT: [u8; 32] = [0x5e; 32];

/// The deployer's ed25519 public key: `SHA-256(DEPLOYER)` as the seed.
#[must_use]
pub fn deployer() -> [u8; 32] {
    let seed: [u8; 32] = Sha256::digest(DEPLOYER.as_bytes()).into();
    ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
}

/// The stateless deployer's address on the local network.
///
/// # Panics
/// If the preimage does not encode.
#[must_use]
pub fn registry() -> String {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(Sha256::digest(PASSPHRASE.as_bytes()).into()),
        contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                deployer(),
            )))),
            salt: Uint256(SALT),
        }),
    });
    let id: [u8; 32] = Sha256::digest(preimage.to_xdr(Limits::none()).expect("XDR")).into();
    stellar_strkey::Contract(id).to_string()
}
