//! The registry a Perch account built for the local network derives its
//! infra from: the chain `evaluation/fixtures/local-registry.path` names on
//! `stellar/quickstart --local`. A fixed deployer key creates the root (an
//! instance of `evaluation/fixtures/stateless-deployer`) with
//! `sha256(root-salt)`; each path segment is a named deploy of another
//! instance at `deployer(parent, sha256(name))`; the last one deploys the
//! infra. A contract's address depends only on the network id, the deployer
//! and the salt, so every link is known before the network starts, and
//! `evaluation/scripts/local-stack.sh` builds the account with this path.

use sha2::{Digest, Sha256};
use soroban_sdk::xdr::{
    AccountId, ContractId, ContractIdPreimage, ContractIdPreimageFromAddress, Hash, HashIdPreimage,
    HashIdPreimageContractId, Limits, PublicKey, ScAddress, Uint256, WriteXdr,
};

/// `stellar/quickstart --local`.
pub const PASSPHRASE: &str = "Standalone Network ; February 2017";

/// The seed label of the root deployer's key.
pub const DEPLOYER: &str = "nido-eval/deployer";

/// The registry path the local account is built with.
pub const REGISTRY_PATH: &str = include_str!("../../fixtures/local-registry.path");

/// The value of `key` in [`REGISTRY_PATH`].
///
/// # Panics
/// If the file has no such line.
fn field(key: &str) -> &'static str {
    REGISTRY_PATH
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .find_map(|l| Some(l.strip_prefix(key)?.strip_prefix(' ')?.trim()))
        .unwrap_or_else(|| panic!("local-registry.path has no `{key}` line"))
}

/// The root deployer's ed25519 public key: `SHA-256(DEPLOYER)` as the seed.
#[must_use]
pub fn deployer() -> [u8; 32] {
    let seed: [u8; 32] = Sha256::digest(DEPLOYER.as_bytes()).into();
    ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes()
}

/// The salt the root deployer creates the root with: `sha256(root-salt)`.
#[must_use]
pub fn root_salt() -> [u8; 32] {
    Sha256::digest(field("root-salt").as_bytes()).into()
}

/// The named deploys below the root, in order.
#[must_use]
pub fn segments() -> Vec<&'static str> {
    field("path")
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect()
}

/// The contract `deployer` creates with `salt` on the local network.
///
/// # Panics
/// If the preimage does not encode.
#[must_use]
pub fn contract_id(deployer: ScAddress, salt: [u8; 32]) -> [u8; 32] {
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id: Hash(Sha256::digest(PASSPHRASE.as_bytes()).into()),
        contract_id_preimage: ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: deployer,
            salt: Uint256(salt),
        }),
    });
    Sha256::digest(preimage.to_xdr(Limits::none()).expect("XDR")).into()
}

/// Every registry on the path, root first.
#[must_use]
pub fn chain() -> Vec<String> {
    let mut id = contract_id(
        ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
            deployer(),
        )))),
        root_salt(),
    );
    let mut out = vec![stellar_strkey::Contract(id).to_string()];
    for name in segments() {
        id = contract_id(
            ScAddress::Contract(ContractId(Hash(id))),
            Sha256::digest(name.as_bytes()).into(),
        );
        out.push(stellar_strkey::Contract(id).to_string());
    }
    out
}

/// The registry the infra is deployed from: the last link of [`chain`].
#[must_use]
pub fn registry() -> String {
    chain().pop().expect("the chain has a root")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_path_names_the_deployer_key() {
        assert_eq!(
            field("root-deployer"),
            stellar_strkey::ed25519::PublicKey(deployer()).to_string()
        );
        assert_eq!(segments(), ["perch", "constructorless"]);
        assert_eq!(chain().len(), 3);
    }
}
