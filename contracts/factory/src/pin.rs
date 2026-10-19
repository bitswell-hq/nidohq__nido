//! Reads the `perch-account` wasm hash the factory pins out of a Perch
//! deployment manifest (`vendor/perch/deployments/<network>.json`). `build.rs`
//! includes this file to generate the pin; the crate's tests include it to
//! check what it refuses.

extern crate std;

use std::format;
use std::string::String;

/// The `perch-account` sha256 in `manifest`, the text of the deployment
/// manifest for `network`. Refuses a manifest that names another network or
/// has no account hash, so a build never pins another network's account.
pub fn account_wasm_hash(manifest: &str, network: &str) -> Result<[u8; 32], String> {
    let json: serde_json::Value =
        serde_json::from_str(manifest).map_err(|e| format!("it is not JSON: {e}"))?;
    if json["network"].as_str() != Some(network) {
        return Err(format!(
            "its network is {}, not \"{network}\"",
            json["network"]
        ));
    }
    let hex = json["contracts"]["perch-account"]["sha256"]
        .as_str()
        .ok_or_else(|| String::from("it has no contracts.perch-account.sha256"))?;
    decode(hex).ok_or_else(|| format!("its perch-account sha256 {hex:?} is not 64 hex digits"))
}

fn decode(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::account_wasm_hash;
    use std::format;
    use std::string::{String, ToString};

    const TESTNET: &str = include_str!("../../../vendor/perch/deployments/testnet.json");
    /// A real Perch manifest with no `perch-account`.
    const NO_ACCOUNT: &str =
        include_str!("../../../vendor/perch/deployments/testnet-exercise.json");

    #[test]
    fn pins_the_manifests_account_hash() {
        let hash = account_wasm_hash(TESTNET, "testnet").unwrap();
        let mut hex = String::new();
        for byte in hash {
            core::fmt::Write::write_fmt(&mut hex, format_args!("{byte:02x}")).unwrap();
        }
        let json: serde_json::Value = serde_json::from_str(TESTNET).unwrap();
        assert_eq!(hex, json["contracts"]["perch-account"]["sha256"]);
    }

    #[test]
    fn refuses_a_manifest_without_an_account_hash() {
        let why = account_wasm_hash(NO_ACCOUNT, "testnet").unwrap_err();
        assert!(why.contains("no contracts.perch-account.sha256"), "{why}");
    }

    /// The testnet manifest with `edit` applied.
    fn edited(edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut json: serde_json::Value = serde_json::from_str(TESTNET).unwrap();
        edit(&mut json);
        json.to_string()
    }

    /// A build for mainnet never pins testnet's account, even from a
    /// manifest file that a mainnet build would read.
    #[test]
    fn refuses_another_networks_manifest() {
        let why = account_wasm_hash(TESTNET, "mainnet").unwrap_err();
        assert!(
            why.contains(r#"its network is "testnet", not "mainnet""#),
            "{why}"
        );
        let unnamed = edited(|json| {
            json.as_object_mut().unwrap().remove("network");
        });
        assert!(account_wasm_hash(&unnamed, "testnet").is_err());
    }

    #[test]
    fn refuses_a_hash_that_is_not_32_bytes_of_hex() {
        let json: serde_json::Value = serde_json::from_str(TESTNET).unwrap();
        let hash = json["contracts"]["perch-account"]["sha256"]
            .as_str()
            .unwrap();
        for bad in [
            &hash[..62],
            "zz",
            &format!("{hash}00"),
            &hash.replace('a', "g"),
        ] {
            let manifest = edited(|json| json["contracts"]["perch-account"]["sha256"] = bad.into());
            assert!(account_wasm_hash(&manifest, "testnet").is_err(), "{bad}");
        }
        assert!(account_wasm_hash("not json", "testnet").is_err());
    }
}
