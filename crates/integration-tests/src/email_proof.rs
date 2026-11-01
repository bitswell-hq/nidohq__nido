//! Real email-recovery proofs for the email-guardian suites.
//!
//! Every approval the suites submit carries a zero-knowledge `UltraHonk`
//! proof of `circuits/email-recovery/recovery` over a DKIM-signed recovery
//! email, verified on chain by `nido-email-verifier` (Perch's vendored
//! verifier with the circuit's key compiled in). Nothing here mocks a
//! verifier.
//!
//! The emails come from `@nidohq/email-mocks`: each launch provider's
//! TEST-ONLY signing key, header layout and DKIM-Signature format. The keys
//! the registry admits are the mock DNS's records for them
//! (`fixtures/email/keys.json`), fed through the DNS attester mock.
//!
//! An approval binds the statement digest the controller builds, the
//! guardian's commitment, and a key root, so each proof is specific to one
//! moment of one test. [`proof`] computes the public inputs natively (the
//! host's Poseidon2, as the registry hashes) and then:
//!
//! - with `NIDO_EMAIL_PROVE=1` (`just gen-email-proofs`), has
//!   `packages/email-recovery/scripts/email-fixture.mjs` generate the email
//!   and encode the circuit's inputs, proves them with Perch's pinned
//!   nargo/bb (`NARGO`/`BB`), checks bb committed to the native public
//!   inputs, and writes `fixtures/email/<name>/`;
//! - otherwise replays the committed proof, after checking the fixture was
//!   made for exactly this statement, inbox, key path, and verification key.
//!   A drifted test fails here with the regeneration command rather than as
//!   an opaque `ProofRejected` from the chain.
//!
//! Proofs are zero-knowledge, so a re-proof has different bytes. The emails
//! are deterministic: a regeneration must reproduce every `message.eml` and
//! `fixture.json`.

// A test harness: every helper either returns the computed value or panics
// on a failed setup step (which fails the test).
#![allow(clippy::missing_panics_doc)]

extern crate std;

use perch_recovery_interface::RecoveryStatement;
use perch_zk_prover::{hex, Toolchain};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soroban_poseidon::Poseidon2Sponge;
use soroban_sdk::crypto::bn254::Bn254Fr;
use soroban_sdk::{Bytes, BytesN, Env, U256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::string::{String, ToString};
use std::vec::Vec;

/// The Noir package every email proof is made with.
pub const CIRCUIT: &str = "recovery";

/// The circuit's verification key, as the verifier contract compiles it in.
pub const EMAIL_VK: &[u8] =
    include_bytes!("../../../contracts/email-verifier/vk/email_recovery.vk");

/// `BE(sha256("nido/email-recovery/v1/commit")) mod r` (spec §2).
pub const DOM_COMMIT: [u8; 32] = [
    0x28, 0xc4, 0x45, 0x78, 0x26, 0x5e, 0x02, 0x6b, 0x7c, 0xec, 0xaa, 0x4b, 0x01, 0xb7, 0x9f, 0xef,
    0x9a, 0x1d, 0x1e, 0x43, 0x40, 0xe2, 0x70, 0x59, 0x6d, 0xe3, 0xa7, 0x24, 0xf0, 0x44, 0xee, 0x56,
];

/// The longest address the commitment packs (spec §4.5, `ADDR_MAX`).
pub const ADDR_MAX: usize = 124;

fn repo() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/email")
}

fn proving() -> bool {
    std::env::var("NIDO_EMAIL_PROVE").is_ok_and(|v| v == "1")
}

/// `sha256` of [`EMAIL_VK`]: the circuit id the verifier reports.
#[must_use]
pub fn circuit_id() -> [u8; 32] {
    Sha256::digest(EMAIL_VK).into()
}

/// `P2(x_1, .., x_n)` on a scratch host: the sponge the registry hashes
/// with, outside any metered invocation.
#[must_use]
pub fn p2(inputs: &[[u8; 32]]) -> [u8; 32] {
    let host = perch_zk_prover::host();
    let mut v = soroban_sdk::vec![&host];
    for x in inputs {
        v.push_back(U256::from_be_bytes(&host, &Bytes::from_array(&host, x)));
    }
    let mut out = [0u8; 32];
    Poseidon2Sponge::<4, Bn254Fr>::new(&host)
        .compute_hash(&v)
        .to_be_bytes()
        .copy_into_slice(&mut out);
    out
}

/// A small integer as a field element.
fn field_u32(x: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[28..].copy_from_slice(&x.to_be_bytes());
    out
}

/// `C = P2(DOM_COMMIT, len, pack(address, 124), account_code)` (spec §5.3).
///
/// # Panics
/// If `address` is empty or longer than [`ADDR_MAX`].
#[must_use]
pub fn commitment(address: &str, account_code: &[u8; 32]) -> [u8; 32] {
    let bytes = address.as_bytes();
    assert!(
        !bytes.is_empty() && bytes.len() <= ADDR_MAX,
        "address length"
    );
    let mut padded = [0u8; ADDR_MAX];
    padded[..bytes.len()].copy_from_slice(bytes);
    let mut inputs = std::vec![DOM_COMMIT, field_u32(u32::try_from(bytes.len()).unwrap())];
    for chunk in padded.chunks(31) {
        let mut limb = [0u8; 32];
        limb[1..].copy_from_slice(chunk);
        inputs.push(limb);
    }
    inputs.push(*account_code);
    p2(&inputs)
}

/// The depth-16 root and siblings of `leaves[index]` in the tree whose
/// first leaves are `leaves` and the rest empty: the registry's tree
/// (spec §7.2) or a pin tree (§7.4).
///
/// # Panics
/// If there is no leaf at `index`.
#[must_use]
pub fn tree_path(leaves: &[[u8; 32]], index: usize) -> ([u8; 32], Vec<[u8; 32]>) {
    assert!(index < leaves.len(), "no leaf at {index}");
    let zeros = &perch_zk_primitives::ZERO_HASHES;
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut at = index;
    let mut siblings = Vec::new();
    for zero in zeros.iter().take(16) {
        siblings.push(level.get(at ^ 1).copied().unwrap_or(*zero));
        level = level
            .chunks(2)
            .map(|pair| p2(&[pair[0], pair.get(1).copied().unwrap_or(*zero)]))
            .collect();
        at >>= 1;
    }
    (level[0], siblings)
}

/// A launch provider's TEST-ONLY DKIM key record as the mock DNS publishes
/// it: one entry of `fixtures/email/keys.json`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProviderKey {
    pub domain: String,
    pub provider: String,
    /// `current` (the provider's live aligned selector) or `gmail-previous`.
    pub signer: String,
    pub selector: String,
    /// The TXT record's value.
    pub record: String,
}

impl ProviderKey {
    /// The record as DNS serves it: character-strings of at most 255 octets.
    #[must_use]
    pub fn strings(&self) -> Vec<&str> {
        self.record
            .as_bytes()
            .chunks(255)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect()
    }

    /// The RSA-2048 modulus the record publishes.
    ///
    /// # Panics
    /// If the record does not publish one.
    #[must_use]
    pub fn modulus(&self) -> [u8; 256] {
        let record = nido_dns_attestation_mock::parse_txt(&self.strings()).expect("a key record");
        nido_dns_attestation_mock::modulus_2048(&record).expect("an RSA-2048 key")
    }

    #[must_use]
    pub fn key_hash(&self) -> [u8; 32] {
        nido_dns_attestation_mock::key_hash(&self.modulus())
    }

    /// The registry leaf `(domain, key_hash)` (spec §7.2).
    #[must_use]
    pub fn leaf(&self) -> [u8; 32] {
        let host = perch_zk_prover::host();
        nido_dkim_registry::hash::Hasher::new(&host)
            .leaf(
                self.domain.as_bytes(),
                &BytesN::from_array(&host, &self.key_hash()),
            )
            .to_array()
    }
}

/// Every key of `fixtures/email/keys.json`: the launch domains' current keys
/// in the registry's allowlist order, then Gmail's previous key.
///
/// # Panics
/// If the committed file does not parse.
#[must_use]
pub fn provider_keys() -> Vec<ProviderKey> {
    serde_json::from_str(include_str!("../fixtures/email/keys.json"))
        .expect("fixtures/email/keys.json")
}

/// The key `signer` of `domain`.
///
/// # Panics
/// If there is none.
#[must_use]
pub fn provider_key(domain: &str, signer: &str) -> ProviderKey {
    provider_keys()
        .into_iter()
        .find(|k| k.domain == domain && k.signer == signer)
        .unwrap_or_else(|| panic!("no {signer} key for {domain} in fixtures/email/keys.json"))
}

/// An enrolled inbox: the address the guardian commits to, the provider
/// that signs its mail, and the wallet's `account_code`.
#[derive(Clone, Debug)]
pub struct Inbox {
    pub address: String,
    pub display_name: Option<String>,
    /// Which of the provider's keys signs: `current` or `gmail-previous`.
    pub signer: String,
    /// The 16-byte code as a field element (32 bytes, the top 16 zero).
    pub account_code: [u8; 32],
}

impl Inbox {
    /// `address` at a launch provider, signing with its current key, with a
    /// TEST-ONLY `account_code` derived from `label`.
    #[must_use]
    pub fn new(label: &str, address: &str, display_name: Option<&str>) -> Self {
        let digest: [u8; 32] =
            Sha256::digest(std::format!("nido-it/email/account-code/{label}")).into();
        let mut account_code = [0u8; 32];
        account_code[16..].copy_from_slice(&digest[..16]);
        Self {
            address: address.to_string(),
            display_name: display_name.map(ToString::to_string),
            signer: "current".to_string(),
            account_code,
        }
    }

    /// The same inbox with its mail signed by another of the provider's keys.
    #[must_use]
    pub fn signed_by(mut self, signer: &str) -> Self {
        self.signer = signer.to_string();
        self
    }

    #[must_use]
    pub fn domain(&self) -> &str {
        &self.address[self.address.rfind('@').unwrap() + 1..]
    }

    /// The key that signs this inbox's mail.
    #[must_use]
    pub fn key(&self) -> ProviderKey {
        provider_key(&self.domain().to_ascii_lowercase(), &self.signer)
    }

    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        commitment(&self.address, &self.account_code)
    }
}

/// A key-tree path: the root a proof is made against, the leaf index, and
/// its 16 siblings, lowest level first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyPath {
    pub root: [u8; 32],
    pub index: u32,
    pub siblings: Vec<[u8; 32]>,
}

impl KeyPath {
    /// The path of `leaves[index]` (see [`tree_path`]).
    #[must_use]
    pub fn of(leaves: &[[u8; 32]], index: usize) -> Self {
        let (root, siblings) = tree_path(leaves, index);
        Self {
            root,
            index: u32::try_from(index).unwrap(),
            siblings,
        }
    }
}

/// What a committed fixture was proved for, so the browser prover's tests
/// can re-encode `message.eml` to the same witness. The secrets are TEST-ONLY
/// values derived from labels.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
struct FixtureMeta {
    description: String,
    circuit: String,
    /// `sha256` of the verification key the proof verifies under.
    circuit_id: String,
    provider: String,
    from: String,
    display_name: Option<String>,
    signer: String,
    selector: String,
    modulus: String,
    account_code: String,
    rho: String,
    /// The Perch statement encoding the email approves.
    statement: String,
    digest: String,
    key_root: String,
    key_index: u32,
    key_siblings: Vec<String>,
    /// `C`, `digest_hi`, `digest_lo`, `key_root`: 32-byte big-endian each.
    public_inputs: Vec<String>,
}

/// The circuit's public inputs as the guardian builds them: `C ||
/// digest_hi || digest_lo || key_root`.
#[must_use]
pub fn public_inputs(commitment: &[u8; 32], digest: &[u8; 32], root: &[u8; 32]) -> [[u8; 32]; 4] {
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[16..].copy_from_slice(&digest[..16]);
    lo[16..].copy_from_slice(&digest[16..]);
    [*commitment, hi, lo, *root]
}

fn run(cmd: &mut Command) {
    let out = cmd.output().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(
        out.status.success(),
        "{cmd:?} failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Generate the email, encode it, and prove it with Perch's pinned
/// toolchain. Returns the proof and bb's public-input bytes.
fn prove(name: &str, request: &serde_json::Value, work: &Path) -> (Vec<u8>, Vec<u8>) {
    let tc = Toolchain::from_env().expect("Perch's pinned nargo/bb (just gen-email-proofs)");
    std::fs::create_dir_all(work).unwrap();
    let work = work.canonicalize().unwrap();
    let request_path = work.join("request.json");
    std::fs::write(
        &request_path,
        serde_json::to_string_pretty(request).unwrap(),
    )
    .unwrap();
    run(Command::new("node")
        .arg(repo().join("packages/email-recovery/scripts/email-fixture.mjs"))
        .arg("email")
        .arg(&request_path)
        .arg(&work));

    let circuits = repo().join("circuits/email-recovery");
    let witness_name = std::format!("email-{name}-{}", std::process::id());
    run(Command::new(&tc.nargo)
        .current_dir(&circuits)
        .args(["execute", "--package", CIRCUIT, "--prover-name"])
        .arg(work.join("Prover"))
        .arg(&witness_name));
    let witness = work.join("witness.gz");
    std::fs::rename(
        circuits
            .join("target")
            .join(std::format!("{witness_name}.gz")),
        &witness,
    )
    .unwrap();
    run(Command::new(&tc.bb)
        .args([
            "prove",
            "--scheme",
            "ultra_honk",
            "--oracle_hash",
            "keccak",
            "--zk",
            "-b",
        ])
        .arg(circuits.join("target").join(std::format!("{CIRCUIT}.json")))
        .arg("-w")
        .arg(&witness)
        .arg("-o")
        .arg(&work));
    (
        std::fs::read(work.join("proof")).unwrap(),
        std::fs::read(work.join("public_inputs")).unwrap(),
    )
}

/// A real proof that `inbox` emailed its approval of `statement`, with its
/// signing key's membership proven along `path`. `name` is the fixture
/// directory (`fixtures/email/<name>/`); `rho` is derived from it.
///
/// # Panics
/// If proving fails, or if the committed fixture was made for another
/// statement, inbox, key path, or verification key (rerun
/// `just gen-email-proofs`).
#[must_use]
pub fn proof(
    env: &Env,
    name: &str,
    description: &str,
    inbox: &Inbox,
    statement: &RecoveryStatement,
    path: &KeyPath,
) -> Bytes {
    let encoding = statement.encode(env).expect("an encodable statement");
    let mut statement_bytes = std::vec![0u8; encoding.len() as usize];
    encoding.copy_into_slice(&mut statement_bytes);
    let digest: [u8; 32] = Sha256::digest(&statement_bytes).into();
    let mut rho: [u8; 32] = Sha256::digest(std::format!("nido-it/email/rho/{name}")).into();
    rho[0] = 0;
    let key = inbox.key();
    let modulus = key.modulus();
    let inputs = public_inputs(&inbox.commitment(), &digest, &path.root);
    let meta = FixtureMeta {
        description: description.to_string(),
        circuit: CIRCUIT.to_string(),
        circuit_id: hex(&circuit_id()),
        provider: key.provider.clone(),
        from: inbox.address.clone(),
        display_name: inbox.display_name.clone(),
        signer: inbox.signer.clone(),
        selector: key.selector.clone(),
        modulus: hex(&modulus),
        account_code: hex(&inbox.account_code),
        rho: hex(&rho),
        statement: hex(&statement_bytes),
        digest: hex(&digest),
        key_root: hex(&path.root),
        key_index: path.index,
        key_siblings: path.siblings.iter().map(|s| hex(s)).collect(),
        public_inputs: inputs.iter().map(|x| hex(x)).collect(),
    };

    let dir = fixtures_dir().join(name);
    let proof = if proving() {
        let request = serde_json::json!({
            "provider": key.provider,
            "from": inbox.address,
            "displayName": inbox.display_name,
            "signer": inbox.signer,
            "modulus": hex(&modulus),
            "accountCode": hex(&inbox.account_code),
            "rho": hex(&rho),
            "statement": hex(&statement_bytes),
            "keyPath": {
                "root": hex(&path.root),
                "index": path.index,
                "siblings": meta.key_siblings,
            },
        });
        let work = repo().join("target/email-work").join(name);
        let (proof, bb_inputs) = prove(name, &request, &work);
        assert_eq!(
            bb_inputs,
            inputs.concat(),
            "bb committed to the public inputs computed natively"
        );
        let encoded: serde_json::Value =
            serde_json::from_slice(&std::fs::read(work.join("encoded.json")).unwrap()).unwrap();
        assert_eq!(
            encoded["publicInputs"],
            serde_json::json!(meta.public_inputs),
            "the encoder's public inputs are the native ones"
        );
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::copy(work.join("message.eml"), dir.join("message.eml")).unwrap();
        std::fs::write(dir.join("proof"), &proof).unwrap();
        std::fs::write(dir.join("public_inputs"), &bb_inputs).unwrap();
        std::fs::write(
            dir.join("fixture.json"),
            serde_json::to_string_pretty(&meta).unwrap() + "\n",
        )
        .unwrap();
        proof
    } else {
        let committed: FixtureMeta = serde_json::from_slice(
            &std::fs::read(dir.join("fixture.json")).unwrap_or_else(|_| {
                panic!("missing email fixture {name}: run `just gen-email-proofs`")
            }),
        )
        .unwrap();
        assert_eq!(
            committed, meta,
            "email fixture {name} was proved for another statement, inbox, key path, or circuit; \
             rerun `just gen-email-proofs`"
        );
        std::fs::read(dir.join("proof")).unwrap()
    };
    Bytes::from_slice(env, &proof)
}
