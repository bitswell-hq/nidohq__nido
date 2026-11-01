//! The local network: the Perch stack, Nido's factory and the grant signer
//! deployed on `stellar/quickstart` in local mode, every agent call sent
//! through `crates/grant-relay` to the chain.
//!
//! [`Net`] starts the network (`grant_relay::local`), deploys the stack and
//! hands a pool of channel accounts to the custody key, which the local Dfns
//! mock holds. Fixtures (`soroban::fixture::Fixture::on_network`) mint
//! accounts on it; the owner's setup goes straight to the chain from an
//! operator account, and agents' calls go through a relay
//! ([`relay::Relay`]) whose agents mirror the account's grants or let every
//! call through to the grant signer ([`Mode`]).

pub mod relay;
pub mod report;
pub mod throughput;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use ed25519_dalek::SigningKey;
use grant_relay::local::{self, pk, Quickstart, PASSPHRASE};
use grant_relay::rpc::HttpRpc;
use nido_key_keeper::dfns::mock::{MockConfig, MockServer};
use nido_key_keeper::stellar;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soroban_sdk::xdr::{
    AccountId, AlphaNum4, Asset, AssetCode4, ChangeTrustAsset, ChangeTrustOp, ContractExecutable,
    ContractIdPreimage, ContractIdPreimageFromAddress, CreateContractArgs, CreateContractArgsV2,
    Hash, HostFunction, InvokeContractArgs, InvokeHostFunctionOp, Limits, OperationBody, PublicKey,
    ReadXdr, ScAddress, ScSymbol, ScVal, SorobanAuthorizationEntry, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
};

use crate::local_stack;
use crate::record;

/// How the relay's agents relate to the account's grants.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// Each grant's holder is a relay agent whose chain grant is the grant's
    /// caveats; revoked grants and grants under a revoked ancestor have no
    /// agent.
    Mirrored,
    /// Each grant's holder is a relay agent whose chain grant has no
    /// caveats: every call reaches the chain's simulation and the grant
    /// signer.
    PassThrough,
}

/// The wasm the stack deploys.
pub struct Wasm {
    pub dapp: Vec<u8>,
    pub deployer: Vec<u8>,
    pub stateless_deployer: Vec<u8>,
    /// The Perch account built for this network (`scripts/local-stack.sh`).
    pub account: Vec<u8>,
    /// Nido's factory around that account.
    pub factory: Vec<u8>,
}

impl Wasm {
    /// The fixtures' wasm and the account and factory in `local_stack`
    /// (`target/eval-local/wasm`).
    ///
    /// # Errors
    ///
    /// If a file cannot be read.
    pub fn load(fixtures: &Path, local_stack: &Path) -> Result<Self, String> {
        let read = |p: PathBuf| std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()));
        Ok(Self {
            dapp: read(fixtures.join("nido_eval_dapp.wasm"))?,
            deployer: read(fixtures.join("nido_eval_deployer.wasm"))?,
            stateless_deployer: read(fixtures.join("nido_eval_stateless_deployer.wasm"))?,
            account: read(local_stack.join("perch_account.wasm"))?,
            factory: read(local_stack.join("nido_factory.wasm"))?,
        })
    }
}

/// The SHA-256 of `wasm`, as its code hash.
#[must_use]
pub fn hash(wasm: &[u8]) -> [u8; 32] {
    Sha256::digest(wasm).into()
}

/// Deterministic test keys: `SHA-256(label)` as the seed, with this run's
/// tag mixed in, so a reused network starts from fresh accounts.
fn key(run: [u8; 8], label: &str) -> SigningKey {
    let mut h = Sha256::new();
    h.update(run);
    h.update(label.as_bytes());
    SigningKey::from_bytes(&h.finalize().into())
}

pub const DFNS_TOKEN: &str = "nido-eval-service-account-token";
pub const DFNS_USER: &str = "us-nido-eval-user";
pub const DFNS_CRED: &str = "cr-nido-eval-credential";
pub const CUSTODY_KEY: &str = "key-nido-eval-custody";

/// The custody key in the local Dfns mock, and the credential that signs
/// the mock's user action challenges.
pub struct Custody {
    pub mock: MockServer,
    pub key: SigningKey,
    pub credential: SigningKey,
}

/// The network, its deployed stack and the relay's channels.
pub struct Net {
    pub quickstart: Quickstart,
    pub rpc: HttpRpc,
    /// Pays and sends every setup transaction; the factory's admin.
    operator: SigningKey,
    run: [u8; 8],
    counter: AtomicU32,
    pub verifier: String,
    pub factory: String,
    pub grant_signer_hash: [u8; 32],
    pub dapp_hash: [u8; 32],
    pub deployer_hash: [u8; 32],
    pub custody: Custody,
    /// Channel accounts, each with master weight 0 and the custody key as its
    /// only signer.
    pub channels: Vec<[u8; 32]>,
    mode: Mutex<Mode>,
    /// The relay agent calls go through, rebuilt when its agents change.
    relay: Mutex<Option<relay::Running>>,
    /// Setup timing and versions, for the results.
    pub conditions: Value,
}

impl Net {
    /// Start the network (or use the one at `NIDO_EVAL_QUICKSTART_URL`),
    /// deploy the stack from `wasm` and set up `channels` channel accounts.
    ///
    /// # Errors
    ///
    /// If any setup step fails.
    #[allow(clippy::too_many_lines)]
    pub fn start(wasm: &Wasm, channels: usize) -> Result<Self, String> {
        let started = Instant::now();
        let mut run = [0u8; 8];
        getrandom::getrandom(&mut run).map_err(|e| e.to_string())?;
        let quickstart = match std::env::var("NIDO_EVAL_QUICKSTART_URL") {
            Ok(base) => Quickstart::existing(&base)?,
            Err(_) => Quickstart::start(&format!("nido-eval-{}", hex::encode(&run[..4])))?,
        };
        eprintln!("network: ready at {}", quickstart.base());
        let rpc = HttpRpc::new(quickstart.rpc_url());
        let operator = key(run, "operator");
        quickstart.fund(&stellar::account_strkey(&pk(&operator)))?;

        let upload = |code: &[u8]| -> Result<[u8; 32], String> {
            let func = HostFunction::UploadContractWasm(
                code.to_vec().try_into().map_err(|_| "wasm too large")?,
            );
            match local::invoke(&rpc, &operator, &func, None) {
                Ok(_) => Ok(hash(code)),
                // Already on this network.
                Err(e) if e.contains("ExistingValue") => Ok(hash(code)),
                Err(e) => Err(format!("uploading wasm {}: {e}", hex::encode(hash(code)))),
            }
        };
        let create = |source: &SigningKey,
                      salt: [u8; 32],
                      code: [u8; 32],
                      args: Vec<ScVal>|
         -> Result<String, String> {
            let preimage = ContractIdPreimage::Address(ContractIdPreimageFromAddress {
                address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                    pk(source),
                )))),
                salt: Uint256(salt),
            });
            let address = local::contract_id(preimage.clone());
            let func = HostFunction::CreateContractV2(CreateContractArgsV2 {
                contract_id_preimage: preimage,
                executable: ContractExecutable::Wasm(Hash(code)),
                constructor_args: args.try_into().map_err(|_| "too many arguments")?,
            });
            match local::invoke(&rpc, source, &func, None) {
                Ok(_) => Ok(address),
                Err(e) if e.contains("ExistingValue") => Ok(address),
                Err(e) => Err(format!("creating {address}: {e}")),
            }
        };

        // Perch's infra at the addresses the local account derives: the
        // stateless deployer from its fixed key and salt, then each pinned
        // contract deployed through it.
        let deployer_seed: [u8; 32] = Sha256::digest(local_stack::DEPLOYER.as_bytes()).into();
        let deployer_key = SigningKey::from_bytes(&deployer_seed);
        let deployer_account = stellar::account_strkey(&pk(&deployer_key));
        if quickstart.fund(&deployer_account).is_err() {
            local::sequence(&rpc, &pk(&deployer_key))?;
        }
        let stateless = upload(&wasm.stateless_deployer)?;
        let registry = create(&deployer_key, local_stack::SALT, stateless, vec![])?;
        if registry != local_stack::registry() {
            return Err(format!(
                "the stateless deployer is at {registry}, not {}",
                local_stack::registry()
            ));
        }
        for (name, code) in [
            (
                "doc compiler",
                nido_integration_tests::PERCH_DOC_COMPILER_WASM,
            ),
            (
                "interpreter",
                nido_integration_tests::PERCH_INTERPRETER_WASM,
            ),
            (
                "spending limit",
                nido_integration_tests::PERCH_SPENDING_LIMIT_WASM,
            ),
        ] {
            let h = upload(code)?;
            let func = invoke(&registry, "deploy", vec![bytes32(h)]);
            match local::invoke(&rpc, &operator, &func, None) {
                Ok(_) => {}
                Err(e) if e.contains("ExistingValue") => {}
                Err(e) => return Err(format!("deploying the {name}: {e}")),
            }
        }
        let verifier = create(
            &operator,
            [1; 32],
            upload(nido_integration_tests::PERCH_WEBAUTHN_VERIFIER_WASM)?,
            vec![],
        )?;
        upload(&wasm.account)?;
        let factory = create(
            &operator,
            [2; 32],
            upload(&wasm.factory)?,
            vec![account_val(&pk(&operator))],
        )?;
        local::invoke(
            &rpc,
            &operator,
            &invoke(
                &factory,
                "set_registry_pins",
                vec![contract_val(&verifier)?],
            ),
            None,
        )
        .map_err(|e| format!("pinning the verifier: {e}"))?;
        let grant_signer_hash = upload(nido_integration_tests::GRANT_SIGNER_WASM)?;
        let dapp_hash = upload(&wasm.dapp)?;
        let deployer_hash = upload(&wasm.deployer)?;
        eprintln!("network: stack deployed (registry {registry}, factory {factory})");

        let custody = Custody {
            mock: MockServer::start(
                &MockConfig::default()
                    .with_key(CUSTODY_KEY, key(run, "custody").to_bytes())
                    .with_token(
                        DFNS_TOKEN,
                        DFNS_USER,
                        DFNS_CRED,
                        &key(run, "credential").verifying_key(),
                    ),
                "127.0.0.1:0",
            )
            .map_err(|e| format!("the Dfns mock: {e}"))?,
            key: key(run, "custody"),
            credential: key(run, "credential"),
        };
        let mut channel_keys = Vec::new();
        for i in 0..channels {
            let c = key(run, &format!("channel-{i}"));
            quickstart.fund(&stellar::account_strkey(&pk(&c)))?;
            local::hand_to_custody(&rpc, &c, &pk(&custody.key))?;
            channel_keys.push(pk(&c));
        }
        eprintln!("network: {channels} channels handed to the custody key");

        let version = rpc
            .call("getVersionInfo", &json!({}))
            .map_err(|e| e.to_string())?;
        let network = rpc
            .call("getNetwork", &json!({}))
            .map_err(|e| e.to_string())?;
        let docker = std::process::Command::new("docker")
            .args([
                "info",
                "--format",
                "{{.ServerVersion}} on {{.OperatingSystem}}, {{.NCPU}} CPUs, {{.MemTotal}} bytes",
            ])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        let cpu = std::process::Command::new("sysctl")
            .args(["-n", "machdep.cpu.brand_string"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default();
        let conditions = json!({
            "machine_cpu": cpu,
            "docker": docker,
            "quickstart": local::QUICKSTART,
            "network_passphrase": PASSPHRASE,
            "protocol_version": network.get("protocolVersion"),
            "rpc_version": version.get("version"),
            "core_version": version.get("captiveCoreVersion"),
            "setup_seconds": started.elapsed().as_secs_f64(),
            "channels": channels,
            "registry": registry,
            "factory": factory,
            "verifier": verifier,
        });
        Ok(Self {
            quickstart,
            rpc,
            operator,
            run,
            counter: AtomicU32::new(0),
            verifier,
            factory,
            grant_signer_hash,
            dapp_hash,
            deployer_hash,
            custody,
            channels: channel_keys,
            mode: Mutex::new(Mode::Mirrored),
            relay: Mutex::new(None),
            conditions,
        })
    }

    /// A fresh 32-byte value for salts, unique in this run.
    #[must_use]
    pub fn salt(&self, label: &str) -> [u8; 32] {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut h = Sha256::new();
        h.update(self.run);
        h.update(n.to_be_bytes());
        h.update(label.as_bytes());
        h.finalize().into()
    }

    /// A funded account for `label`, unique in this run.
    ///
    /// # Errors
    ///
    /// If friendbot does not fund it.
    pub fn funded(&self, label: &str) -> Result<SigningKey, String> {
        let k = SigningKey::from_bytes(&self.salt(label));
        self.quickstart.fund(&stellar::account_strkey(&pk(&k)))?;
        Ok(k)
    }

    #[must_use]
    pub fn mode(&self) -> Mode {
        *self.mode.lock().expect("mode")
    }

    pub fn set_mode(&self, mode: Mode) {
        *self.mode.lock().expect("mode") = mode;
        *self.relay.lock().expect("relay") = None;
    }

    /// The latest ledger.
    ///
    /// # Errors
    ///
    /// If RPC does not answer.
    pub fn ledger(&self) -> Result<u32, String> {
        let r = self
            .rpc
            .call("getLatestLedger", &json!({}))
            .map_err(|e| e.to_string())?;
        r.get("sequence")
            .and_then(Value::as_u64)
            .and_then(|s| u32::try_from(s).ok())
            .ok_or_else(|| "getLatestLedger: no sequence".into())
    }

    /// Simulate `func` from the operator and return its result: a read of
    /// the chain's current state. A [`local::transient`] error is retried.
    ///
    /// # Errors
    ///
    /// The simulation's error.
    pub fn read(&self, func: &HostFunction) -> Result<ScVal, String> {
        let mut tries = 0;
        loop {
            match self.read_once(func) {
                Err(e) if local::transient(&e) && tries < 10 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
                other => return other,
            }
        }
    }

    fn read_once(&self, func: &HostFunction) -> Result<ScVal, String> {
        let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
            tx: local::tx(
                &pk(&self.operator),
                0,
                100,
                OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                    host_function: func.clone(),
                    auth: Vec::new().try_into().expect("empty"),
                }),
                TransactionExt::V0,
            ),
            signatures: Vec::new().try_into().expect("empty"),
        });
        let b64 = envelope
            .to_xdr_base64(Limits::none())
            .map_err(|e| e.to_string())?;
        let r = self
            .rpc
            .call(
                "simulateTransaction",
                &json!({ "transaction": b64, "authMode": "record" }),
            )
            .map_err(|e| e.to_string())?;
        if let Some(e) = r.get("error").and_then(Value::as_str) {
            return Err(e.to_owned());
        }
        let xdr = r
            .pointer("/results/0/xdr")
            .and_then(Value::as_str)
            .ok_or("simulateTransaction: no result")?;
        ScVal::from_xdr_base64(xdr, Limits::none()).map_err(|e| e.to_string())
    }

    /// Send `func` from the operator: with `auth`, carrying exactly those
    /// entries; without, the operator's own authorization.
    ///
    /// # Errors
    ///
    /// The simulation's error or the transaction's failure.
    pub fn setup(
        &self,
        func: &HostFunction,
        auth: Option<Vec<SorobanAuthorizationEntry>>,
    ) -> Result<(), String> {
        local::invoke(&self.rpc, &self.operator, func, auth).map(|_| ())
    }

    /// Send `func` from `key`'s account with its recorded authorization.
    ///
    /// # Errors
    ///
    /// The simulation's error or the transaction's failure.
    pub fn send_as(&self, key: &SigningKey, func: &HostFunction) -> Result<(), String> {
        local::invoke(&self.rpc, key, func, None).map(|_| ())
    }

    /// Deploy `code` with the operator as deployer and `args` to its
    /// constructor; returns its address.
    ///
    /// # Errors
    ///
    /// If the creation fails.
    pub fn deploy(&self, label: &str, code: [u8; 32], args: Vec<ScVal>) -> Result<String, String> {
        let preimage = ContractIdPreimage::Address(ContractIdPreimageFromAddress {
            address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk(
                &self.operator,
            ))))),
            salt: Uint256(self.salt(label)),
        });
        let address = local::contract_id(preimage.clone());
        self.setup(
            &HostFunction::CreateContractV2(CreateContractArgsV2 {
                contract_id_preimage: preimage,
                executable: ContractExecutable::Wasm(Hash(code)),
                constructor_args: args.try_into().map_err(|_| "too many arguments")?,
            }),
            None,
        )
        .map_err(|e| format!("deploying {label}: {e}"))?;
        Ok(address)
    }

    /// A credit asset `code` issued by a fresh account, its Stellar Asset
    /// Contract deployed, and `amount` minted to each of `holders` (contract
    /// addresses, which hold the asset without a trustline). Returns the
    /// asset contract's address and the asset.
    ///
    /// # Errors
    ///
    /// If a step fails.
    pub fn asset(
        &self,
        code: &str,
        holders: &[String],
        amount: i128,
    ) -> Result<(String, AlphaNum4), String> {
        let issuer = self.funded(&format!("issuer/{code}"))?;
        let mut c = [0u8; 4];
        c[..code.len().min(4)].copy_from_slice(&code.as_bytes()[..code.len().min(4)]);
        let asset = AlphaNum4 {
            asset_code: AssetCode4(c),
            issuer: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk(&issuer)))),
        };
        let preimage = ContractIdPreimage::Asset(Asset::CreditAlphanum4(asset.clone()));
        let address = local::contract_id(preimage.clone());
        self.setup(
            &HostFunction::CreateContract(CreateContractArgs {
                contract_id_preimage: preimage,
                executable: ContractExecutable::StellarAsset,
            }),
            None,
        )
        .map_err(|e| format!("deploying the {code} asset contract: {e}"))?;
        for holder in holders {
            self.send_as(
                &issuer,
                &invoke(
                    &address,
                    "mint",
                    vec![contract_val(holder)?, i128_val(amount)],
                ),
            )
            .map_err(|e| format!("minting {code} to {holder}: {e}"))?;
        }
        Ok((address, asset))
    }

    /// Create `key`'s account if it does not exist, and give it a trustline
    /// for `asset`.
    ///
    /// # Errors
    ///
    /// If the trustline is not created.
    pub fn trustline(&self, key: &SigningKey, asset: &AlphaNum4) -> Result<(), String> {
        let account = pk(key);
        if self
            .quickstart
            .fund(&stellar::account_strkey(&account))
            .is_err()
        {
            local::sequence(&self.rpc, &account)?;
        }
        let op = OperationBody::ChangeTrust(ChangeTrustOp {
            line: ChangeTrustAsset::CreditAlphanum4(asset.clone()),
            limit: i64::MAX,
        });
        let seq = local::sequence(&self.rpc, &account)? + 1;
        local::sign_and_send(
            &self.rpc,
            key,
            local::tx(&account, seq, 100, op, TransactionExt::V0),
        )
        .map(|_| ())
    }

    /// The relay agent calls go through, for `agents`: the running one when
    /// it was started for the same agents, otherwise a new one.
    ///
    /// # Errors
    ///
    /// If a new relay does not start.
    pub fn relay_for(&self, agents: &[relay::AgentSpec]) -> Result<relay::Handle, String> {
        let mut current = self.relay.lock().expect("relay");
        if let Some(r) = current.as_ref() {
            if r.agents == agents {
                return Ok(r.handle());
            }
        }
        // Two channels: agent calls are sequential, and a second channel
        // shows that the lease, not the pool's size, keeps them apart.
        let running = relay::Running::start(self, agents, &self.channels[..2], 4)?;
        let handle = running.handle();
        *current = Some(running);
        Ok(handle)
    }

    /// The channels' sequence numbers, by `G…` strkey.
    ///
    /// # Errors
    ///
    /// If RPC does not answer.
    pub fn channel_sequences(&self) -> Result<Vec<(String, i64)>, String> {
        self.channels
            .iter()
            .map(|c| Ok((stellar::account_strkey(c), local::sequence(&self.rpc, c)?)))
            .collect()
    }
}

/// `contract.f(args)` as a host function.
///
/// # Panics
///
/// If `contract` is not a contract strkey or `f` not a symbol.
#[must_use]
pub fn invoke(contract: &str, f: &str, args: Vec<ScVal>) -> HostFunction {
    HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: contract.parse().expect("a contract strkey"),
        function_name: ScSymbol(f.try_into().expect("a symbol")),
        args: args.try_into().expect("arguments fit"),
    })
}

fn bytes32(b: [u8; 32]) -> ScVal {
    ScVal::Bytes(b.to_vec().try_into().expect("32 bytes"))
}

fn account_val(key: &[u8; 32]) -> ScVal {
    ScVal::Address(ScAddress::Account(AccountId(
        PublicKey::PublicKeyTypeEd25519(Uint256(*key)),
    )))
}

fn contract_val(strkey: &str) -> Result<ScVal, String> {
    Ok(ScVal::Address(
        strkey.parse().map_err(|e| format!("{strkey}: {e:?}"))?,
    ))
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn i128_val(n: i128) -> ScVal {
    ScVal::I128(soroban_sdk::xdr::Int128Parts {
        hi: (n >> 64) as i64,
        lo: n as u64,
    })
}

/// Run the local-network stage: the attack suite and the workloads through
/// the relay in each [`Mode`], relay throughput against the channel pool's
/// size, and sibling sub-agents spending concurrently against a shared
/// ancestor's allowance. Writes `network-*.json` to `out`.
///
/// # Errors
///
/// If the network cannot be set up or a result cannot be written.
pub fn run(wasm: &Wasm, out: &Path, quick: bool) -> Result<(), String> {
    let net = std::sync::Arc::new(Net::start(wasm, 8)?);
    let mut attacks = Vec::new();
    let mut workloads = Vec::new();
    for mode in [Mode::Mirrored, Mode::PassThrough] {
        net.set_mode(mode);
        let fixture = |label: &str, dapps: usize, extra| {
            crate::soroban::fixture::Fixture::on_network(&net, label, dapps, extra)
        };
        let rows = crate::soroban::attacks::run(&fixture);
        eprintln!("network ({mode:?}): {} attack rows", rows.len());
        attacks.push(json!({ "mode": mode, "rows": rows }));
        let mut all = Vec::new();
        for w in crate::workloads::all() {
            all.extend(crate::soroban::workloads::run(&fixture, &w));
        }
        eprintln!("network ({mode:?}): {} workload calls", all.len());
        workloads.push(json!({ "mode": mode, "rows": all }));
    }
    net.set_mode(Mode::Mirrored);
    record::write(out, "network-attacks.json", &attacks)?;
    record::write(out, "network-workloads.json", &workloads)?;

    let race = throughput::race(&net)?;
    record::write(out, "network-race.json", &race)?;
    let tput = throughput::sweep(&net, quick)?;
    record::write(out, "network-throughput.json", &tput)?;
    record::write(out, "network.json", &net.conditions)?;
    Ok(())
}
