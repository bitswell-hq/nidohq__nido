//! The relay end to end on a local Stellar network, signing through the
//! Dfns client against the local Dfns mock.
//!
//! Needs Docker (it starts `stellar/quickstart` in local mode with Soroban
//! RPC) and builds the forwarder test contract for `wasm32v1-none`, so it is
//! ignored by default:
//!
//! ```sh
//! cargo test -p grant-relay --test local_network -- --ignored --nocapture
//! ```
//!
//! With `GRANT_RELAY_QUICKSTART_URL` set (for example
//! `http://localhost:8000`), it uses that already running quickstart instead
//! of starting one.
//!
//! The test funds two channel accounts and hands them to the custody key
//! (master weight 0, custody key the only signer), deploys the native asset
//! contract and the forwarder, and then sends `/relay` requests the way the
//! browser does: a recording simulation for the call, the user's signature
//! on each authorization entry, and `{func, auth}` to the relay.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer as _, SigningKey};
use grant_relay::local::{
    self, contract_id, hand_to_custody, http, network_id, pk, tx, Quickstart, PASSPHRASE,
};
use grant_relay::rpc::{AuthMode, HttpRpc, Lookup, SorobanRpc};
use grant_relay::{Config, ConfigFile, Relay, Server};
use nido_key_keeper::dfns::mock::{MockConfig, MockServer};
use nido_key_keeper::dfns::{DfnsConfig, DfnsKeyKeeper, KeyCredential};
use nido_key_keeper::{stellar, KeyId, KeyKeeper, Payload, SignError, Signature};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    Asset, ContractExecutable, ContractIdPreimage, ContractIdPreimageFromAddress,
    CreateContractArgs, CreateContractArgsV2, Hash, HashIdPreimage,
    HashIdPreimageSorobanAuthorization, HostFunction, Int128Parts, InvokeContractArgs,
    InvokeHostFunctionOp, Limits, OperationBody, ReadXdr, ScAddress, ScBytes, ScMap, ScMapEntry,
    ScSymbol, ScVal, ScVec, SorobanAuthorizationEntry, SorobanCredentials, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, WriteXdr,
};

const DFNS_TOKEN: &str = "local-service-account-token";
const DFNS_USER: &str = "us-3k8s2-q0pde-4hn2bq7k4u1c8a9f";
const DFNS_CRED: &str = "cr-6tq9a-1m2kd-8s7f0d3l5p2h4j6k";
const CUSTODY_KEY: &str = "key-01snl-t56gb-j8tsok0vn802p80i";

const PAYER: &str = "payer-key";
const FORWARDER_ONLY: &str = "forwarder-only-key";
const FORWARDER_AND_TOKEN: &str = "forwarder-and-token-key";

fn seeded(n: u8) -> SigningKey {
    let mut seed = [n; 32];
    // Distinct per run, so a reused quickstart starts from fresh accounts.
    getrandom::getrandom(&mut seed[..16]).unwrap();
    SigningKey::from_bytes(&seed)
}

// ---------------------------------------------------------------------------
// The local network (`grant_relay::local`)

fn network() -> Quickstart {
    if let Ok(base) = std::env::var("GRANT_RELAY_QUICKSTART_URL") {
        Quickstart::existing(&base)
    } else {
        let mut id = [0u8; 4];
        getrandom::getrandom(&mut id).unwrap();
        Quickstart::start(&format!("grant-relay-e2e-{}", hex::encode(id)))
    }
    .expect("the local network starts")
}

fn sequence(rpc: &HttpRpc, account: &[u8; 32]) -> i64 {
    local::sequence(rpc, account).expect("the account exists")
}

/// Run `func` with `key`'s account as source, using the recorded
/// authorization. An `Err` is the simulation's error.
fn invoke_as(rpc: &HttpRpc, key: &SigningKey, func: &HostFunction) -> Result<(), String> {
    local::invoke(rpc, key, func, None).map(|_| ())
}

fn forwarder_wasm() -> Vec<u8> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let manifest = root.join("tests/fixtures/forwarder/Cargo.toml");
    let target = root.join("../../target/grant-relay-forwarder");
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([
            "build",
            "--release",
            "--target",
            "wasm32v1-none",
            "--manifest-path",
        ])
        .arg(&manifest)
        .arg("--target-dir")
        .arg(&target)
        .status()
        .expect("cargo runs");
    assert!(status.success(), "the forwarder builds");
    std::fs::read(target.join("wasm32v1-none/release/grant_relay_forwarder.wasm")).unwrap()
}

// ---------------------------------------------------------------------------
// The browser's side: simulate, sign the entries, post {func, auth}

fn address(strkey: &str) -> ScAddress {
    strkey.parse().unwrap()
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn amount(n: i128) -> ScVal {
    ScVal::I128(Int128Parts {
        hi: (n >> 64) as i64,
        lo: n as u64,
    })
}

fn invoke(contract: &str, function: &str, args: Vec<ScVal>) -> HostFunction {
    HostFunction::InvokeContract(InvokeContractArgs {
        contract_address: address(contract),
        function_name: ScSymbol(function.try_into().unwrap()),
        args: args.try_into().unwrap(),
    })
}

/// Record the call's authorization (from `sim_source`, as the frontend
/// simulates from a relayer-provided source) and sign each entry as `user`.
fn browser_request(
    rpc: &HttpRpc,
    sim_source: &[u8; 32],
    user: &SigningKey,
    func: &HostFunction,
) -> (String, Vec<String>) {
    let draft = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx(
            sim_source,
            1,
            100,
            OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
                host_function: func.clone(),
                auth: Vec::new().try_into().unwrap(),
            }),
            TransactionExt::V0,
        ),
        signatures: Vec::new().try_into().unwrap(),
    });
    let sim = rpc.simulate(&draft, AuthMode::Record).unwrap();
    let latest = sim.latest_ledger;
    let entries = sim.outcome.expect("the browser's simulation succeeds").auth;
    let auth = entries
        .into_iter()
        .map(|mut entry| {
            let SorobanCredentials::Address(creds) = &mut entry.credentials else {
                panic!("expected address credentials")
            };
            creds.signature_expiration_ledger = latest + 100;
            let payload =
                HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
                    network_id: Hash(network_id()),
                    nonce: creds.nonce,
                    signature_expiration_ledger: creds.signature_expiration_ledger,
                    invocation: entry.root_invocation.clone(),
                });
            let digest: [u8; 32] = Sha256::digest(payload.to_xdr(Limits::none()).unwrap()).into();
            let signature = user.sign(&digest).to_bytes();
            let map = ScMap(
                vec![
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("public_key".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(pk(user).to_vec().try_into().unwrap())),
                    },
                    ScMapEntry {
                        key: ScVal::Symbol(ScSymbol("signature".try_into().unwrap())),
                        val: ScVal::Bytes(ScBytes(signature.to_vec().try_into().unwrap())),
                    },
                ]
                .try_into()
                .unwrap(),
            );
            creds.signature =
                ScVal::Vec(Some(ScVec(vec![ScVal::Map(Some(map))].try_into().unwrap())));
            entry.to_xdr_base64(Limits::none()).unwrap()
        })
        .collect();
    (func.to_xdr_base64(Limits::none()).unwrap(), auth)
}

/// POST `body` to `/agents/{api_key}/relay`, returning status and JSON body.
fn post(server: &Server, api_key: &str, body: &Value) -> (u16, Value) {
    let mut response = http()
        .post(format!("{}/agents/{api_key}/relay", server.url()))
        .header("Content-Type", "application/json")
        .send(body.to_string())
        .expect("the relay answers");
    let status = response.status().as_u16();
    let body = response.body_mut().read_to_string().unwrap();
    (status, serde_json::from_str(&body).expect("JSON body"))
}

fn relay_call(server: &Server, api_key: &str, func: &str, auth: &[String]) -> (u16, Value) {
    post(
        server,
        api_key,
        &json!({ "params": { "func": func, "auth": auth, "skipWait": true } }),
    )
}

/// Poll `getTransaction` as `waitForConfirmation` does, until a terminal
/// status.
fn wait_for(server: &Server, api_key: &str, id: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let (status, body) = post(
            server,
            api_key,
            &json!({ "params": { "getTransaction": { "transactionId": id } } }),
        );
        assert_eq!(status, 200, "{body}");
        let s = body["data"]["status"].as_str().unwrap();
        if s != "submitted" {
            return body["data"].clone();
        }
        assert!(Instant::now() < deadline, "never settled");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Counts the keeper's sign calls.
struct Counting<K> {
    inner: K,
    calls: Arc<AtomicUsize>,
}

impl<K: KeyKeeper> KeyKeeper for Counting<K> {
    fn sign(&self, key: &KeyId, payload: &Payload) -> Result<Signature, SignError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(key, payload)
    }
}

#[test]
#[ignore = "needs Docker"]
#[allow(clippy::too_many_lines)]
fn relays_allowed_calls_to_confirmation_and_never_signs_denied_ones() {
    let wasm = forwarder_wasm();
    let net = network();
    let rpc = HttpRpc::new(net.rpc_url());

    let custody = seeded(7);
    let credential = seeded(42);
    let channels = [seeded(11), seeded(12)];
    let user = seeded(21);
    let bob = seeded(33);
    for key in channels.iter().chain([&user, &bob]) {
        net.fund(&stellar::account_strkey(&pk(key)))
            .expect("friendbot funds");
    }
    for c in &channels {
        hand_to_custody(&rpc, c, &pk(&custody)).expect("the channel is handed over");
    }

    // The native asset contract and the forwarder.
    let sac_preimage = ContractIdPreimage::Asset(Asset::Native);
    let sac = contract_id(sac_preimage.clone());
    let deployed = invoke_as(
        &rpc,
        &user,
        &HostFunction::CreateContract(CreateContractArgs {
            contract_id_preimage: sac_preimage,
            executable: ContractExecutable::StellarAsset,
        }),
    );
    if let Err(e) = deployed {
        // A reused network may have it already.
        assert!(
            e.contains("ExistingValue"),
            "deploying the native asset contract: {e}"
        );
    }
    let wasm_hash: [u8; 32] = Sha256::digest(&wasm).into();
    invoke_as(
        &rpc,
        &user,
        &HostFunction::UploadContractWasm(wasm.try_into().unwrap()),
    )
    .unwrap();
    let forwarder_preimage = ContractIdPreimage::Address(ContractIdPreimageFromAddress {
        address: ScAddress::Account(stellar_xdr::AccountId(
            stellar_xdr::PublicKey::PublicKeyTypeEd25519(Uint256(pk(&user))),
        )),
        salt: Uint256([1; 32]),
    });
    let forwarder = contract_id(forwarder_preimage.clone());
    invoke_as(
        &rpc,
        &user,
        &HostFunction::CreateContractV2(CreateContractArgsV2 {
            contract_id_preimage: forwarder_preimage,
            executable: ContractExecutable::Wasm(Hash(wasm_hash)),
            constructor_args: Vec::new().try_into().unwrap(),
        }),
    )
    .unwrap();
    eprintln!("native asset contract {sac}, forwarder {forwarder}");

    // The Dfns mock holds the custody key; the relay signs through the Dfns
    // client.
    let mock = MockServer::start(
        &MockConfig::default()
            .with_key(CUSTODY_KEY, custody.to_bytes())
            .with_token(
                DFNS_TOKEN,
                DFNS_USER,
                DFNS_CRED,
                &credential.verifying_key(),
            ),
        "127.0.0.1:0",
    )
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let keeper = Counting {
        inner: DfnsKeyKeeper::new(DfnsConfig::new(
            mock.url(),
            DFNS_TOKEN,
            KeyCredential {
                cred_id: DFNS_CRED.into(),
                signing_key: credential.clone(),
            },
        )),
        calls: Arc::clone(&calls),
    };
    let signing = json!([
        { "key_in": [CUSTODY_KEY] },
        { "network_in": [PASSPHRASE] },
        { "payload_in": ["transaction"] }
    ]);
    let config: ConfigFile = serde_json::from_value(json!({
        "network_passphrase": PASSPHRASE,
        "rpc_url": net.rpc_url(),
        "custody": { "key_id": CUSTODY_KEY, "public_key": stellar::account_strkey(&pk(&custody)) },
        "channels": channels.iter().map(|c| stellar::account_strkey(&pk(c))).collect::<Vec<_>>(),
        "poll_interval_ms": 500,
        "agents": [
            {
                "name": "payer",
                "api_key_sha256": grant_relay::config::api_key_sha256(PAYER),
                "chain": [
                    { "contract_in": [sac] },
                    { "function_in": ["transfer"] },
                    { "arg_i128_at_most": [2, "1000"] }
                ],
                "signing": signing
            },
            {
                "name": "forwarder-only",
                "api_key_sha256": grant_relay::config::api_key_sha256(FORWARDER_ONLY),
                "chain": [{ "contract_in": [forwarder] }, { "function_in": ["forward"] }],
                "signing": signing
            },
            {
                "name": "forwarder-and-token",
                "api_key_sha256": grant_relay::config::api_key_sha256(FORWARDER_AND_TOKEN),
                "chain": [
                    { "contract_in": [forwarder, sac] },
                    { "function_in": ["forward", "transfer"] }
                ],
                "signing": signing
            }
        ]
    }))
    .unwrap();
    let config = Config::from_file(&config).unwrap();
    let relay = Relay::new(config, keeper, HttpRpc::new(net.rpc_url()));
    relay
        .check_channels()
        .expect("the channels belong to the custody key");
    let server = Server::start(&relay, "127.0.0.1:0", 8).unwrap();

    let user_addr = ScVal::Address(address(&stellar::account_strkey(&pk(&user))));
    let bob_addr = ScVal::Address(address(&stellar::account_strkey(&pk(&bob))));
    let transfer = |n| {
        invoke(
            &sac,
            "transfer",
            vec![user_addr.clone(), bob_addr.clone(), amount(n)],
        )
    };
    let forward = |n| {
        invoke(
            &forwarder,
            "forward",
            vec![
                ScVal::Address(address(&sac)),
                user_addr.clone(),
                bob_addr.clone(),
                amount(n),
            ],
        )
    };
    let seqs = || {
        channels
            .iter()
            .map(|c| sequence(&rpc, &pk(c)))
            .collect::<Vec<_>>()
    };
    let request = |func: &HostFunction| browser_request(&rpc, &pk(&bob), &user, func);

    // 1. An allowed transfer is signed through the Dfns mock and confirmed.
    let before = seqs();
    let (func, auth) = request(&transfer(1000));
    let (status, body) = relay_call(&server, PAYER, &func, &auth);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"]["status"], "submitted");
    let id = body["data"]["transactionId"].as_str().unwrap().to_owned();
    let settled = wait_for(&server, PAYER, &id);
    assert_eq!(settled["status"], "confirmed", "{settled}");
    let hash: [u8; 32] = hex::decode(settled["hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(
        rpc.transaction(&hash).unwrap(),
        Lookup::Success,
        "the chain agrees"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let after = seqs();
    assert_eq!(
        after.iter().sum::<i64>(),
        before.iter().sum::<i64>() + 1,
        "one channel used one sequence number"
    );

    // 2. Over the amount cap: denied, never signed.
    let (func, auth) = request(&transfer(1001));
    let (status, body) = relay_call(&server, PAYER, &func, &auth);
    assert_eq!(
        (status, &body["data"]["code"]),
        (403, &json!("GRANT_DENIED")),
        "{body}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the keeper was not called");

    // 3. forward is allowed, the transfer nested in its authorization tree
    // is not: denied, never signed.
    let (func, auth) = request(&forward(10));
    let (status, body) = relay_call(&server, FORWARDER_ONLY, &func, &auth);
    assert_eq!(
        (status, &body["data"]["code"]),
        (403, &json!("GRANT_DENIED")),
        "{body}"
    );
    assert_eq!(body["data"]["details"]["actionIndex"], 2, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap()
            .contains(&format!("{sac}.transfer")),
        "{body}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "the keeper was not called");
    assert_eq!(seqs(), after, "no sequence number was used");

    // 4. With both contexts allowed, the same call is relayed.
    let (status, body) = relay_call(&server, FORWARDER_AND_TOKEN, &func, &auth);
    assert_eq!(status, 200, "{body}");
    let id = body["data"]["transactionId"].as_str().unwrap().to_owned();
    assert_eq!(
        wait_for(&server, FORWARDER_AND_TOKEN, &id)["status"],
        "confirmed"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    // 5. A tampered authorization fails the enforcing simulation: refused
    // before signing, the channel freed and its sequence number unused.
    let before = seqs();
    let (func, mut auth) = request(&transfer(5));
    let mut entry = SorobanAuthorizationEntry::from_xdr_base64(&auth[0], Limits::none()).unwrap();
    if let SorobanCredentials::Address(c) = &mut entry.credentials {
        c.signature_expiration_ledger += 1;
    }
    auth[0] = entry.to_xdr_base64(Limits::none()).unwrap();
    let (status, body) = relay_call(&server, PAYER, &func, &auth);
    assert_eq!(
        (status, &body["data"]["code"]),
        (400, &json!("SIMULATION_FAILED")),
        "{body}"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2, "the keeper was not called");
    assert_eq!(relay.pool().in_use(), 0);
    assert_eq!(seqs(), before);

    // 6. Two requests at once go out on the two channels.
    let (f1, a1) = request(&transfer(3));
    let (f2, a2) = request(&transfer(4));
    let (r1, r2) = std::thread::scope(|s| {
        let h1 = s.spawn(|| relay_call(&server, PAYER, &f1, &a1));
        let h2 = s.spawn(|| relay_call(&server, PAYER, &f2, &a2));
        (h1.join().unwrap(), h2.join().unwrap())
    });
    for (status, body) in [&r1, &r2] {
        assert_eq!(*status, 200, "{body}");
        let id = body["data"]["transactionId"].as_str().unwrap();
        assert_eq!(wait_for(&server, PAYER, id)["status"], "confirmed");
    }
    let after = seqs();
    assert_eq!(
        after
            .iter()
            .zip(&before)
            .map(|(a, b)| a - b)
            .collect::<Vec<_>>(),
        vec![1, 1],
        "each channel used one sequence number"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 4);
}
