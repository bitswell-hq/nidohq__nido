//! Nido's TypeScript relay client (`packages/passkey-sdk/src/relayer.ts`)
//! against this relay over HTTP, with only its base URL pointed here.
//!
//! Needs Node 22.6 or later (`--experimental-transform-types` loads the
//! `.ts` source directly), so it is ignored by default:
//!
//! ```sh
//! cargo test -p grant-relay --test frontend_client -- --ignored
//! ```

mod common;

use std::path::PathBuf;
use std::process::Command;

use common::*;
use grant_relay::Server;
use serde_json::Value;

fn run_client(base_url: &str, func: &str, auth: &[String]) -> Value {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let relayer = root.join("../../packages/passkey-sdk/src/relayer.ts");
    let driver = root.join("tests/frontend-client.mjs");
    let output = Command::new("node")
        .args(["--experimental-transform-types", "--no-warnings"])
        .arg(&driver)
        .arg(relayer.canonicalize().expect("relayer.ts exists"))
        .arg(base_url)
        .arg(func)
        .arg(serde_json::to_string(auth).unwrap())
        .output()
        .expect("node runs");
    assert!(
        output.status.success(),
        "node failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("the driver prints JSON")
}

#[test]
#[ignore = "needs Node 22.6+"]
fn the_typescript_client_relays_to_confirmation() {
    let net = FakeNetwork::new();
    let (relay, keeper) = relay(&net);
    let server = Server::start(&relay, "127.0.0.1:0", 4).unwrap();
    let base = format!("{}/agents/{PAYER}", server.url());
    let (func, auth) = transfer(10);

    let out = run_client(
        &base,
        &b64(&func),
        &auth.iter().map(b64).collect::<Vec<_>>(),
    );
    assert_eq!(out["ok"], true, "{out}");
    assert_eq!(out["submitted"]["status"], "submitted");
    assert_eq!(out["confirmed"]["status"], "confirmed");
    assert_eq!(out["confirmed"]["hash"], out["submitted"]["hash"]);
    assert_eq!(keeper.requests(), 1);
}

#[test]
#[ignore = "needs Node 22.6+"]
fn the_typescript_client_sees_a_denial_as_a_relayer_error() {
    let net = FakeNetwork::new();
    let (relay, keeper) = relay(&net);
    let server = Server::start(&relay, "127.0.0.1:0", 4).unwrap();
    let base = format!("{}/agents/{FORWARDER_ONLY}", server.url());
    let (func, auth) = forward(10);

    let out = run_client(
        &base,
        &b64(&func),
        &auth.iter().map(b64).collect::<Vec<_>>(),
    );
    assert_eq!(out["ok"], false, "{out}");
    assert_eq!(out["name"], "RelayerError");
    assert_eq!(out["code"], "GRANT_DENIED");
    assert_eq!(out["details"]["actionIndex"], 2);
    assert_eq!(keeper.requests(), 0);
    assert!(net.sent().is_empty());
}
