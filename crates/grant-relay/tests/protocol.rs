//! The `/relay` protocol over HTTP, pinned to Nido's browser client
//! (`packages/passkey-sdk/src/relayer.ts`).
//!
//! Requests are the bodies that client builds (`JSON.stringify({ params })`
//! with `Content-Type: application/json`). Responses are judged by
//! [`client_call`], a line-by-line port of its `call()`, and
//! [`client_wait`], a port of its `waitForConfirmation` loop. The
//! `frontend_client` test runs the TypeScript client itself.

mod common;

use std::time::Duration;

use common::*;
use grant_relay::{Relay, Server};
use serde_json::{json, Value};

struct Harness {
    server: Server,
    agent: ureq::Agent,
    _relay: Relay<SharedKeeper, FakeNetwork>,
    keeper: SharedKeeper,
}

fn start(net: &FakeNetwork) -> Harness {
    let (relay, keeper) = relay(net);
    let server = Server::start(&relay, "127.0.0.1:0", 4).expect("server starts");
    let agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    Harness {
        server,
        agent,
        _relay: relay,
        keeper,
    }
}

/// An HTTP response: status, headers we read, body.
struct Reply {
    status: u16,
    allow_origin: Option<String>,
    headers: Vec<(String, String)>,
    body: String,
}

impl Harness {
    fn post(&self, path: &str, api_key: Option<&str>, body: &str) -> Reply {
        let mut request = self
            .agent
            .post(format!("{}{path}", self.server.url()))
            .header("Content-Type", "application/json");
        if let Some(k) = api_key {
            request = request.header("x-api-key", k);
        }
        reply(request.send(body))
    }

    fn request(&self, method: &str, path: &str) -> Reply {
        let url = format!("{}{path}", self.server.url());
        let request = ureq::http::Request::builder()
            .method(method)
            .uri(url)
            .body(())
            .unwrap();
        reply(self.agent.run(request))
    }

    /// `submitSorobanTransaction({func, auth})` against base URL `base`.
    fn submit(&self, base: &str, api_key: Option<&str>, func: &str, auth: &[String]) -> Reply {
        // `call({ func, auth, skipWait: args.skipWait ?? true })`, then
        // `JSON.stringify({ params })`.
        let body = json!({ "params": { "func": func, "auth": auth, "skipWait": true } });
        self.post(&format!("{base}/relay"), api_key, &body.to_string())
    }

    /// `getRelayerTransaction(transactionId)`.
    fn get(&self, base: &str, api_key: Option<&str>, id: &str) -> Reply {
        let body = json!({ "params": { "getTransaction": { "transactionId": id } } });
        self.post(&format!("{base}/relay"), api_key, &body.to_string())
    }
}

fn reply(response: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Reply {
    let mut response = response.expect("the server answers");
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("").to_owned()))
        .collect::<Vec<_>>();
    let allow_origin = response
        .headers()
        .get("access-control-allow-origin")
        .map(|v| v.to_str().unwrap().to_owned());
    Reply {
        status: response.status().as_u16(),
        allow_origin,
        headers,
        body: response.body_mut().read_to_string().unwrap_or_default(),
    }
}

/// What `relayer.ts`'s `call()` returns or throws.
#[derive(Debug, PartialEq)]
enum ClientResult {
    /// `RelayerTxResponse`.
    Ok {
        transaction_id: Option<String>,
        hash: Option<String>,
        status: Option<String>,
    },
    /// `RelayerError(message, code, details)`.
    Err {
        message: String,
        code: Option<String>,
        details: Value,
    },
}

/// A port of `call()` in `packages/passkey-sdk/src/relayer.ts`.
fn client_call(reply: &Reply) -> ClientResult {
    let ok = (200..300).contains(&reply.status);
    let err = |message: String, code: Option<String>, details: Value| ClientResult::Err {
        message,
        code,
        details,
    };
    // `body = (await resp.json()) ?? {}`, or "Relayer returned non-JSON".
    let Ok(body) = serde_json::from_str::<Value>(&reply.body) else {
        return err(
            format!("Relayer returned non-JSON (HTTP {})", reply.status),
            None,
            Value::Null,
        );
    };
    let body = if body.is_null() { json!({}) } else { body };
    let error = body.get("error").filter(|e| !e.is_null());
    // `if (body.success === false || (!resp.ok && body.error))`
    if body.get("success") == Some(&Value::Bool(false)) || (!ok && error.is_some()) {
        let data = body.get("data");
        return err(
            error
                .and_then(Value::as_str)
                .map_or_else(|| format!("Relayer HTTP {}", reply.status), str::to_owned),
            data.and_then(|d| d.get("code"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            data.and_then(|d| d.get("details"))
                .cloned()
                .unwrap_or(Value::Null),
        );
    }
    if !ok {
        return err(format!("Relayer HTTP {}", reply.status), None, Value::Null);
    }
    // `payload = data?.result ?? data`
    let data = body.get("data");
    let payload = data
        .and_then(|d| d.get("result"))
        .filter(|r| !r.is_null())
        .or(data);
    let Some(payload) = payload.and_then(Value::as_object) else {
        return err(
            "Relayer returned an empty payload".into(),
            None,
            Value::Null,
        );
    };
    if !payload.contains_key("transactionId") && !payload.contains_key("status") {
        return err("Unrecognized relayer payload".into(), None, body.clone());
    }
    let s = |k: &str| payload.get(k).and_then(Value::as_str).map(str::to_owned);
    ClientResult::Ok {
        transaction_id: s("transactionId"),
        hash: s("hash"),
        status: s("status"),
    }
}

/// A port of `waitForConfirmation`: poll until `confirmed` (returned),
/// `failed` / `expired` (`ONCHAIN_FAILED`), or attempts run out.
fn client_wait(
    h: &Harness,
    base: &str,
    api_key: Option<&str>,
    id: &str,
) -> Result<ClientResult, String> {
    for _ in 0..55 {
        let result = client_call(&h.get(base, api_key, id));
        if let ClientResult::Ok { status, .. } = &result {
            match status.as_deref() {
                Some("confirmed") => return Ok(result),
                Some("failed" | "expired") => return Err("ONCHAIN_FAILED".into()),
                _ => {}
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("WAIT_TIMEOUT".into())
}

fn transfer_b64(amount: i128) -> (String, Vec<String>) {
    let (func, auth) = transfer(amount);
    (b64(&func), auth.iter().map(b64).collect())
}

#[test]
fn the_browser_flow_submits_then_polls_to_confirmed() {
    let net = FakeNetwork::new();
    let h = start(&net);
    let (func, auth) = transfer_b64(10);

    let submitted = h.submit("", Some(PAYER), &func, &auth);
    assert_eq!(submitted.status, 200);
    assert_eq!(submitted.allow_origin.as_deref(), Some("*"));
    let ClientResult::Ok {
        transaction_id: Some(id),
        hash: Some(hash),
        status: Some(status),
    } = client_call(&submitted)
    else {
        panic!("the client rejects {}", submitted.body);
    };
    assert_eq!(status, "submitted");
    assert_eq!(hash.len(), 64);

    // `relayerSubmitAndConfirm` needs a transaction id, then a hash on the
    // confirmed poll.
    let confirmed = client_wait(&h, "", Some(PAYER), &id).unwrap();
    let ClientResult::Ok {
        hash: Some(confirmed_hash),
        status: Some(status),
        transaction_id: Some(confirmed_id),
    } = confirmed
    else {
        panic!("no hash on confirmation")
    };
    assert_eq!(status, "confirmed");
    assert_eq!(confirmed_hash, hash);
    assert_eq!(confirmed_id, id);
}

#[test]
fn the_response_bodies_have_the_documented_shape() {
    let net = FakeNetwork::new();
    let h = start(&net);
    let (func, auth) = transfer_b64(10);
    let body: Value = serde_json::from_str(&h.submit("", Some(PAYER), &func, &auth).body).unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["error"], Value::Null);
    let data = body["data"].as_object().unwrap();
    let mut keys: Vec<&str> = data.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["hash", "status", "transactionId"]);

    let (func, auth) = transfer_b64(5000);
    let reply = h.submit("", Some(PAYER), &func, &auth);
    assert_eq!(reply.status, 403);
    let body: Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(body["success"], false);
    assert!(body["error"].is_string());
    assert_eq!(body["data"]["code"], "GRANT_DENIED");
    assert!(body["data"]["details"].is_object());
}

#[test]
fn a_denial_reaches_the_client_as_a_relayer_error_with_its_code() {
    let net = FakeNetwork::new();
    let h = start(&net);
    let (func, auth) = forward(10);
    let auth: Vec<String> = auth.iter().map(b64).collect();
    let reply = h.submit("", Some(FORWARDER_ONLY), &b64(&func), &auth);
    let ClientResult::Err {
        message,
        code,
        details,
    } = client_call(&reply)
    else {
        panic!("the client accepted a denial")
    };
    assert_eq!(code.as_deref(), Some("GRANT_DENIED"));
    assert!(message.contains("transfer"), "{message}");
    assert_eq!(details["tree"], "supplied");
    assert_eq!(h.keeper.requests(), 0);
    assert!(net.sent().is_empty());
}

#[test]
fn the_api_key_can_ride_in_the_base_url() {
    // The client takes only a base URL and POSTs to `${baseUrl}/relay`.
    let net = FakeNetwork::new();
    let h = start(&net);
    let base = format!("/agents/{PAYER}");
    let (func, auth) = transfer_b64(10);
    let reply = h.submit(&base, None, &func, &auth);
    let ClientResult::Ok {
        transaction_id: Some(id),
        ..
    } = client_call(&reply)
    else {
        panic!("{}", reply.body)
    };
    assert!(client_wait(&h, &base, None, &id).is_ok());

    // A status read through the plain route with the same key also works,
    // and a different key in the header is refused.
    assert!(matches!(
        client_call(&h.get("", Some(PAYER), &id)),
        ClientResult::Ok { .. }
    ));
    let reply = h.get(&base, Some(FORWARDER_ONLY), &id);
    assert_eq!(reply.status, 401);
}

#[test]
fn requests_without_a_known_key_are_refused() {
    let net = FakeNetwork::new();
    let h = start(&net);
    let (func, auth) = transfer_b64(10);
    for reply in [
        h.submit("", None, &func, &auth),
        h.submit("", Some("wrong"), &func, &auth),
        h.submit("/agents/wrong", None, &func, &auth),
    ] {
        assert_eq!(reply.status, 401);
        let ClientResult::Err { code, .. } = client_call(&reply) else {
            panic!()
        };
        assert_eq!(code.as_deref(), Some("UNAUTHORIZED"));
    }
}

#[test]
fn the_preflight_matches_the_caddy_front() {
    let net = FakeNetwork::new();
    let h = start(&net);
    for path in ["/relay", "/agents/anything/relay"] {
        let reply = h.request("OPTIONS", path);
        assert_eq!(reply.status, 204);
        let header = |name: &str| {
            reply
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(header("access-control-allow-origin").as_deref(), Some("*"));
        assert_eq!(
            header("access-control-allow-methods").as_deref(),
            Some("POST, OPTIONS")
        );
        assert_eq!(
            header("access-control-allow-headers").as_deref(),
            Some("Content-Type")
        );
        assert_eq!(header("access-control-max-age").as_deref(), Some("86400"));
    }
}

#[test]
fn health_and_unknown_routes() {
    let net = FakeNetwork::new();
    let h = start(&net);
    let reply = h.request("GET", "/api/v1/health");
    assert_eq!(reply.status, 200);
    assert_eq!(
        serde_json::from_str::<Value>(&reply.body).unwrap()["status"],
        "ok"
    );
    assert_eq!(h.request("GET", "/nope").status, 404);
    assert_eq!(h.request("GET", "/relay").status, 405);
}

#[test]
fn malformed_requests_are_invalid_params() {
    let net = FakeNetwork::new();
    let h = start(&net);
    let (func, auth) = transfer_b64(10);
    let cases = [
        "not json".to_owned(),
        json!({}).to_string(),
        json!({ "params": "x" }).to_string(),
        json!({ "params": { "func": func } }).to_string(),
        json!({ "params": { "func": "!!", "auth": [] } }).to_string(),
        json!({ "params": { "func": func, "auth": ["!!"] } }).to_string(),
        json!({ "params": { "func": func, "auth": auth, "skipWait": "yes" } }).to_string(),
        json!({ "params": { "func": func, "auth": auth, "extra": 1 } }).to_string(),
        json!({ "params": { "xdr": "AAAA" } }).to_string(),
        json!({ "params": { "getTransaction": { "transactionId": "" } } }).to_string(),
        json!({ "params": { "getTransaction": { "transactionId": "a", "x": 1 } } }).to_string(),
        json!({ "params": { "getTransaction": { "transactionId": "a" }, "func": func } })
            .to_string(),
    ];
    for body in cases {
        let reply = h.post("/relay", Some(PAYER), &body);
        assert_eq!(reply.status, 400, "{body}");
        let ClientResult::Err { code, .. } = client_call(&reply) else {
            panic!("{body}")
        };
        assert_eq!(code.as_deref(), Some("INVALID_PARAMS"), "{body}");
    }
    assert!(net.sent().is_empty());
}

#[test]
fn an_oversized_body_is_refused() {
    let net = FakeNetwork::new();
    let h = start(&net);
    let body = format!("{{\"params\":{{\"func\":\"{}\"}}}}", "A".repeat(300 * 1024));
    let reply = h.post("/relay", Some(PAYER), &body);
    assert_eq!(reply.status, 413);
}

#[test]
fn an_unknown_transaction_is_a_relayer_error() {
    let net = FakeNetwork::new();
    let h = start(&net);
    let reply = h.get("", Some(PAYER), "nope");
    assert_eq!(reply.status, 404);
    let ClientResult::Err { code, .. } = client_call(&reply) else {
        panic!()
    };
    assert_eq!(code.as_deref(), Some("NOT_FOUND"));
}
