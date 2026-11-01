//! The mock over raw HTTP: unauthenticated and malformed requests get the
//! documented statuses and error body. The user action flow here is written
//! out by hand from the Dfns reference, independently of `DfnsKeyKeeper`.

mod common;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use common::{credential_key, start_mock, CRED_ID, KEY, OTHER_KEY, TOKEN};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};

struct Http {
    base: String,
    agent: ureq::Agent,
}

impl Http {
    fn new(base: &str) -> Self {
        Self {
            base: base.to_owned(),
            agent: ureq::Agent::config_builder()
                .http_status_as_error(false)
                .build()
                .into(),
        }
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&str>,
    ) -> (u16, Value) {
        let url = format!("{}{path}", self.base);
        let response = if method == "GET" {
            let mut req = self.agent.get(&url);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            req.call()
        } else {
            let mut req = self.agent.post(&url);
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            req.content_type("application/json")
                .send(body.unwrap_or(""))
        };
        let mut response = response.expect("mock reachable");
        let status = response.status().as_u16();
        let text = response.body_mut().read_to_string().unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }

    /// The documented asymmetric-key user action flow for one request.
    fn user_action(&self, signer: &SigningKey, cred_id: &str, path: &str, body: &str) -> String {
        let bearer = format!("Bearer {TOKEN}");
        let init = json!({
            "userActionHttpMethod": "POST",
            "userActionHttpPath": path,
            "userActionPayload": body,
            "userActionServerKind": "Api",
        })
        .to_string();
        let (status, challenge) = self.send(
            "POST",
            "/auth/action/init",
            &[("Authorization", &bearer)],
            Some(&init),
        );
        assert_eq!(status, 200, "{challenge}");
        let client_data = json!({
            "type": "key.get",
            "challenge": challenge["challenge"],
        })
        .to_string();
        let complete = json!({
            "challengeIdentifier": challenge["challengeIdentifier"],
            "firstFactor": {
                "kind": "Key",
                "credentialAssertion": {
                    "credId": cred_id,
                    "clientData": URL_SAFE_NO_PAD.encode(&client_data),
                    "signature": URL_SAFE_NO_PAD.encode(signer.sign(client_data.as_bytes()).to_bytes()),
                },
            },
        })
        .to_string();
        let (status, token) = self.send(
            "POST",
            "/auth/action",
            &[("Authorization", &bearer)],
            Some(&complete),
        );
        assert_eq!(status, 200, "{token}");
        token["userAction"].as_str().unwrap().to_owned()
    }

    /// Generate Signature with a fresh user action for exactly `body`.
    fn generate(&self, key: &str, body: &str) -> (u16, Value) {
        let path = format!("/keys/{key}/signatures");
        let user_action = self.user_action(&credential_key(), CRED_ID, &path, body);
        self.send(
            "POST",
            &path,
            &[
                ("Authorization", &format!("Bearer {TOKEN}")),
                ("X-DFNS-USERACTION", &user_action),
            ],
            Some(body),
        )
    }
}

/// The documented error body: `{"error": {"id", "status", "message"}}`.
fn assert_error(reply: &(u16, Value), status: u16) {
    assert_eq!(reply.0, status, "{}", reply.1);
    let error = &reply.1["error"];
    assert_eq!(error["status"], status, "{}", reply.1);
    assert!(
        error["id"].is_string() && error["message"].is_string(),
        "{}",
        reply.1
    );
}

const HASH_BODY: &str = r#"{"kind":"Hash","hash":"0xd356339fa071e88335fdfab167cb600430522b71839d8556fa351fe1b4cd7556"}"#;

#[test]
fn a_hand_rolled_flow_gets_a_signature() {
    let mock = start_mock();
    let http = Http::new(mock.url());
    let (status, body) = http.generate(KEY, HASH_BODY);
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["status"], "Signed");
    assert_eq!(body["keyId"], KEY);
    for field in ["id", "requester", "requestBody", "dateRequested"] {
        assert!(!body[field].is_null(), "missing {field}: {body}");
    }
    // Both documented hash spellings are accepted.
    let (status, _) = http.generate(KEY, &HASH_BODY.replace("0xd3", "d3"));
    assert_eq!(status, 200);
}

#[test]
fn requests_without_a_valid_bearer_token_are_401() {
    let mock = start_mock();
    let http = Http::new(mock.url());
    let path = format!("/keys/{KEY}/signatures");
    assert_error(&http.send("POST", &path, &[], Some(HASH_BODY)), 401);
    assert_error(
        &http.send("POST", &path, &[("Authorization", TOKEN)], Some(HASH_BODY)),
        401,
    );
    assert_error(
        &http.send(
            "POST",
            &path,
            &[("Authorization", "Bearer someone-else")],
            Some(HASH_BODY),
        ),
        401,
    );
    assert_error(
        &http.send("POST", "/auth/action/init", &[], Some("{}")),
        401,
    );
    assert_error(&http.send("GET", &format!("{path}/sig-x"), &[], None), 401);
}

#[test]
fn generate_signature_without_a_user_action_is_403() {
    let mock = start_mock();
    let http = Http::new(mock.url());
    let path = format!("/keys/{KEY}/signatures");
    let reply = http.send(
        "POST",
        &path,
        &[("Authorization", &format!("Bearer {TOKEN}"))],
        Some(HASH_BODY),
    );
    assert_error(&reply, 403);
    assert_eq!(
        reply.1["error"]["message"],
        "User action signature is missing"
    );
}

#[test]
fn a_user_action_authorizes_exactly_one_request() {
    let mock = start_mock();
    let http = Http::new(mock.url());
    let bearer = format!("Bearer {TOKEN}");
    let path = format!("/keys/{KEY}/signatures");
    let send = |path: &str, token: &str, body: &str| {
        http.send(
            "POST",
            path,
            &[("Authorization", &bearer), ("X-DFNS-USERACTION", token)],
            Some(body),
        )
    };

    // A different body than the one the challenge named.
    let token = http.user_action(&credential_key(), CRED_ID, &path, HASH_BODY);
    let other_body = HASH_BODY.replace("0xd3", "0xd4");
    assert_error(&send(&path, &token, &other_body), 403);
    // The token was spent by that attempt.
    assert_error(&send(&path, &token, HASH_BODY), 403);

    // A different key than the one the challenge named.
    let token = http.user_action(&credential_key(), CRED_ID, &path, HASH_BODY);
    assert_error(
        &send(&format!("/keys/{OTHER_KEY}/signatures"), &token, HASH_BODY),
        403,
    );

    // Used once, then replayed.
    let token = http.user_action(&credential_key(), CRED_ID, &path, HASH_BODY);
    assert_eq!(send(&path, &token, HASH_BODY).0, 200);
    assert_error(&send(&path, &token, HASH_BODY), 403);

    assert_error(&send(&path, "made-up", HASH_BODY), 403);
}

#[test]
fn malformed_generate_signature_bodies_are_400() {
    let mock = start_mock();
    let http = Http::new(mock.url());
    let envelope_hex = hex::encode(common::xdr(&common::payment_envelope(
        &nido_key_keeper::stellar::account_strkey(&common::key_public()),
    )));
    let long_id = "x".repeat(51);
    let bodies = [
        "not json".to_owned(),
        "[]".to_owned(),
        r#"{"hash":"00"}"#.to_owned(),
        r#"{"kind":"Sign","hash":"00"}"#.to_owned(),
        r#"{"kind":"Eip191","message":"0x00"}"#.to_owned(),
        r#"{"kind":"Hash"}"#.to_owned(),
        HASH_BODY.replace(r#""kind""#, r#""extra":1,"kind""#),
        r#"{"kind":"Hash","hash":"0x1234"}"#.to_owned(),
        format!(r#"{{"kind":"Hash","hash":"0x{}"}}"#, "zz".repeat(32)),
        r#"{"kind":"Hash","hash":12}"#.to_owned(),
        r#"{"kind":"Message","message":"0xabc"}"#.to_owned(),
        HASH_BODY.replace('}', r#","network":"Mars"}"#),
        HASH_BODY.replace('}', r#","network":"Ethereum"}"#),
        HASH_BODY.replace('}', r#","blockchainKind":"Evm"}"#),
        HASH_BODY.replace('}', r#","externalId":""}"#),
        HASH_BODY.replace('}', &format!(r#","externalId":"{long_id}"}}"#)),
        format!(r#"{{"kind":"Transaction","transaction":"0x{envelope_hex}"}}"#),
        r#"{"kind":"Transaction","transaction":"0x0102","network":"StellarTestnet"}"#.to_owned(),
        r#"{"kind":"Transaction","transaction":{"to":"G"},"network":"StellarTestnet"}"#.to_owned(),
        r#"{"kind":"StellarFeeBumpTransaction","innerTransaction":"00"}"#.to_owned(),
    ];
    for body in &bodies {
        let reply = http.generate(KEY, body);
        assert_eq!(reply.0, 400, "{body} -> {}", reply.1);
        assert_error(&reply, 400);
    }
    // The well-formed Stellar transaction request, for contrast.
    let ok = format!(
        r#"{{"kind":"Transaction","transaction":"0x{envelope_hex}","network":"StellarTestnet"}}"#
    );
    assert_eq!(http.generate(KEY, &ok).0, 200);
}

#[test]
fn malformed_or_unverifiable_user_action_requests_are_refused() {
    let mock = start_mock();
    let http = Http::new(mock.url());
    let bearer = format!("Bearer {TOKEN}");
    let auth = [("Authorization", bearer.as_str())];

    let init_with_extra = json!({
        "userActionHttpMethod": "POST",
        "userActionHttpPath": "/keys/x/signatures",
        "userActionPayload": "{}",
        "unexpected": true,
    })
    .to_string();
    assert_error(
        &http.send("POST", "/auth/action/init", &auth, Some(&init_with_extra)),
        400,
    );
    let init_bad_method = json!({
        "userActionHttpMethod": "PATCH",
        "userActionHttpPath": "/keys/x/signatures",
        "userActionPayload": "{}",
    })
    .to_string();
    assert_error(
        &http.send("POST", "/auth/action/init", &auth, Some(&init_bad_method)),
        400,
    );

    let init = json!({
        "userActionHttpMethod": "POST",
        "userActionHttpPath": "/keys/x/signatures",
        "userActionPayload": "{}",
    })
    .to_string();
    let (_, challenge) = http.send("POST", "/auth/action/init", &auth, Some(&init));
    assert_eq!(challenge["allowCredentials"]["key"][0]["id"], CRED_ID);
    let assertion = |client_data: &str, signer: &SigningKey| {
        json!({
            "challengeIdentifier": challenge["challengeIdentifier"],
            "firstFactor": {
                "kind": "Key",
                "credentialAssertion": {
                    "credId": CRED_ID,
                    "clientData": URL_SAFE_NO_PAD.encode(client_data),
                    "signature": URL_SAFE_NO_PAD.encode(signer.sign(client_data.as_bytes()).to_bytes()),
                },
            },
        })
        .to_string()
    };
    let wrong_challenge = json!({ "type": "key.get", "challenge": "other" }).to_string();
    assert_error(
        &http.send(
            "POST",
            "/auth/action",
            &auth,
            Some(&assertion(&wrong_challenge, &credential_key())),
        ),
        401,
    );
    // The failed attempt spent the challenge.
    let right = json!({ "type": "key.get", "challenge": challenge["challenge"] }).to_string();
    assert_error(
        &http.send(
            "POST",
            "/auth/action",
            &auth,
            Some(&assertion(&right, &credential_key())),
        ),
        400,
    );

    let (_, challenge) = http.send("POST", "/auth/action/init", &auth, Some(&init));
    let fido = json!({
        "challengeIdentifier": challenge["challengeIdentifier"],
        "firstFactor": { "kind": "Fido2", "credentialAssertion": {} },
    })
    .to_string();
    assert_error(&http.send("POST", "/auth/action", &auth, Some(&fido)), 400);
}

#[test]
fn unknown_keys_signatures_and_routes_are_404() {
    let mock = start_mock();
    let http = Http::new(mock.url());
    let bearer = format!("Bearer {TOKEN}");
    let reply = http.generate("key-unknown", HASH_BODY);
    assert_error(&reply, 404);
    assert_eq!(reply.1["error"]["details"]["keyId"], "key-unknown");
    assert_error(
        &http.send(
            "GET",
            &format!("/keys/{KEY}/signatures/sig-missing"),
            &[("Authorization", &bearer)],
            None,
        ),
        404,
    );
    assert_error(
        &http.send("GET", "/wallets", &[("Authorization", &bearer)], None),
        404,
    );
}
