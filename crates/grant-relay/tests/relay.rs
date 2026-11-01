//! The relay pipeline against an in-process network and keeper: what is
//! signed, what is refused before signing, and that every failure frees its
//! channel without using a sequence number.

mod common;

use std::time::Duration;

use common::*;
use grant_relay::protocol::Status;
use grant_relay::rpc::AuthMode;
use stellar_xdr::{
    CreateContractArgsV2, HostFunction, Limits, ScVal, SorobanAuthorizedFunction,
    SorobanCredentials, WriteXdr,
};

const WAIT: Duration = Duration::from_secs(5);

#[test]
fn an_allowed_transfer_is_signed_submitted_and_confirmed() {
    let net = FakeNetwork::new();
    let (relay, keeper) = relay(&net);
    let (func, auth) = transfer(1000);

    let submitted = relay.handle(Some(PAYER), submit(func, auth, true)).unwrap();
    assert_eq!(submitted.status, Status::Submitted);
    let settled = settle(&relay, PAYER, &submitted.transaction_id, WAIT);
    assert_eq!(settled.status, Status::Confirmed);
    assert_eq!(settled.hash, submitted.hash);

    assert_eq!(keeper.requests(), 1);
    let sent = net.sent();
    assert_eq!(sent.len(), 1);
    assert!(custody_signed(&sent[0]));
    let (source, seq) = source_and_seq(&sent[0]);
    assert!(channels().contains(&source));
    assert_eq!(seq, 101, "the channel's ledger sequence plus one");
    assert_eq!(
        fee(&sent[0]),
        100 + 5_000,
        "inclusion fee plus resource fee"
    );
    assert_eq!(net.simulations(), vec![AuthMode::Record, AuthMode::Enforce]);
    wait_idle(&relay);
}

#[test]
fn without_skip_wait_the_response_is_the_settled_status() {
    let net = FakeNetwork::new();
    let (relay, _) = relay(&net);
    let (func, auth) = transfer(1);
    let response = relay
        .handle(Some(PAYER), submit(func, auth, false))
        .unwrap();
    assert_eq!(response.status, Status::Confirmed);
}

/// Every denial below happens before any channel is leased, any simulation
/// runs, or the keeper is asked for anything.
fn assert_denied_before_signing(
    api_key: &str,
    func: HostFunction,
    auth: Vec<stellar_xdr::SorobanAuthorizationEntry>,
    code: &str,
) -> grant_relay::RelayError {
    let net = FakeNetwork::new();
    let (relay, keeper) = relay(&net);
    let err = relay
        .handle(Some(api_key), submit(func, auth, true))
        .unwrap_err();
    assert_eq!(err.code, code, "{err}");
    assert_eq!(keeper.requests(), 0, "the keeper was never asked");
    assert!(net.sent().is_empty());
    assert!(net.simulations().is_empty());
    assert_eq!(relay.pool().in_use(), 0);
    err
}

#[test]
fn an_amount_over_the_cap_is_never_signed() {
    let (func, auth) = transfer(1001);
    let err = assert_denied_before_signing(PAYER, func, auth, "GRANT_DENIED");
    assert_eq!(err.status, 403);
    assert_eq!(err.details["grant"], "chain");
    assert_eq!(err.details["tree"], "supplied");
    assert_eq!(err.details["actionIndex"], 0, "the host function itself");
}

#[test]
fn a_disallowed_nested_call_is_never_signed() {
    // forwarder.forward is allowed; the token transfer it makes, which is
    // in the same authorization tree, is not.
    let (func, auth) = forward(10);
    let err = assert_denied_before_signing(FORWARDER_ONLY, func, auth, "GRANT_DENIED");
    assert_eq!(
        err.details["actionIndex"], 2,
        "host fn, tree root, then the nested transfer"
    );
    assert!(err.message.contains(&token()), "{}", err.message);
    assert!(err.message.contains("transfer"), "{}", err.message);
}

#[test]
fn a_disallowed_call_in_a_second_tree_is_never_signed() {
    let (func, mut auth) = transfer(5);
    auth.push(entry(call(invoke_args(&contract(9), "drain", vec![]))));
    assert_denied_before_signing(PAYER, func, auth, "GRANT_DENIED");
}

#[test]
fn contract_creation_is_never_signed_under_a_chain_caveat() {
    // A creation context inside an allowed call's tree.
    let (func, _) = transfer(5);
    let auth = vec![entry(node(
        SorobanAuthorizedFunction::ContractFn(transfer_args(5)),
        vec![node(create_contract_fn(), vec![])],
    ))];
    assert_denied_before_signing(PAYER, func, auth, "GRANT_DENIED");

    // A creation host function.
    let args = create_contract_args();
    let func = HostFunction::CreateContractV2(CreateContractArgsV2 {
        contract_id_preimage: args.contract_id_preimage,
        executable: args.executable,
        constructor_args: Vec::new().try_into().unwrap(),
    });
    let err = assert_denied_before_signing(PAYER, func, vec![], "GRANT_DENIED");
    assert!(err.message.contains("deploying wasm"), "{}", err.message);
}

/// A `token.set(u32)` call whose argument the agent's grant pins with one
/// `arg_eq` value, as written in the configuration file.
fn set_u32_under(value: &serde_json::Value) -> (Result<Status, String>, usize) {
    const SETTER: &str = "setter-api-key";
    let mut json = config_json();
    json["agents"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "name": "setter",
            "api_key_sha256": grant_relay::config::api_key_sha256(SETTER),
            "chain": [
                { "contract_in": [token()] },
                { "function_in": ["set"] },
                { "arg_eq": [0, value] }
            ],
            "signing": []
        }));
    let net = FakeNetwork::new();
    let (relay, keeper) = relay_with(config_from(&json), &net);
    let args = invoke_args(&token(), "set", vec![ScVal::U32(7)]);
    let result = relay
        .handle(
            Some(SETTER),
            submit(
                HostFunction::InvokeContract(args.clone()),
                vec![entry(call(args))],
                false,
            ),
        )
        .map(|r| r.status)
        .map_err(|e| e.code.to_owned());
    (result, keeper.requests())
}

#[test]
fn a_u32_argument_never_satisfies_a_bytes_caveat_with_its_xdr() {
    let xdr = hex::encode(ScVal::U32(7).to_xdr(Limits::none()).unwrap());
    let (denied, signed) = set_u32_under(&serde_json::json!({ "bytes": xdr }));
    assert_eq!(denied, Err("GRANT_DENIED".to_owned()));
    assert_eq!(signed, 0, "the keeper was never asked");

    let (allowed, signed) = set_u32_under(&serde_json::json!({ "other": xdr }));
    assert_eq!(allowed, Ok(Status::Confirmed));
    assert_eq!(signed, 1);
}

#[test]
fn wasm_upload_is_not_relayed() {
    let func = HostFunction::UploadContractWasm(vec![0, 97, 115, 109].try_into().unwrap());
    let err =
        assert_denied_before_signing(OTHER_NETWORK, func, vec![], "UNSUPPORTED_HOST_FUNCTION");
    assert_eq!(err.status, 400);
}

#[test]
fn source_account_credentials_are_refused() {
    let (func, _) = transfer(5);
    let auth = vec![source_entry(call(transfer_args(5)))];
    let err = assert_denied_before_signing(PAYER, func, auth, "INVALID_PARAMS");
    assert_eq!(err.details["authIndex"], 0);
}

#[test]
fn the_signing_grant_is_checked() {
    let (func, auth) = transfer(5);
    let err = assert_denied_before_signing(OTHER_NETWORK, func, auth, "GRANT_DENIED");
    assert_eq!(err.details["grant"], "signing");
}

#[test]
fn unknown_and_missing_api_keys_are_refused() {
    let net = FakeNetwork::new();
    let (relay, keeper) = relay(&net);
    let (func, auth) = transfer(5);
    let err = relay
        .handle(Some("not-a-key"), submit(func.clone(), auth.clone(), true))
        .unwrap_err();
    assert_eq!((err.status, err.code), (401, "UNAUTHORIZED"));
    let err = relay.handle(None, submit(func, auth, true)).unwrap_err();
    assert_eq!((err.status, err.code), (401, "UNAUTHORIZED"));
    assert_eq!(keeper.requests(), 0);
}

#[test]
fn a_disallowed_call_the_simulation_records_is_never_signed() {
    // The supplied tree passes, but the recording simulation shows the call
    // asks for authorization of another context too.
    let net = FakeNetwork::new();
    net.record(vec![entry(node(
        SorobanAuthorizedFunction::ContractFn(transfer_args(5)),
        vec![call(invoke_args(&contract(9), "drain", vec![]))],
    ))]);
    let (relay, keeper) = relay(&net);
    let (func, auth) = transfer(5);
    let err = relay
        .handle(Some(PAYER), submit(func, auth, true))
        .unwrap_err();
    assert_eq!(err.code, "GRANT_DENIED");
    assert_eq!(err.details["tree"], "recorded");
    assert_eq!(keeper.requests(), 0);
    assert!(net.sent().is_empty());
    assert_eq!(net.simulations(), vec![AuthMode::Record]);
    assert_eq!(relay.pool().in_use(), 0, "the lease was dropped");
}

#[test]
fn a_call_that_needs_the_channel_accounts_authorization_is_never_signed() {
    let net = FakeNetwork::new();
    net.record(vec![source_entry(call(transfer_args(5)))]);
    let (relay, keeper) = relay(&net);
    let (func, auth) = transfer(5);
    let err = relay
        .handle(Some(PAYER), submit(func, auth, true))
        .unwrap_err();
    assert_eq!((err.status, err.code), (403, "CHANNEL_AUTH_REQUIRED"));
    assert_eq!(keeper.requests(), 0);
    assert_eq!(relay.pool().in_use(), 0);
}

/// A failure after the lease: nothing sent (or nothing that can land),
/// the channel freed, its sequence number unchanged.
fn assert_fails_safely(net: &FakeNetwork, code: &str, keeper_calls: usize) {
    let (relay, keeper) = relay(net);
    let before: Vec<i64> = channels().iter().map(|c| net.sequence(c)).collect();
    let (func, auth) = transfer(5);
    let err = relay
        .handle(Some(PAYER), submit(func, auth, true))
        .unwrap_err();
    assert_eq!(err.code, code, "{err}");
    assert_eq!(keeper.requests(), keeper_calls);
    assert_eq!(relay.pool().in_use(), 0, "the channel was freed");
    let after: Vec<i64> = channels().iter().map(|c| net.sequence(c)).collect();
    assert_eq!(before, after, "no sequence number was used");
}

#[test]
fn a_failed_recording_simulation_fails_safely() {
    let net = FakeNetwork::new();
    net.fail_record("HostError: Error(WasmVm, InvalidAction)");
    assert_fails_safely(&net, "SIMULATION_FAILED", 0);
}

#[test]
fn a_failed_enforcing_simulation_fails_safely() {
    let net = FakeNetwork::new();
    net.fail_enforce("HostError: Error(Auth, InvalidAction)");
    assert_fails_safely(&net, "SIMULATION_FAILED", 0);
}

#[test]
fn an_unreachable_rpc_fails_safely() {
    let net = FakeNetwork::new();
    net.set_rpc_down(true);
    assert_fails_safely(&net, "RPC_UNAVAILABLE", 0);
}

#[test]
fn a_fee_over_the_cap_fails_safely() {
    let net = FakeNetwork::new();
    net.set_min_resource_fee(20_000_000);
    assert_fails_safely(&net, "FEE_TOO_HIGH", 0);
}

#[test]
fn an_authorization_about_to_expire_fails_safely() {
    let net = FakeNetwork::new();
    net.set_latest_ledger(9_999);
    assert_fails_safely(&net, "AUTH_EXPIRY_TOO_SHORT", 0);
}

#[test]
fn a_keeper_failure_fails_safely() {
    let net = FakeNetwork::new();
    let mut json = config_json();
    json["custody"]["key_id"] = "key-unknown".into();
    // An agent whose grants allow anything, so the request reaches the keeper.
    json["agents"][2]["signing"] = serde_json::json!([]);
    let (relay, keeper) = relay_with(config_from(&json), &net);
    let (func, auth) = transfer(5);
    let err = relay
        .handle(Some(OTHER_NETWORK), submit(func, auth, true))
        .unwrap_err();
    assert_eq!(err.code, "SIGNING_FAILED");
    assert_eq!(keeper.requests(), 1);
    assert!(net.sent().is_empty());
    assert_eq!(relay.pool().in_use(), 0);
}

#[test]
fn a_refused_submission_fails_safely() {
    let net = FakeNetwork::new();
    net.send_mode(SendMode::Error);
    assert_fails_safely(&net, "SUBMIT_FAILED", 1);
    let net = FakeNetwork::new();
    net.send_mode(SendMode::TryAgainLater);
    assert_fails_safely(&net, "TRY_AGAIN_LATER", 1);
}

#[test]
fn after_a_refused_submission_the_channel_reuses_its_sequence_number() {
    let net = FakeNetwork::new();
    let mut json = config_json();
    json["channels"] =
        serde_json::json!([nido_key_keeper::stellar::account_strkey(&channels()[0])]);
    let (relay, _) = relay_with(config_from(&json), &net);
    net.send_mode(SendMode::Error);
    let (func, auth) = transfer(5);
    relay
        .handle(Some(PAYER), submit(func.clone(), auth.clone(), true))
        .unwrap_err();
    net.send_mode(SendMode::Accept);
    let ok = relay
        .handle(Some(PAYER), submit(func.clone(), auth.clone(), false))
        .unwrap();
    assert_eq!(ok.status, Status::Confirmed);
    let ok = relay
        .handle(Some(PAYER), submit(func, auth, false))
        .unwrap();
    assert_eq!(ok.status, Status::Confirmed);
    let seqs: Vec<i64> = net.sent().iter().map(|e| source_and_seq(e).1).collect();
    assert_eq!(seqs, vec![101, 101, 102]);
}

#[test]
fn a_failed_transaction_frees_its_channel_and_uses_its_sequence_number() {
    let net = FakeNetwork::new();
    net.send_mode(SendMode::AcceptThenFail);
    let (relay, _) = relay(&net);
    let (func, auth) = transfer(5);
    let response = relay
        .handle(Some(PAYER), submit(func, auth, false))
        .unwrap();
    assert_eq!(response.status, Status::Failed);
    let (source, seq) = source_and_seq(&net.sent()[0]);
    assert_eq!(net.sequence(&source), seq);
    wait_idle(&relay);
}

#[test]
fn concurrent_requests_use_distinct_channels() {
    let net = FakeNetwork::new();
    net.hold();
    let (relay, keeper) = relay(&net);
    let (func, auth) = transfer(5);

    let handles: Vec<_> = (0..2)
        .map(|_| {
            let relay = relay.clone();
            let (func, auth) = (func.clone(), auth.clone());
            std::thread::spawn(move || relay.handle(Some(PAYER), submit(func, auth, true)))
        })
        .collect();
    let responses: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .collect();
    assert!(responses.iter().all(|r| r.status == Status::Submitted));
    let sources = net
        .sent()
        .iter()
        .map(|e| source_and_seq(e).0)
        .collect::<Vec<_>>();
    assert_eq!(distinct(sources), 2, "two channels");
    assert_eq!(
        relay.pool().in_use(),
        2,
        "held until the transactions settle"
    );

    // Both channels are in use, so a third request is refused before
    // anything is signed.
    let err = relay
        .handle(Some(PAYER), submit(func, auth, true))
        .unwrap_err();
    assert_eq!((err.status, err.code), (503, "CHANNELS_BUSY"));
    assert_eq!(keeper.requests(), 2);

    net.release();
    for r in &responses {
        assert_eq!(
            settle(&relay, PAYER, &r.transaction_id, WAIT).status,
            Status::Confirmed
        );
    }
    wait_idle(&relay);
}

#[test]
fn a_transaction_that_misses_its_window_expires_and_frees_its_channel() {
    let net = FakeNetwork::new();
    net.hold();
    let (relay, _) = relay(&net);
    let (func, auth) = transfer(5);
    let submitted = relay.handle(Some(PAYER), submit(func, auth, true)).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(relay.pool().in_use(), 1, "held while it can still land");

    // A ledger closes past the transaction's maxTime without it.
    net.advance_close_time(120);
    let settled = settle(&relay, PAYER, &submitted.transaction_id, WAIT);
    assert_eq!(settled.status, Status::Expired);
    wait_idle(&relay);
    let (source, seq) = source_and_seq(&net.sent()[0]);
    assert_eq!(
        net.sequence(&source),
        seq - 1,
        "its sequence number is still free"
    );
}

#[test]
fn an_unanswered_submission_is_tracked_not_released() {
    // The send's answer is lost, but the transaction reached the network:
    // the relay keeps the channel and finds the result by hash.
    let net = FakeNetwork::new();
    net.send_mode(SendMode::AcceptButNoAnswer);
    let (relay, _) = relay(&net);
    let (func, auth) = transfer(5);
    let submitted = relay.handle(Some(PAYER), submit(func, auth, true)).unwrap();
    assert_eq!(submitted.status, Status::Submitted);
    assert_eq!(
        settle(&relay, PAYER, &submitted.transaction_id, WAIT).status,
        Status::Confirmed
    );

    // The send never reached the network: the channel is held until the
    // window closes, then the transaction is expired.
    let net = FakeNetwork::new();
    net.send_mode(SendMode::Lost);
    let (relay, _) = common::relay(&net);
    let (func, auth) = transfer(5);
    let submitted = relay.handle(Some(PAYER), submit(func, auth, true)).unwrap();
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(relay.pool().in_use(), 1);
    net.advance_close_time(120);
    assert_eq!(
        settle(&relay, PAYER, &submitted.transaction_id, WAIT).status,
        Status::Expired
    );
    wait_idle(&relay);
}

#[test]
fn only_the_submitting_agent_reads_a_transaction() {
    let net = FakeNetwork::new();
    let (relay, _) = relay(&net);
    let (func, auth) = transfer(5);
    let submitted = relay.handle(Some(PAYER), submit(func, auth, true)).unwrap();
    let err = relay
        .handle(Some(OTHER_NETWORK), get(&submitted.transaction_id))
        .unwrap_err();
    assert_eq!((err.status, err.code), (404, "NOT_FOUND"));
    let err = relay.handle(Some(PAYER), get("no-such-id")).unwrap_err();
    assert_eq!(err.code, "NOT_FOUND");
}

#[test]
fn channel_accounts_are_checked() {
    let net = FakeNetwork::new();
    let (relay, _) = relay(&net);
    relay.check_channels().unwrap();

    let c = channels()[1];
    let mut account = channel_account(&c, &custody_public(), 100);
    account.thresholds.0[0] = 1;
    net.set_account(account);
    let err = relay.check_channels().unwrap_err();
    assert!(err.contains("master weight is 1"), "{err}");

    net.set_account(channel_account(&c, &[99; 32], 100));
    let err = relay.check_channels().unwrap_err();
    assert!(err.contains("only signer"), "{err}");

    let mut account = channel_account(&c, &custody_public(), 100);
    account.thresholds.0[2] = 2;
    net.set_account(account);
    let err = relay.check_channels().unwrap_err();
    assert!(err.contains("thresholds"), "{err}");
}

#[test]
fn every_credential_kind_but_source_account_is_checked_by_its_tree() {
    // AddressWithDelegates entries authorize the same tree; the tree is what
    // the grant sees.
    let (func, auth) = forward(10);
    let mut entry = auth[0].clone();
    let SorobanCredentials::Address(creds) = entry.credentials.clone() else {
        unreachable!()
    };
    entry.credentials = SorobanCredentials::AddressWithDelegates(
        stellar_xdr::SorobanAddressCredentialsWithDelegates {
            address_credentials: creds,
            delegates: Vec::new().try_into().unwrap(),
        },
    );
    assert_denied_before_signing(FORWARDER_ONLY, func, vec![entry], "GRANT_DENIED");
}
