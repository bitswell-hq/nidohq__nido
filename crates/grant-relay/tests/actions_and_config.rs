//! The XDR-to-action mapping and the configuration file.

mod common;

use common::*;
use grant_eval::chain::{Action, Val};
use grant_relay::actions;
use grant_relay::ConfigFile;
use stellar_xdr::{
    ContractExecutable, ContractIdPreimage, CreateContractArgs, HostFunction, Limits, ScString,
    ScVal, SorobanAuthorizedFunction, WriteXdr,
};

fn invoke_parts(a: &Action) -> (String, String, &[Val]) {
    let Action::Invoke {
        contract,
        function,
        args,
    } = a
    else {
        panic!("not an invocation")
    };
    (
        String::from_utf8(contract.clone()).unwrap(),
        String::from_utf8(function.clone()).unwrap(),
        args,
    )
}

#[test]
fn an_invocation_names_its_contract_function_and_arguments() {
    let action = actions::host_function(&HostFunction::InvokeContract(transfer_args(-5))).unwrap();
    let (contract, function, args) = invoke_parts(&action);
    assert_eq!(contract, token());
    assert_eq!(function, "transfer");
    assert!(matches!(&args[0], Val::Address(a) if a == user().as_bytes()));
    assert!(matches!(&args[1], Val::Address(a) if a == bob().as_bytes()));
    assert!(matches!(args[2], Val::I128(-5)));
}

#[test]
fn i128_arguments_keep_their_full_range() {
    for n in [0, 1, -1, i128::from(i64::MAX) + 1, i128::MIN, i128::MAX] {
        assert!(
            matches!(actions::val(&i128_val(n)), Val::I128(v) if v == n),
            "{n}"
        );
    }
}

#[test]
fn argument_types_without_a_val_variant_keep_their_position_as_xdr_bytes() {
    let s = ScVal::String(ScString("hi".try_into().unwrap()));
    let Val::Bytes(bytes) = actions::val(&s) else {
        panic!("not bytes")
    };
    assert_eq!(bytes, s.to_xdr(Limits::none()).unwrap());
    assert!(matches!(actions::val(&ScVal::U32(7)), Val::Bytes(_)));
    assert!(matches!(actions::val(&ScVal::U64(7)), Val::U64(7)));
    assert!(matches!(actions::val(&ScVal::Bool(true)), Val::Bool(true)));
}

#[test]
fn the_tree_is_walked_root_first_depth_first() {
    let (_, auth) = forward(10);
    let mut out = Vec::new();
    actions::authorization_tree(&auth[0], &mut out);
    assert_eq!(out.len(), 2);
    assert_eq!(invoke_parts(&out[0]).1, "forward");
    assert_eq!(invoke_parts(&out[1]).0, token());

    let deep = entry(node(
        SorobanAuthorizedFunction::ContractFn(invoke_args(&contract(3), "a", vec![])),
        vec![
            node(
                SorobanAuthorizedFunction::ContractFn(invoke_args(&contract(3), "b", vec![])),
                vec![call(invoke_args(&contract(3), "c", vec![]))],
            ),
            call(invoke_args(&contract(3), "d", vec![])),
        ],
    ));
    let mut out = Vec::new();
    actions::authorization_tree(&deep, &mut out);
    let names: Vec<String> = out.iter().map(|a| invoke_parts(a).1).collect();
    assert_eq!(names, ["a", "b", "c", "d"]);
}

#[test]
fn contract_creation_carries_the_wasm_hash() {
    let Action::CreateContract { wasm_hash } = actions::authorized_function(&create_contract_fn())
    else {
        panic!()
    };
    assert_eq!(wasm_hash, vec![6; 32]);
    let sac = HostFunction::CreateContract(CreateContractArgs {
        contract_id_preimage: ContractIdPreimage::Asset(stellar_xdr::Asset::Native),
        executable: ContractExecutable::StellarAsset,
    });
    let Action::CreateContract { wasm_hash } = actions::host_function(&sac).unwrap() else {
        panic!()
    };
    assert!(wasm_hash.is_empty());
}

fn parse(json: &serde_json::Value) -> Result<(), String> {
    let file: ConfigFile = serde_json::from_value(json.clone()).map_err(|e| e.to_string())?;
    grant_relay::Config::from_file(&file).map(|_| ())
}

#[test]
fn the_example_configuration_parses() {
    let text = include_str!("../relay.example.json");
    let file: ConfigFile = serde_json::from_str(text).unwrap();
    let config = grant_relay::Config::from_file(&file).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(config.channels.len(), 2);
    assert!(file.keeper.is_some());
}

#[test]
fn configuration_errors_name_the_field() {
    let mut json = config_json();
    json["channels"] = serde_json::json!([]);
    assert!(parse(&json).unwrap_err().contains("channels"));

    let mut json = config_json();
    let c = json["channels"][0].clone();
    json["channels"][1] = c;
    assert!(parse(&json).unwrap_err().contains("listed twice"));

    let mut json = config_json();
    json["agents"][0]["chain"][0] = serde_json::json!({ "contract_in": ["CNOTACONTRACT"] });
    assert!(parse(&json).unwrap_err().contains("contract_in"));

    let mut json = config_json();
    json["agents"][0]["chain"][2] = serde_json::json!({ "arg_i128_at_most": [2, "ten"] });
    assert!(parse(&json).unwrap_err().contains("i128"));

    let mut json = config_json();
    json["agents"][1]["api_key_sha256"] = json["agents"][0]["api_key_sha256"].clone();
    assert!(parse(&json).unwrap_err().contains("same API key"));

    let mut json = config_json();
    json["agents"][0]["chain"][0] = serde_json::json!({ "contract_out": [] });
    assert!(parse(&json).is_err(), "unknown caveat");

    let mut json = config_json();
    json["unknown_field"] = serde_json::json!(1);
    assert!(parse(&json).is_err(), "unknown field");
}

#[test]
fn argument_values_parse_into_their_variants() {
    let mut json = config_json();
    json["agents"][0]["chain"] = serde_json::json!([
        { "arg_eq": [0, { "address": user() }] },
        { "arg_eq": [1, { "i128": "-170141183460469231731687303715884105728" }] },
        { "arg_eq": [2, { "u64": 5 }] },
        { "arg_eq": [3, { "bool": false }] },
        { "arg_eq": [4, { "bytes": "00ff" }] },
        { "arg_eq": [5, { "symbol": "native" }] }
    ]);
    parse(&json).unwrap();
    json["agents"][0]["chain"] = serde_json::json!([{ "arg_eq": [0, { "address": "nope" }] }]);
    assert!(parse(&json).is_err());
}
