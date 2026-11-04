//! The XDR-to-context mapping and the configuration file.

mod common;

use common::*;
use grant_relay::actions::{self, Action};
use grant_relay::config::{chain_rules, ChainCaveatFile};
use grant_relay::ConfigFile;
use rule_eval::{Context, Val};
use stellar_xdr::{
    ContractExecutable, ContractIdPreimage, CreateContractArgs, HostFunction, Limits, ScAddress,
    ScString, ScVal, ScVec, SorobanAuthorizedFunction, WriteXdr,
};

/// The `ScAddress` XDR of the address `strkey` names.
fn address_xdr(strkey: &str) -> Vec<u8> {
    strkey
        .parse::<ScAddress>()
        .unwrap()
        .to_xdr(Limits::none())
        .unwrap()
}

fn call_parts(a: &Action) -> (&[u8], String, &[Val]) {
    let Some(Context::Call {
        contract,
        function,
        args,
    }) = a
    else {
        panic!("not a call")
    };
    (contract, String::from_utf8(function.clone()).unwrap(), args)
}

#[test]
fn an_invocation_names_its_contract_function_and_arguments() {
    let action = actions::host_function(&HostFunction::InvokeContract(transfer_args(-5))).unwrap();
    let (contract, function, args) = call_parts(&action);
    assert_eq!(contract, address_xdr(&token()));
    assert_eq!(function, "transfer");
    assert!(matches!(&args[0], Val::Address(a) if *a == address_xdr(&user())));
    assert!(matches!(&args[1], Val::Address(a) if *a == address_xdr(&bob())));
    assert!(matches!(args[2], Val::I128(-5)));
}

#[test]
fn i128_arguments_keep_their_full_range() {
    for n in [0, 1, -1, i128::from(i64::MAX) + 1, i128::MIN, i128::MAX] {
        assert!(
            matches!(actions::val(&i128_val(n)), Some(Val::I128(v)) if v == n),
            "{n}"
        );
    }
}

fn string_hi() -> ScVal {
    ScVal::String(ScString("hi".try_into().unwrap()))
}

fn vec_of_u32_one() -> ScVal {
    ScVal::Vec(Some(ScVec(vec![ScVal::U32(1)].try_into().unwrap())))
}

#[test]
fn argument_types_without_a_val_variant_are_other_with_their_full_xdr() {
    for v in [ScVal::U32(7), ScVal::I64(-1), vec_of_u32_one()] {
        let Some(Val::Other(xdr)) = actions::val(&v) else {
            panic!("{v:?} is not Other")
        };
        assert_eq!(xdr, v.to_xdr(Limits::none()).unwrap());
    }
    assert!(matches!(actions::val(&string_hi()), Some(Val::String(s)) if s == b"hi"));
    assert!(matches!(actions::val(&ScVal::U64(7)), Some(Val::U64(7))));
    assert!(matches!(
        actions::val(&ScVal::Bool(true)),
        Some(Val::Bool(true))
    ));
}

/// The XDR the `grant_eval` chain tests write by hand is what `stellar_xdr`
/// encodes.
#[test]
fn the_evaluator_tests_unmodeled_xdr_is_the_real_encoding() {
    let xdr = |v: ScVal| v.to_xdr(Limits::none()).unwrap();
    assert_eq!(xdr(ScVal::U32(1)), [0, 0, 0, 3, 0, 0, 0, 1]);
    assert_eq!(
        xdr(string_hi()),
        [0, 0, 0, 14, 0, 0, 0, 2, b'h', b'i', 0, 0]
    );
    assert_eq!(
        xdr(vec_of_u32_one()),
        [0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0, 1]
    );
}

/// A rule set from one `arg_eq` caveat on `token`.
fn arg_eq_rules(v: &serde_json::Value) -> Vec<rule_eval::Rule> {
    let grant: Vec<ChainCaveatFile> = serde_json::from_value(serde_json::json!([
        { "contract_in": [token()] },
        { "arg_eq": [0, v] }
    ]))
    .unwrap();
    chain_rules(&grant).unwrap()
}

/// An `arg_eq` caveat written for bytes never matches a `u32`, `string` or
/// `vec` argument whose XDR is exactly those bytes.
#[test]
fn a_bytes_caveat_never_matches_an_unmodeled_argument_with_the_same_xdr() {
    for v in [ScVal::U32(1), string_hi(), vec_of_u32_one()] {
        let action = actions::host_function(&HostFunction::InvokeContract(invoke_args(
            &token(),
            "set",
            vec![v.clone()],
        )))
        .unwrap()
        .unwrap();
        let xdr = hex::encode(v.to_xdr(Limits::none()).unwrap());
        let bytes_grant = arg_eq_rules(&serde_json::json!({ "bytes": xdr }));
        assert!(!rule_eval::allows(&bytes_grant, &action, &[]), "{v:?}");
        let other_grant = arg_eq_rules(&serde_json::json!({ "other": xdr }));
        assert!(rule_eval::allows(&other_grant, &action, &[]), "{v:?}");
    }
}

/// A chain grant is one rule per contract every `contract_in` names, with
/// the functions every `function_in` names and every argument caveat as a
/// condition.
#[test]
fn a_chain_grant_lowers_to_one_rule_per_contract_it_names() {
    let grant: Vec<ChainCaveatFile> = serde_json::from_value(serde_json::json!([
        { "contract_in": [token(), forwarder(), contract(3)] },
        { "function_in": ["transfer", "forward"] },
        { "contract_in": [forwarder(), token()] },
        { "function_in": ["forward", "approve"] },
        { "arg_i128_at_most": [2, "10"] }
    ]))
    .unwrap();
    let rules = chain_rules(&grant).unwrap();
    let contracts: Vec<&[u8]> = rules.iter().map(|r| r.contract.as_slice()).collect();
    assert_eq!(
        contracts,
        [address_xdr(&forwarder()), address_xdr(&token())]
    );
    for r in &rules {
        assert!(
            matches!(&r.functions, rule_eval::Functions::Only(f) if *f == [b"forward".to_vec()])
        );
        assert!(matches!(
            r.conds.as_slice(),
            [rule_eval::Cond::ArgI128AtMost(2, 10)]
        ));
        assert!(r.signers.is_empty() && r.threshold == 0);
    }

    let no_contracts: Vec<ChainCaveatFile> =
        serde_json::from_value(serde_json::json!([{ "function_in": ["transfer"] }])).unwrap();
    let Err(e) = chain_rules(&no_contracts) else {
        panic!("a grant that names no contract lowers")
    };
    assert!(e.contains("contract_in"), "{e}");
}

#[test]
fn the_tree_is_walked_root_first_depth_first() {
    let (_, auth) = forward(10);
    let mut out = Vec::new();
    actions::authorization_tree(&auth[0], &mut out);
    assert_eq!(out.len(), 2);
    assert_eq!(call_parts(&out[0]).1, "forward");
    assert_eq!(call_parts(&out[1]).0, address_xdr(&token()));

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
    let names: Vec<String> = out.iter().map(|a| call_parts(a).1).collect();
    assert_eq!(names, ["a", "b", "c", "d"]);
}

#[test]
fn contract_creation_carries_the_wasm_hash() {
    let Some(Context::Create { wasm_hash }) = actions::authorized_function(&create_contract_fn())
    else {
        panic!()
    };
    assert_eq!(wasm_hash, vec![6; 32]);
    let sac = HostFunction::CreateContract(CreateContractArgs {
        contract_id_preimage: ContractIdPreimage::Asset(stellar_xdr::Asset::Native),
        executable: ContractExecutable::StellarAsset,
    });
    let Some(Context::Create { wasm_hash }) = actions::host_function(&sac).unwrap() else {
        panic!()
    };
    assert!(wasm_hash.is_empty());
}

/// A claimable-balance address is no value a contract takes: the facade does
/// not read it, so the call holding it is no context a grant allows.
#[test]
fn a_call_holding_a_value_the_facade_does_not_read_is_none() {
    let balance = ScVal::Address(ScAddress::ClaimableBalance(
        stellar_xdr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(stellar_xdr::Hash([4; 32])),
    ));
    assert!(actions::val(&balance).is_none());
    let action = actions::host_function(&HostFunction::InvokeContract(invoke_args(
        &token(),
        "set",
        vec![balance],
    )))
    .unwrap();
    assert!(action.is_none());
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
    json["agents"][0]["chain"] = serde_json::json!([{ "function_in": ["transfer"] }]);
    assert!(
        parse(&json).unwrap_err().contains("contract_in"),
        "no contracts named"
    );

    let mut json = config_json();
    json["unknown_field"] = serde_json::json!(1);
    assert!(parse(&json).is_err(), "unknown field");
}

#[test]
fn argument_values_parse_into_their_variants() {
    let mut json = config_json();
    json["agents"][0]["chain"] = serde_json::json!([
        { "contract_in": [token()] },
        { "arg_eq": [0, { "address": user() }] },
        { "arg_eq": [1, { "i128": "-170141183460469231731687303715884105728" }] },
        { "arg_eq": [2, { "u64": 5 }] },
        { "arg_eq": [3, { "bool": false }] },
        { "arg_eq": [4, { "bytes": "00ff" }] },
        { "arg_eq": [5, { "symbol": "native" }] },
        { "arg_eq": [6, { "other": "0000000300000007" }] },
        { "arg_eq": [7, { "other": "0000000e0000000268690000" }] }
    ]);
    parse(&json).unwrap();
    // `other` takes ScVal XDR of a type without its own value form.
    for refused in [
        "00",
        "zz",
        // `ScVal::U64(7)`, which is written `{"u64": 7}`.
        "000000050000000000000007",
    ] {
        json["agents"][0]["chain"] = serde_json::json!([
            { "contract_in": [token()] },
            { "arg_eq": [0, { "other": refused }] }
        ]);
        assert!(parse(&json).is_err(), "{refused}");
    }
    json["agents"][0]["chain"] = serde_json::json!([
        { "contract_in": [token()] },
        { "arg_eq": [0, { "address": "nope" }] }
    ]);
    assert!(parse(&json).is_err());
}
