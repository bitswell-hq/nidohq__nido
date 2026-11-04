//! Grants and authorization contexts in the evaluator's form, as the JSON the
//! Lean step counter (`evaluation/cost-bound/Steps.lean`) reads.
//!
//! A grant's caveat maps to `grant_eval::chain::Caveat` byte for byte, and an
//! authorization context to an action whose contract, function and arguments
//! are the call's as `grant_eval` writes them: a contract and an address
//! argument by its strkey, a function and a symbol by its text, and any
//! other argument type as `Other` of its `ScVal` XDR. The grant signer checks
//! the same grant as the rule set `nido_integration_tests::grants` lowers it
//! to, which `crates/grant-eval/tests/rule_eval.rs` checks against
//! `grant_eval::chain` on the same caveats.

use grant_eval::chain::{self, Action, Val};
use nido_integration_tests::grants::{Arg, Caveat};
use serde_json::{json, Value};
use soroban_sdk::xdr::{
    ContractExecutable, Int128Parts, InvokeContractArgs, Limits, ScVal, SorobanAuthorizedFunction,
    WriteXdr,
};

/// The action of one authorized function, in the encoding of the caveats.
#[must_use]
pub fn authorized_function(function: &SorobanAuthorizedFunction) -> Action {
    match function {
        SorobanAuthorizedFunction::ContractFn(args) => invoke(args),
        SorobanAuthorizedFunction::CreateContractHostFn(args) => create(&args.executable),
        SorobanAuthorizedFunction::CreateContractV2HostFn(args) => create(&args.executable),
    }
}

fn invoke(args: &InvokeContractArgs) -> Action {
    Action::Invoke {
        contract: args.contract_address.to_string().into_bytes(),
        function: args.function_name.0.to_vec(),
        args: args.args.iter().map(val).collect(),
    }
}

fn create(executable: &ContractExecutable) -> Action {
    Action::CreateContract {
        wasm_hash: match executable {
            ContractExecutable::Wasm(hash) => hash.0.to_vec(),
            ContractExecutable::StellarAsset | ContractExecutable::ExternalRef(_) => Vec::new(),
        },
    }
}

fn val(v: &ScVal) -> Val {
    match v {
        ScVal::I128(Int128Parts { hi, lo }) => Val::I128(i128::from(*hi) << 64 | i128::from(*lo)),
        ScVal::U64(n) => Val::U64(*n),
        ScVal::Bool(b) => Val::Bool(*b),
        ScVal::Bytes(b) => Val::Bytes(b.0.to_vec()),
        ScVal::Symbol(s) => Val::Symbol(s.0.to_vec()),
        ScVal::Address(a) => Val::Address(a.to_string().into_bytes()),
        other => Val::Other(
            other
                .to_xdr(Limits::none())
                .expect("an ScVal decoded from XDR encodes again"),
        ),
    }
}

fn bytes(b: &soroban_sdk::Bytes) -> Vec<u8> {
    b.to_alloc_vec()
}

/// The evaluator's form of a stored caveat.
#[must_use]
pub fn caveat(c: &Caveat) -> chain::Caveat {
    match c {
        Caveat::ContractIn(list) => {
            chain::Caveat::ContractIn(list.iter().map(|b| bytes(&b)).collect())
        }
        Caveat::FunctionIn(list) => {
            chain::Caveat::FunctionIn(list.iter().map(|b| bytes(&b)).collect())
        }
        Caveat::ArgI128AtMost(i, n) => chain::Caveat::ArgI128AtMost(*i, *n),
        Caveat::ArgEq(i, v) => chain::Caveat::ArgEq(*i, arg(v)),
    }
}

fn arg(a: &Arg) -> Val {
    match a {
        Arg::I128(n) => Val::I128(*n),
        Arg::U64(n) => Val::U64(*n),
        Arg::Bool(b) => Val::Bool(*b),
        Arg::Bytes(b) => Val::Bytes(bytes(b)),
        Arg::Address(b) => Val::Address(bytes(b)),
        Arg::Symbol(b) => Val::Symbol(bytes(b)),
        Arg::Other(b) => Val::Other(bytes(b)),
    }
}

#[must_use]
pub fn val_json(v: &Val) -> Value {
    match v {
        Val::I128(n) => json!({ "i128": n.to_string() }),
        Val::U64(n) => json!({ "u64": n }),
        Val::Bool(b) => json!({ "bool": b }),
        Val::Bytes(b) => json!({ "bytes": hex::encode(b) }),
        Val::Address(b) => json!({ "address": hex::encode(b) }),
        Val::Symbol(b) => json!({ "symbol": hex::encode(b) }),
        Val::Other(b) => json!({ "other": hex::encode(b) }),
    }
}

#[must_use]
pub fn caveat_json(c: &chain::Caveat) -> Value {
    let list = |l: &[Vec<u8>]| l.iter().map(hex::encode).collect::<Vec<_>>();
    match c {
        chain::Caveat::ContractIn(l) => json!({ "contract_in": list(l) }),
        chain::Caveat::FunctionIn(l) => json!({ "function_in": list(l) }),
        chain::Caveat::ArgI128AtMost(i, n) => {
            json!({ "arg_i128_at_most": { "index": i, "bound": n.to_string() } })
        }
        chain::Caveat::ArgEq(i, v) => json!({ "arg_eq": { "index": i, "value": val_json(v) } }),
    }
}

#[must_use]
pub fn action_json(a: &Action) -> Value {
    match a {
        Action::Invoke {
            contract,
            function,
            args,
        } => json!({ "invoke": {
            "contract": hex::encode(contract),
            "function": hex::encode(function),
            "args": args.iter().map(val_json).collect::<Vec<_>>(),
        }}),
        Action::CreateContract { wasm_hash } => {
            json!({ "create_contract": hex::encode(wasm_hash) })
        }
    }
}

/// One Lean case: `id`, the grant's caveats and the actions it is asked to
/// allow, with the native evaluator's verdict for comparison.
#[must_use]
pub fn lean_case(id: &str, caveats: &[chain::Caveat], actions: &[Action]) -> Value {
    json!({
        "id": id,
        "caveats": caveats.iter().map(caveat_json).collect::<Vec<_>>(),
        "actions": actions.iter().map(action_json).collect::<Vec<_>>(),
        "native_allowed": chain::allows_all(caveats, actions),
    })
}
