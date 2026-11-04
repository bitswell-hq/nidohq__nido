//! Chain actions from Soroban XDR, and chain caveats from a grant's `chain`
//! list, in the chain vocabulary of `grant_eval` that the evaluator
//! component checks:
//!
//! - A contract is named by its strkey (`C…`), a function by its symbol's
//!   bytes, and an `Address` argument by its strkey (`G…`, `C…`, `M…`, …).
//! - `ScVal::I128`, `U64`, `Bool`, `Bytes` and `Symbol` map onto the `Val`
//!   variant of the same name. Any other argument type (`u32`, `i64`,
//!   `string`, `vec`, `map`, …) becomes `Val::Other` holding its full `ScVal`
//!   XDR, discriminant included, so it keeps its position in the argument
//!   list and never equals a value of another type.
//! - A contract-creating host function or authorized function becomes
//!   `CreateContract`, with the wasm hash of a `Wasm` executable and empty
//!   bytes for an executable no wasm hash names: the Stellar Asset Contract,
//!   or an `ExternalRef` to an executable entry another contract owns.
//!
//! The grant file's `chain` list has the relay's form
//! (`grant_relay::config::ChainCaveatFile`). The relay and the grant signer
//! check a chain grant as the `rule_eval` rule set it lowers to, reading
//! contexts through `soroban-facade` (`grant_relay::config::chain_rules`,
//! `grant_relay::actions`); this module is the agent host's own reading, in
//! the vocabulary the component evaluates.

use grant_eval::chain::{Action, Caveat, Val};
use grant_relay::config::{ChainCaveatFile, I128Text, ValFile};
use stellar_xdr::{
    ContractExecutable, HostFunction, Int128Parts, InvokeContractArgs, Limits, ReadXdr, ScAddress,
    ScVal, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    WriteXdr,
};

/// A host function the host does not sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedHostFunction(pub &'static str);

/// The action of the operation's own host function: the root of the call.
///
/// # Errors
///
/// `UploadContractWasm`, which names no contract call or deployment the chain
/// vocabulary can express.
pub fn host_function(func: &HostFunction) -> Result<Action, UnsupportedHostFunction> {
    match func {
        HostFunction::InvokeContract(args) => Ok(invoke(args)),
        HostFunction::CreateContract(args) => Ok(create(&args.executable)),
        HostFunction::CreateContractV2(args) => Ok(create(&args.executable)),
        HostFunction::UploadContractWasm(_) => Err(UnsupportedHostFunction("UploadContractWasm")),
    }
}

/// Every context of `entry`'s authorization tree, root first, depth first.
pub fn authorization_tree(entry: &SorobanAuthorizationEntry, out: &mut Vec<Action>) {
    invocation_tree(&entry.root_invocation, out);
}

/// Every context of the tree under `node`, `node` first, depth first.
pub fn invocation_tree(node: &SorobanAuthorizedInvocation, out: &mut Vec<Action>) {
    out.push(authorized_function(&node.function));
    for sub in &node.sub_invocations {
        invocation_tree(sub, out);
    }
}

/// The action of one authorization context.
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

/// The evaluator's view of one argument.
///
/// # Panics
///
/// Never: a value decoded from XDR encodes again.
#[must_use]
pub fn val(v: &ScVal) -> Val {
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

/// A chain caveat of a grant file as the evaluator takes it.
///
/// # Errors
///
/// A `contract_in` entry that is not a `C…` address, or a malformed value.
pub fn chain_caveat(c: &ChainCaveatFile) -> Result<Caveat, String> {
    Ok(match c {
        ChainCaveatFile::ContractIn(list) => {
            for c in list {
                if !matches!(c.parse::<ScAddress>(), Ok(ScAddress::Contract(_))) {
                    return Err(format!("contract_in: {c} is not a C… contract address"));
                }
            }
            Caveat::ContractIn(bytes_list(list))
        }
        ChainCaveatFile::FunctionIn(list) => Caveat::FunctionIn(bytes_list(list)),
        ChainCaveatFile::ArgI128AtMost(index, bound) => {
            Caveat::ArgI128AtMost(*index, i128_value(bound)?)
        }
        ChainCaveatFile::ArgEq(index, v) => Caveat::ArgEq(*index, value(v)?),
    })
}

fn value(v: &ValFile) -> Result<Val, String> {
    Ok(match v {
        ValFile::I128(n) => Val::I128(i128_value(n)?),
        ValFile::U64(n) => Val::U64(*n),
        ValFile::Bool(b) => Val::Bool(*b),
        ValFile::Bytes(h) => Val::Bytes(hex::decode(h).map_err(|e| format!("bytes {h:?}: {e}"))?),
        ValFile::Address(a) => {
            a.parse::<ScAddress>()
                .map_err(|_| format!("{a} is not an address strkey"))?;
            Val::Address(a.clone().into_bytes())
        }
        ValFile::Symbol(s) => Val::Symbol(s.clone().into_bytes()),
        ValFile::Other(h) => {
            // Through `val`, so the value is exactly what an argument of that
            // type maps to; a type with its own variant is refused.
            let bytes = hex::decode(h).map_err(|e| format!("other {h:?}: {e}"))?;
            let arg = ScVal::from_xdr(bytes, Limits::none())
                .map_err(|e| format!("other {h:?}: not ScVal XDR: {e}"))?;
            match val(&arg) {
                v @ Val::Other(_) => v,
                _ => return Err(format!("other {h:?}: this type has its own value form")),
            }
        }
    })
}

fn i128_value(n: &I128Text) -> Result<i128, String> {
    match n {
        I128Text::Number(n) => Ok(i128::from(*n)),
        I128Text::Text(t) => t.parse().map_err(|_| format!("{t:?} is not an i128")),
    }
}

fn bytes_list(list: &[String]) -> Vec<Vec<u8>> {
    list.iter().map(|s| s.clone().into_bytes()).collect()
}
