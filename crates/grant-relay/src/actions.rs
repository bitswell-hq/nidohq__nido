//! Chain actions from a Soroban invocation: the host function and every
//! context of every authorization tree, as `grant_eval::chain` actions.
//!
//! The mapping is the trusted wiring between Soroban's XDR and the evaluator:
//!
//! - A contract is named by its strkey (`C…`), a function by its symbol's
//!   bytes, and an `Address` argument by its strkey (`G…`, `C…`, `M…`, …).
//! - `ScVal::I128`, `U64`, `Bool`, `Bytes` and `Symbol` map onto the `Val`
//!   variant of the same name. Any other argument type (`u32`, `i64`,
//!   `string`, `vec`, `map`, …) becomes `Val::Other` holding its full `ScVal`
//!   XDR, discriminant included, so it keeps its position in the argument list
//!   and never equals a value of another type.
//! - A contract-creating host function or authorized function becomes
//!   `CreateContract`, with the wasm hash of a `Wasm` executable and empty
//!   bytes for the Stellar Asset Contract executable.

use grant_eval::chain::{Action, Val};
use stellar_xdr::{
    ContractExecutable, HostFunction, Int128Parts, InvokeContractArgs, Limits, ScVal,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, WriteXdr,
};

/// A host function the relay does not submit.
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
            ContractExecutable::StellarAsset => Vec::new(),
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
