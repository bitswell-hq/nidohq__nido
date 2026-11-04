//! Authorization contexts from a Soroban invocation: the host function and
//! every context of every authorization tree, as `rule_eval` reads them.
//!
//! The mapping is the grant signer's: every value crosses as its XDR through
//! `soroban-facade`, which reads it as plain data, and the facade's
//! `val_to_rule_eval` gives what `rule_eval` reads of it:
//!
//! - A call's contract is its `ScAddress` XDR, its function its symbol's
//!   bytes.
//! - `i128`, `u64`, `bool`, bytes, string and symbol arguments map onto the
//!   `rule_eval::Val` constructor of the same name, and an address argument
//!   onto `Address` of its `ScAddress` XDR (accounts, contracts and muxed
//!   accounts). Any other argument type (`u32`, `i64`, `vec`, `map`, …)
//!   becomes `Other` holding its full `ScVal` XDR, discriminant included, so
//!   it keeps its position in the argument list and never equals a value of
//!   another type.
//! - A contract-creating host function or authorized function becomes
//!   `Create`, with the wasm hash of a `Wasm` executable and empty bytes for
//!   an executable no wasm hash names: the Stellar Asset Contract, or an
//!   `ExternalRef` to an executable entry another contract owns.
//!
//! A context holding a value the facade does not read (a ledger key, a
//! contract instance, a claimable-balance or liquidity-pool address, none of
//! which a contract takes as an argument) is `None`: no grant allows it, as
//! the grant signer refuses a batch the facade does not read.

use rule_eval::Context;
use stellar_xdr::{
    ContractExecutable, HostFunction, InvokeContractArgs, Limits, ScAddress, ScVal,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, WriteXdr,
};

/// One context of an authorization tree as `rule_eval` reads it, or `None`
/// when soroban-facade does not read one of its values.
pub type Action = Option<Context>;

/// A host function the relay does not submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedHostFunction(pub &'static str);

/// The context of the operation's own host function: the root of the call.
///
/// # Errors
///
/// `UploadContractWasm`, which names no contract call or deployment a rule
/// can express.
pub fn host_function(func: &HostFunction) -> Result<Action, UnsupportedHostFunction> {
    match func {
        HostFunction::InvokeContract(args) => Ok(invoke(args)),
        HostFunction::CreateContract(args) => Ok(Some(create(&args.executable))),
        HostFunction::CreateContractV2(args) => Ok(Some(create(&args.executable))),
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

/// The context of one authorized function.
#[must_use]
pub fn authorized_function(function: &SorobanAuthorizedFunction) -> Action {
    match function {
        SorobanAuthorizedFunction::ContractFn(args) => invoke(args),
        SorobanAuthorizedFunction::CreateContractHostFn(args) => Some(create(&args.executable)),
        SorobanAuthorizedFunction::CreateContractV2HostFn(args) => Some(create(&args.executable)),
    }
}

fn invoke(args: &InvokeContractArgs) -> Action {
    Some(Context::Call {
        contract: address(&args.contract_address)?,
        function: args.function_name.0.to_vec(),
        args: args.args.iter().map(val).collect::<Option<_>>()?,
    })
}

fn create(executable: &ContractExecutable) -> Context {
    Context::Create {
        wasm_hash: match executable {
            ContractExecutable::Wasm(hash) => hash.0.to_vec(),
            ContractExecutable::StellarAsset | ContractExecutable::ExternalRef(_) => Vec::new(),
        },
    }
}

/// `a`'s `ScAddress` XDR, as the facade reads it; `None` for an address it
/// does not read.
#[must_use]
pub fn address(a: &ScAddress) -> Option<Vec<u8>> {
    match val(&ScVal::Address(a.clone()))? {
        rule_eval::Val::Address(x) => Some(x),
        _ => None,
    }
}

/// What `rule_eval` reads of one argument, or `None` for a value the facade
/// does not read.
#[must_use]
pub fn val(v: &ScVal) -> Option<rule_eval::Val> {
    let xdr = v.to_xdr(Limits::none()).ok()?;
    soroban_facade::xdr::decode(&xdr).map(|v| soroban_facade::val_to_rule_eval(&v))
}
