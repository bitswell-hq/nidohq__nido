//! The trusted wiring between Soroban and the evaluator: each contract-call
//! context becomes a `grant_eval::chain::Action` and each stored caveat a
//! `grant_eval::chain::Caveat`. The encoding is `crates/grant-relay`'s
//! (`actions.rs` there), so one grant means the same at the relay and here:
//!
//! - A contract is named by its strkey (`C…`), a function by its symbol's
//!   bytes, and an `Address` argument by its strkey (`G…`, `C…`, `M…`).
//! - `i128`, `u64`, `bool`, `Bytes` and `Symbol` arguments map onto the `Val`
//!   variant of the same name. Any other argument becomes `Val::Other` with
//!   its full `ScVal` XDR, discriminant included.
//!
//! `__check_auth` refuses a contract-creation context before mapping, so
//! only calls reach the evaluator.
//!
//! Each conversion below accepts exactly one kind of host value, so the
//! order of the checks in [`val`] decides nothing except that an `Address`
//! is tried before a `MuxedAddress` (which also accepts plain addresses).

use alloc::vec::Vec as AVec;
use grant_eval::chain;
use soroban_sdk::auth::ContractContext;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    symbol_short, Address, Bytes, Env, MuxedAddress, String, Symbol, SymbolStr, TryFromVal, Val,
    Vec,
};

use crate::{Arg, Caveat};

/// The evaluator's action for one contract-call context.
pub fn invoke(e: &Env, c: &ContractContext) -> chain::Action {
    chain::Action::Invoke {
        contract: address(&c.contract),
        function: symbol(e, &c.fn_name),
        args: c.args.iter().map(|v| val(e, v)).collect(),
    }
}

/// The evaluator's view of one argument.
fn val(e: &Env, v: Val) -> chain::Val {
    if let Ok(n) = i128::try_from_val(e, &v) {
        return chain::Val::I128(n);
    }
    if let Ok(n) = u64::try_from_val(e, &v) {
        return chain::Val::U64(n);
    }
    if let Ok(b) = bool::try_from_val(e, &v) {
        return chain::Val::Bool(b);
    }
    if let Ok(b) = Bytes::try_from_val(e, &v) {
        return chain::Val::Bytes(b.to_alloc_vec());
    }
    if let Ok(s) = Symbol::try_from_val(e, &v) {
        return chain::Val::Symbol(symbol(e, &s));
    }
    if let Ok(a) = Address::try_from_val(e, &v) {
        return chain::Val::Address(address(&a));
    }
    if let Ok(m) = MuxedAddress::try_from_val(e, &v) {
        return chain::Val::Address(string(&m.to_strkey()));
    }
    chain::Val::Other(v.to_xdr(e).to_alloc_vec())
}

fn address(a: &Address) -> AVec<u8> {
    string(&a.to_string())
}

fn string(s: &String) -> AVec<u8> {
    let mut out = alloc::vec![0u8; s.len() as usize];
    s.copy_into_slice(&mut out);
    out
}

fn symbol(e: &Env, s: &Symbol) -> AVec<u8> {
    let text = SymbolStr::try_from_val(e, &s.to_symbol_val())
        .unwrap_or_else(|_| panic!("a symbol is at most 32 bytes"));
    AsRef::<[u8]>::as_ref(&text).into()
}

/// The evaluator's form of a stored caveat list.
pub fn caveats(list: &Vec<Caveat>) -> AVec<chain::Caveat> {
    list.iter().map(|c| caveat(&c)).collect()
}

fn caveat(c: &Caveat) -> chain::Caveat {
    match c {
        Caveat::ContractIn(list) => chain::Caveat::ContractIn(bytes_list(list)),
        Caveat::FunctionIn(list) => chain::Caveat::FunctionIn(bytes_list(list)),
        Caveat::ArgI128AtMost(index, bound) => chain::Caveat::ArgI128AtMost(*index, *bound),
        Caveat::ArgEq(index, v) => chain::Caveat::ArgEq(*index, arg(v)),
    }
}

fn arg(a: &Arg) -> chain::Val {
    match a {
        Arg::I128(n) => chain::Val::I128(*n),
        Arg::U64(n) => chain::Val::U64(*n),
        Arg::Bool(b) => chain::Val::Bool(*b),
        Arg::Bytes(b) => chain::Val::Bytes(b.to_alloc_vec()),
        Arg::Address(b) => chain::Val::Address(b.to_alloc_vec()),
        Arg::Symbol(b) => chain::Val::Symbol(b.to_alloc_vec()),
        Arg::Other(b) => chain::Val::Other(b.to_alloc_vec()),
    }
}

fn bytes_list(list: &Vec<Bytes>) -> AVec<AVec<u8>> {
    list.iter().map(|b| b.to_alloc_vec()).collect()
}

/// The amount a call on the budget asset moves, if it is
/// `transfer(from, to, amount)` with a non-negative `i128` amount: the only
/// call on that asset a grant can authorize. A Stellar Asset Contract's
/// `transfer` requires `from`'s authorization, so the account's own
/// authorization of it names the account as `from`.
pub fn transfer_amount(e: &Env, c: &ContractContext) -> Option<u128> {
    if c.fn_name != symbol_short!("transfer") || c.args.len() != 3 {
        return None;
    }
    let amount = i128::try_from_val(e, &c.args.get_unchecked(2)).ok()?;
    u128::try_from(amount).ok()
}
