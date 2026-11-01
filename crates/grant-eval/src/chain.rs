//! Chain vocabulary: the contexts of a Soroban authorization tree.
//!
//! Every chain caveat is false on [`Action::CreateContract`], so any grant
//! with at least one chain caveat denies contract deployment.
//!
//! Each argument is one [`Val`], and two values are equal only when they have
//! the same variant, so an argument of one type never satisfies an
//! [`Caveat::ArgEq`] written for another. An argument type the vocabulary does
//! not model is [`Val::Other`], never [`Val::Bytes`].

use alloc::vec::Vec;

use crate::bytes::{bytes_eq, bytes_in};
use crate::Check;

/// A contract-call argument.
pub enum Val {
    I128(i128),
    U64(u64),
    Bool(bool),
    Bytes(Vec<u8>),
    Address(Vec<u8>),
    Symbol(Vec<u8>),
    /// An argument of a type the other variants do not model (`u32`, `i64`,
    /// `string`, `vec`, `map`, …), as its full `ScVal` XDR. The XDR begins
    /// with the type's discriminant, so two `Other` values are equal only when
    /// the arguments have the same type and the same value.
    Other(Vec<u8>),
}

/// One context of a Soroban authorization tree.
pub enum Action {
    /// A contract function call.
    Invoke {
        contract: Vec<u8>,
        function: Vec<u8>,
        args: Vec<Val>,
    },
    /// A contract-deploying host function.
    CreateContract { wasm_hash: Vec<u8> },
}

/// A chain caveat. Argument indices count from zero.
pub enum Caveat {
    /// The action is an invocation of one of these contracts.
    ContractIn(Vec<Vec<u8>>),
    /// The action is an invocation of one of these function names.
    FunctionIn(Vec<Vec<u8>>),
    /// The action is an invocation whose argument at this index exists, is
    /// an `I128`, and is at most this bound.
    ArgI128AtMost(u32, i128),
    /// The action is an invocation whose argument at this index exists and
    /// equals this value.
    ArgEq(u32, Val),
}

// `u32 as usize` below is lossless on every target with at least 32-bit
// pointers, which covers the host and `wasm32v1-none`.
const _: () = assert!(usize::BITS >= 32);

/// Whether `a` and `b` are the same value: same variant, equal payload.
#[must_use]
pub fn val_eq(a: &Val, b: &Val) -> bool {
    match (a, b) {
        (Val::I128(x), Val::I128(y)) => *x == *y,
        (Val::U64(x), Val::U64(y)) => *x == *y,
        (Val::Bool(x), Val::Bool(y)) => *x == *y,
        (Val::Bytes(x), Val::Bytes(y))
        | (Val::Address(x), Val::Address(y))
        | (Val::Symbol(x), Val::Symbol(y))
        | (Val::Other(x), Val::Other(y)) => bytes_eq(x, y),
        _ => false,
    }
}

/// Whether `caveat` holds for `action`.
#[must_use]
pub fn holds(caveat: &Caveat, action: &Action) -> bool {
    match action {
        Action::CreateContract { .. } => false,
        Action::Invoke {
            contract,
            function,
            args,
        } => match caveat {
            Caveat::ContractIn(list) => bytes_in(contract, list),
            Caveat::FunctionIn(list) => bytes_in(function, list),
            Caveat::ArgI128AtMost(index, bound) => match args.get(*index as usize) {
                Some(Val::I128(v)) => *v <= *bound,
                _ => false,
            },
            Caveat::ArgEq(index, expected) => match args.get(*index as usize) {
                Some(v) => val_eq(v, expected),
                None => false,
            },
        },
    }
}

impl Check<Action> for Caveat {
    fn holds(&self, action: &Action) -> bool {
        holds(self, action)
    }
}

/// Whether `grant` allows `action`.
#[must_use]
pub fn allows(grant: &[Caveat], action: &Action) -> bool {
    crate::allows(grant, action)
}

/// Whether `grant` allows every context in `actions`.
#[must_use]
pub fn allows_all(grant: &[Caveat], actions: &[Action]) -> bool {
    crate::allows_all(grant, actions)
}
