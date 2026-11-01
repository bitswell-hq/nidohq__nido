//! Grant evaluator.
//!
//! A grant is a list of caveats over one action type. An action is allowed
//! exactly when every caveat in the grant holds for it, so the empty grant
//! allows every action and adding a caveat can only narrow what a grant
//! allows. This is the readable Lean model the evaluator agrees with:
//!
//! ```lean
//! structure Grant (α : Type) where
//!   caveats : List (α → Bool)
//!
//! def Grant.allows (g : Grant α) (a : α) : Bool :=
//!   g.caveats.all (· a)
//! ```
//!
//! Four vocabularies instantiate the model: [`chain`] (Soroban contract
//! invocations and contract creation), [`files`], [`network`] and
//! [`signing`]. Each defines its action and caveat types and its own
//! `allows` / `allows_all`.
//!
//! The code is written in a restricted Rust subset so Charon and Aeneas can
//! translate it to Lean: plain structs and enums, `while` loops over bounds
//! checked indices, no closures, iterator adaptors, trait objects, `unsafe`
//! or derived equality, and no operation that can panic. `README.md` lists
//! the rules and the trusted base.
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod chain;
pub mod files;
pub mod network;
pub mod signing;

mod bytes;
mod eval;

pub use bytes::{bytes_eq, bytes_in};
pub use eval::{allows, allows_all, Check};
