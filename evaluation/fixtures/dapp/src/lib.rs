//! The dApp the evaluation's agents call. Every entry point requires
//! `account`'s authorization, so each call is one context of the account's
//! authorization tree, and every call it makes for `account` is a nested
//! context of the same tree.
//!
//! - `forward(account, token, to, amount)`: a transfer of `account`'s
//!   `token` inside the call (one nested context).
//! - `hop(account, hops, token, to, amount)`: calls `hop` on the first
//!   instance in `hops` with the rest, and when `hops` is empty transfers.
//!   A contract cannot re-enter itself, so each hop is another instance of
//!   this wasm; `hops` of length `d` nests the transfer `d + 1` calls deep.
//! - `take(account, value)`: accepts an argument of any type.
//! - `probe(account, data)`: accepts a byte string of any length.
#![no_std]

use soroban_sdk::{contract, contractimpl, token, Address, Bytes, Env, Val, Vec};

#[contract]
pub struct Dapp;

#[contractimpl]
impl Dapp {
    pub fn forward(env: Env, account: Address, token: Address, to: Address, amount: i128) {
        account.require_auth();
        token::TokenClient::new(&env, &token).transfer(&account, &to, &amount);
    }

    pub fn hop(
        env: Env,
        account: Address,
        hops: Vec<Address>,
        token: Address,
        to: Address,
        amount: i128,
    ) {
        account.require_auth();
        match hops.first() {
            Some(next) => {
                DappClient::new(&env, &next).hop(
                    &account,
                    &hops.slice(1..),
                    &token,
                    &to,
                    &amount,
                );
            }
            None => token::TokenClient::new(&env, &token).transfer(&account, &to, &amount),
        }
    }

    pub fn take(_env: Env, account: Address, _value: Val) {
        account.require_auth();
    }

    pub fn probe(_env: Env, account: Address, _data: Bytes) {
        account.require_auth();
    }
}
