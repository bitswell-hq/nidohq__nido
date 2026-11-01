//! `forward(token, from, to, amount)` moves `amount` of `token` from `from` to
//! `to`. `from` authorizes the call, and the token transfer runs inside it, so
//! `from`'s authorization tree is `forward` with `transfer` as a
//! sub-invocation.
#![no_std]

use soroban_sdk::{contract, contractimpl, token, Address, Env};

#[contract]
pub struct Forwarder;

#[contractimpl]
impl Forwarder {
    pub fn forward(env: Env, token: Address, from: Address, to: Address, amount: i128) {
        from.require_auth();
        token::TokenClient::new(&env, &token).transfer(&from, &to, &amount);
    }
}
