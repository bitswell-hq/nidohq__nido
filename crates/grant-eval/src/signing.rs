//! Signing vocabulary: signatures by key, network and payload kind.

use alloc::vec::Vec;

use crate::bytes::bytes_in;
use crate::Check;

/// What is being signed.
pub enum Payload {
    Transaction,
    AuthEntry,
    Message,
}

/// A signing request.
pub struct Action {
    pub key: Vec<u8>,
    pub network: Vec<u8>,
    pub payload: Payload,
}

/// A signing caveat.
pub enum Caveat {
    /// The action's key is one of these.
    KeyIn(Vec<Vec<u8>>),
    /// The action's network is one of these. Testnet only is
    /// `NetworkIn([testnet id])`.
    NetworkIn(Vec<Vec<u8>>),
    /// The action's payload kind is one of these.
    PayloadIn(Vec<Payload>),
}

/// Whether `a` and `b` are the same payload kind.
#[must_use]
pub fn payload_eq(a: &Payload, b: &Payload) -> bool {
    matches!(
        (a, b),
        (Payload::Transaction, Payload::Transaction)
            | (Payload::AuthEntry, Payload::AuthEntry)
            | (Payload::Message, Payload::Message)
    )
}

/// Whether `payload` is one of the payload kinds in `list`.
#[must_use]
pub fn payload_in(payload: &Payload, list: &[Payload]) -> bool {
    let mut i = 0;
    while i < list.len() {
        if payload_eq(payload, &list[i]) {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether `caveat` holds for `action`.
#[must_use]
pub fn holds(caveat: &Caveat, action: &Action) -> bool {
    match caveat {
        Caveat::KeyIn(list) => bytes_in(&action.key, list),
        Caveat::NetworkIn(list) => bytes_in(&action.network, list),
        Caveat::PayloadIn(list) => payload_in(&action.payload, list),
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

/// Whether `grant` allows every action in `actions`.
#[must_use]
pub fn allows_all(grant: &[Caveat], actions: &[Action]) -> bool {
    crate::allows_all(grant, actions)
}
