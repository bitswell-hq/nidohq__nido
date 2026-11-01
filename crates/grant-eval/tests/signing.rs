mod common;

use grant_eval::signing::{allows, allows_all, holds, Action, Caveat, Payload};

const KEY_K: &[u8] = b"key-k";
const KEY_J: &[u8] = b"key-j";
const TESTNET: &[u8] = b"Test SDF Network ; September 2015";
const MAINNET: &[u8] = b"Public Global Stellar Network ; September 2015";

fn ids(list: &[&[u8]]) -> Vec<Vec<u8>> {
    list.iter().map(|s| s.to_vec()).collect()
}

fn sign(key: &[u8], network: &[u8], payload: Payload) -> Action {
    Action {
        key: key.to_vec(),
        network: network.to_vec(),
        payload,
    }
}

#[test]
fn key_in() {
    let c = Caveat::KeyIn(ids(&[KEY_K]));
    assert!(holds(&c, &sign(KEY_K, TESTNET, Payload::Transaction)));
    assert!(!holds(&c, &sign(KEY_J, TESTNET, Payload::Transaction)));
    assert!(!holds(&c, &sign(b"key-", TESTNET, Payload::Transaction)));
    assert!(!holds(&c, &sign(b"key-kk", TESTNET, Payload::Transaction)));
    assert!(!holds(
        &Caveat::KeyIn(vec![]),
        &sign(KEY_K, TESTNET, Payload::Message)
    ));
}

#[test]
fn network_in() {
    let testnet_only = Caveat::NetworkIn(ids(&[TESTNET]));
    assert!(holds(
        &testnet_only,
        &sign(KEY_K, TESTNET, Payload::AuthEntry)
    ));
    assert!(!holds(
        &testnet_only,
        &sign(KEY_K, MAINNET, Payload::AuthEntry)
    ));
    assert!(!holds(
        &Caveat::NetworkIn(vec![]),
        &sign(KEY_K, TESTNET, Payload::AuthEntry)
    ));
}

#[test]
fn payload_in() {
    let c = Caveat::PayloadIn(vec![Payload::AuthEntry, Payload::Message]);
    assert!(holds(&c, &sign(KEY_K, TESTNET, Payload::AuthEntry)));
    assert!(holds(&c, &sign(KEY_K, TESTNET, Payload::Message)));
    assert!(!holds(&c, &sign(KEY_K, TESTNET, Payload::Transaction)));
    assert!(holds(
        &Caveat::PayloadIn(vec![Payload::Transaction]),
        &sign(KEY_K, TESTNET, Payload::Transaction)
    ));
    assert!(!holds(
        &Caveat::PayloadIn(vec![]),
        &sign(KEY_K, TESTNET, Payload::Message)
    ));
}

#[test]
fn empty_grant_allows_everything() {
    assert!(allows(&[], &sign(KEY_J, MAINNET, Payload::Transaction)));
    assert!(allows_all(
        &[],
        &[
            sign(KEY_K, TESTNET, Payload::Message),
            sign(KEY_J, MAINNET, Payload::AuthEntry)
        ]
    ));
}

#[test]
fn one_key_on_testnet_only() {
    let grant = [
        Caveat::KeyIn(ids(&[KEY_K])),
        Caveat::NetworkIn(ids(&[TESTNET])),
    ];
    assert!(allows(&grant, &sign(KEY_K, TESTNET, Payload::Transaction)));
    assert!(!allows(&grant, &sign(KEY_K, MAINNET, Payload::Transaction)));
    assert!(!allows(&grant, &sign(KEY_J, TESTNET, Payload::Transaction)));
    assert!(!allows_all(
        &grant,
        &[
            sign(KEY_K, TESTNET, Payload::AuthEntry),
            sign(KEY_K, MAINNET, Payload::AuthEntry)
        ]
    ));
}

const N_CAVEATS: usize = 8;

fn caveat(i: usize) -> Caveat {
    match i {
        0 => Caveat::KeyIn(ids(&[KEY_K])),
        1 => Caveat::KeyIn(ids(&[KEY_K, KEY_J])),
        2 => Caveat::KeyIn(vec![]),
        3 => Caveat::NetworkIn(ids(&[TESTNET])),
        4 => Caveat::NetworkIn(ids(&[TESTNET, MAINNET])),
        5 => Caveat::PayloadIn(vec![Payload::Transaction]),
        6 => Caveat::PayloadIn(vec![Payload::AuthEntry, Payload::Message]),
        7 => Caveat::PayloadIn(vec![]),
        _ => unreachable!(),
    }
}

const N_ACTIONS: usize = 8;

fn action(i: usize) -> Action {
    match i {
        0 => sign(KEY_K, TESTNET, Payload::Transaction),
        1 => sign(KEY_K, TESTNET, Payload::AuthEntry),
        2 => sign(KEY_K, MAINNET, Payload::Message),
        3 => sign(KEY_J, TESTNET, Payload::Message),
        4 => sign(KEY_J, MAINNET, Payload::Transaction),
        5 => sign(b"key-x", TESTNET, Payload::AuthEntry),
        6 => sign(KEY_K, b"futurenet", Payload::Transaction),
        7 => sign(b"", b"", Payload::Message),
        _ => unreachable!(),
    }
}

fn payload_index(p: &Payload) -> u8 {
    match p {
        Payload::Transaction => 0,
        Payload::AuthEntry => 1,
        Payload::Message => 2,
    }
}

/// The signing semantics in plain Rust.
fn reference(c: &Caveat, a: &Action) -> bool {
    match c {
        Caveat::KeyIn(list) => list.contains(&a.key),
        Caveat::NetworkIn(list) => list.contains(&a.network),
        Caveat::PayloadIn(list) => list
            .iter()
            .any(|p| payload_index(p) == payload_index(&a.payload)),
    }
}

#[test]
fn exhaustive_attenuation_and_reference_agreement() {
    let seen = common::check_exhaustive(caveat, N_CAVEATS, action, N_ACTIONS, reference);
    assert!(seen.checks > 50_000, "{seen:?}");
}
