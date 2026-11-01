//! The evaluator component: allowed and denied cases for each vocabulary,
//! and agreement with `grant-eval` called natively on every grant of up to
//! three caveats from a small universe, against every action in that
//! vocabulary's set.

use agent_host::evaluator::{wit, Evaluator};
use agent_host::native;

fn b(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn path(s: &str) -> Vec<Vec<u8>> {
    s.split('/').filter(|c| !c.is_empty()).map(b).collect()
}

/// Every list of at most three items from `universe` (with repeats).
fn grants<T: Clone>(universe: &[T]) -> Vec<Vec<T>> {
    let mut out = vec![vec![]];
    let mut last = vec![vec![]];
    for _ in 0..3 {
        let mut next = Vec::new();
        for g in &last {
            for c in universe {
                let mut g = g.clone();
                g.push(c.clone());
                next.push(g);
            }
        }
        out.extend(next.iter().cloned());
        last = next;
    }
    out
}

#[test]
fn files_allowed_and_denied() {
    use wit::files::{Action, Caveat, Mode};
    let mut ev = Evaluator::new().unwrap();
    let grant = [
        Caveat::PathUnder(path("/home/a")),
        Caveat::ModeIn(vec![Mode::Read]),
    ];
    let act = |p: &str, mode| Action {
        path: path(p),
        mode,
    };
    assert!(ev.files(&grant, &act("/home/a/x", Mode::Read)).unwrap());
    assert!(ev.files(&grant, &act("/home/a", Mode::Read)).unwrap());
    assert!(!ev.files(&grant, &act("/home/a/x", Mode::Write)).unwrap());
    // Component-wise: `/home/ab` is not under `/home/a`.
    assert!(!ev.files(&grant, &act("/home/ab", Mode::Read)).unwrap());
    assert!(!ev.files(&grant, &act("/home/ab/x", Mode::Read)).unwrap());
    assert!(!ev.files(&grant, &act("/home", Mode::Read)).unwrap());
    assert!(ev.files(&[], &act("/etc/passwd", Mode::Write)).unwrap());
}

#[test]
fn network_allowed_and_denied() {
    use wit::network::{Action, Caveat, Scheme};
    let mut ev = Evaluator::new().unwrap();
    let grant = [
        Caveat::HostIn(vec![b("api.example.com")]),
        Caveat::SchemeIn(vec![Scheme::Https]),
        Caveat::PortIn(vec![443]),
    ];
    let act = |host: &str, port, scheme| Action {
        host: b(host),
        port,
        scheme,
    };
    assert!(ev
        .network(&grant, &act("api.example.com", 443, Scheme::Https))
        .unwrap());
    assert!(!ev
        .network(&grant, &act("api.example.com", 80, Scheme::Http))
        .unwrap());
    assert!(!ev
        .network(&grant, &act("api.example.com", 8443, Scheme::Https))
        .unwrap());
    assert!(!ev
        .network(&grant, &act("evil.example.com", 443, Scheme::Https))
        .unwrap());
    assert!(!ev
        .network(&grant, &act("API.example.com", 443, Scheme::Https))
        .unwrap());
}

#[test]
fn signing_allowed_and_denied() {
    use wit::signing::{Action, Caveat, Payload};
    let mut ev = Evaluator::new().unwrap();
    let testnet = b("Test SDF Network ; September 2015");
    let mainnet = b("Public Global Stellar Network ; September 2015");
    let grant = [
        Caveat::KeyIn(vec![b("key-a")]),
        Caveat::NetworkIn(vec![testnet.clone()]),
        Caveat::PayloadIn(vec![Payload::Transaction]),
    ];
    let act = |key: &str, network: &[u8], payload| Action {
        key: b(key),
        network: network.to_vec(),
        payload,
    };
    assert!(ev
        .signing(&grant, &act("key-a", &testnet, Payload::Transaction))
        .unwrap());
    assert!(!ev
        .signing(&grant, &act("key-b", &testnet, Payload::Transaction))
        .unwrap());
    assert!(!ev
        .signing(&grant, &act("key-a", &mainnet, Payload::Transaction))
        .unwrap());
    assert!(!ev
        .signing(&grant, &act("key-a", &testnet, Payload::Message))
        .unwrap());
}

#[test]
fn chain_allowed_and_denied() {
    use wit::chain::{Action, Caveat, Invocation, Val};
    let mut ev = Evaluator::new().unwrap();
    let grant = [
        Caveat::ContractIn(vec![b("C1")]),
        Caveat::FunctionIn(vec![b("transfer")]),
        Caveat::ArgI128AtMost((2, native::int128(100))),
    ];
    let transfer = |contract: &str, amount: i128| {
        Action::Invoke(Invocation {
            contract: b(contract),
            function: b("transfer"),
            args: vec![
                Val::Address(b("G1")),
                Val::Address(b("G2")),
                Val::Int128(native::int128(amount)),
            ],
        })
    };
    assert!(ev
        .chain_all(&grant, &[transfer("C1", 100), transfer("C1", -5)])
        .unwrap());
    // One disallowed context anywhere in the tree denies the whole tree.
    assert!(!ev
        .chain_all(&grant, &[transfer("C1", 1), transfer("C1", 101)])
        .unwrap());
    assert!(!ev
        .chain_all(&grant, &[transfer("C1", 1), transfer("C2", 1)])
        .unwrap());
    assert!(!ev
        .chain_all(&grant, &[Action::CreateContract(vec![0; 32])])
        .unwrap());
    // i128 values cross the boundary intact at the extremes.
    let wide = [Caveat::ArgI128AtMost((0, native::int128(i128::MIN + 1)))];
    let call = |n: i128| {
        Action::Invoke(Invocation {
            contract: b("C1"),
            function: b("f"),
            args: vec![Val::Int128(native::int128(n))],
        })
    };
    assert!(ev.chain_all(&wide, &[call(i128::MIN)]).unwrap());
    assert!(ev.chain_all(&wide, &[call(i128::MIN + 1)]).unwrap());
    assert!(!ev.chain_all(&wide, &[call(i128::MIN + 2)]).unwrap());
    assert!(!ev.chain_all(&wide, &[call(i128::MAX)]).unwrap());
}

#[test]
fn files_agree_with_native() {
    use wit::files::{Action, Caveat, Mode};
    let mut ev = Evaluator::new().unwrap();
    let universe = [
        Caveat::PathUnder(path("/home/a")),
        Caveat::PathUnder(path("/home")),
        Caveat::PathUnder(path("/home/ab")),
        Caveat::ModeIn(vec![Mode::Read]),
        Caveat::ModeIn(vec![Mode::Write, Mode::Execute]),
    ];
    let mut actions = Vec::new();
    for p in ["/", "/home", "/home/a", "/home/a/x", "/home/ab", "/etc"] {
        for mode in [Mode::Read, Mode::Write, Mode::Execute] {
            actions.push(Action {
                path: path(p),
                mode,
            });
        }
    }
    for g in grants(&universe) {
        let native_grant: Vec<_> = g.iter().map(native::file_caveat).collect();
        for a in &actions {
            let expected = grant_eval::files::allows(&native_grant, &native::file_action(a));
            assert_eq!(ev.files(&g, a).unwrap(), expected, "{g:?} {a:?}");
        }
    }
}

#[test]
fn network_agrees_with_native() {
    use wit::network::{Action, Caveat, Scheme};
    let mut ev = Evaluator::new().unwrap();
    let universe = [
        Caveat::HostIn(vec![b("a.example")]),
        Caveat::HostIn(vec![b("a.example"), b("b.example")]),
        Caveat::PortIn(vec![443]),
        Caveat::SchemeIn(vec![Scheme::Https]),
        Caveat::SchemeIn(vec![]),
    ];
    let mut actions = Vec::new();
    for host in ["a.example", "b.example", "c.example"] {
        for (port, scheme) in [
            (443, Scheme::Https),
            (80, Scheme::Http),
            (443, Scheme::Http),
        ] {
            actions.push(Action {
                host: b(host),
                port,
                scheme,
            });
        }
    }
    for g in grants(&universe) {
        let native_grant: Vec<_> = g.iter().map(native::network_caveat).collect();
        for a in &actions {
            let expected = grant_eval::network::allows(&native_grant, &native::network_action(a));
            assert_eq!(ev.network(&g, a).unwrap(), expected, "{g:?} {a:?}");
        }
    }
}

#[test]
fn signing_agrees_with_native() {
    use wit::signing::{Action, Caveat, Payload};
    let mut ev = Evaluator::new().unwrap();
    let universe = [
        Caveat::KeyIn(vec![b("k1")]),
        Caveat::KeyIn(vec![b("k1"), b("k2")]),
        Caveat::NetworkIn(vec![b("testnet")]),
        Caveat::PayloadIn(vec![Payload::Transaction, Payload::AuthEntry]),
        Caveat::PayloadIn(vec![Payload::Message]),
    ];
    let mut actions = Vec::new();
    for key in ["k1", "k2", "k3"] {
        for network in ["testnet", "mainnet"] {
            for payload in [Payload::Transaction, Payload::AuthEntry, Payload::Message] {
                actions.push(Action {
                    key: b(key),
                    network: b(network),
                    payload,
                });
            }
        }
    }
    for g in grants(&universe) {
        let native_grant: Vec<_> = g.iter().map(native::signing_caveat).collect();
        for a in &actions {
            let expected = grant_eval::signing::allows(&native_grant, &native::signing_action(a));
            assert_eq!(ev.signing(&g, a).unwrap(), expected, "{g:?} {a:?}");
        }
    }
}

#[test]
fn chain_agrees_with_native() {
    use wit::chain::{Action, Caveat, Invocation, Val};
    let mut ev = Evaluator::new().unwrap();
    let universe = [
        Caveat::ContractIn(vec![b("C1")]),
        Caveat::FunctionIn(vec![b("transfer"), b("approve")]),
        Caveat::ArgI128AtMost((1, native::int128(10))),
        Caveat::ArgEq((0, Val::Address(b("G1")))),
        Caveat::ArgEq((0, Val::Bytes(b("G1")))),
    ];
    let invoke = |contract: &str, function: &str, args: Vec<Val>| {
        Action::Invoke(Invocation {
            contract: b(contract),
            function: b(function),
            args,
        })
    };
    let singles = vec![
        invoke(
            "C1",
            "transfer",
            vec![Val::Address(b("G1")), Val::Int128(native::int128(10))],
        ),
        invoke(
            "C1",
            "transfer",
            vec![Val::Address(b("G1")), Val::Int128(native::int128(11))],
        ),
        invoke("C1", "approve", vec![Val::Other(b("G1")), Val::U64(10)]),
        invoke("C2", "transfer", vec![Val::Address(b("G2"))]),
        invoke("C1", "mint", vec![]),
        Action::CreateContract(vec![7; 32]),
    ];
    let mut trees: Vec<Vec<Action>> = vec![vec![]];
    for x in &singles {
        trees.push(vec![x.clone()]);
        for y in &singles {
            trees.push(vec![x.clone(), y.clone()]);
        }
    }
    for g in grants(&universe) {
        let native_grant: Vec<_> = g.iter().map(native::chain_caveat).collect();
        for tree in &trees {
            let native_tree: Vec<_> = tree.iter().map(native::chain_action).collect();
            let expected = grant_eval::chain::allows_all(&native_grant, &native_tree);
            assert_eq!(ev.chain_all(&g, tree).unwrap(), expected, "{g:?} {tree:?}");
        }
    }
}
