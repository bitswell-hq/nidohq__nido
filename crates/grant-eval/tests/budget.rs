use grant_eval::budget::{check_spend, refill, spend, Node, RefillError, SpendError};

fn node(parent: Option<usize>, allowance: u128, spent: u128) -> Node {
    Node {
        parent,
        allowance,
        spent,
    }
}

/// Every field of every node, so two snapshots are equal exactly when the
/// ledgers are identical.
fn snapshot(ledger: &[Node]) -> Vec<(Option<usize>, u128, u128)> {
    ledger
        .iter()
        .map(|n| (n.parent, n.allowance, n.spent))
        .collect()
}

fn spent(ledger: &[Node]) -> Vec<u128> {
    ledger.iter().map(|n| n.spent).collect()
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Err {
    NoSuchNode(usize),
    BadParent(usize),
    Overdrawn(usize),
}

fn err(e: &SpendError) -> Err {
    match e {
        SpendError::NoSuchNode(i) => Err::NoSuchNode(*i),
        SpendError::BadParent(i) => Err::BadParent(*i),
        SpendError::Overdrawn(i) => Err::Overdrawn(*i),
    }
}

/// Spend, asserting that a failure leaves the ledger identical.
fn try_spend(ledger: &mut [Node], at: usize, amount: u128) -> Result<(), Err> {
    let before = snapshot(ledger);
    let checked = check_spend(ledger, at, amount).map_err(|e| err(&e));
    let result = spend(ledger, at, amount).map_err(|e| err(&e));
    assert_eq!(checked, result, "check_spend and spend disagree");
    if result.is_err() {
        assert_eq!(
            snapshot(ledger),
            before,
            "a failed spend changed the ledger"
        );
    }
    result
}

#[test]
fn oversubscribed_siblings_share_the_parent() {
    // Root 10, two children of 8 each: 16 promised against 10.
    let mut l = vec![node(None, 10, 0), node(Some(0), 8, 0), node(Some(0), 8, 0)];
    assert_eq!(try_spend(&mut l, 1, 8), Ok(()));
    assert_eq!(spent(&l), [8, 8, 0]);
    // The second child is within its own allowance, but the root has 2 left.
    assert_eq!(try_spend(&mut l, 2, 3), Err(Err::Overdrawn(0)));
    assert_eq!(try_spend(&mut l, 2, 2), Ok(()));
    assert_eq!(spent(&l), [10, 8, 2]);
    assert_eq!(try_spend(&mut l, 2, 1), Err(Err::Overdrawn(0)));
    assert_eq!(try_spend(&mut l, 1, 1), Err(Err::Overdrawn(1)));
}

#[test]
fn spend_exhausting_a_middle_ancestor() {
    // Root 100 > middle 10 < leaf 50.
    let mut l = vec![
        node(None, 100, 0),
        node(Some(0), 10, 0),
        node(Some(1), 50, 0),
    ];
    assert_eq!(try_spend(&mut l, 2, 10), Ok(()));
    assert_eq!(spent(&l), [10, 10, 10]);
    // The leaf and the root have room; the middle does not.
    assert_eq!(try_spend(&mut l, 2, 1), Err(Err::Overdrawn(1)));
    // The middle's sibling, directly under the root, is unaffected.
    l.push(node(Some(0), 5, 0));
    assert_eq!(try_spend(&mut l, 3, 5), Ok(()));
    assert_eq!(spent(&l), [15, 10, 10, 5]);
    // A refill of the named node lets the spend through.
    assert!(refill(&mut l, 1, 1).is_ok());
    assert_eq!(try_spend(&mut l, 2, 1), Ok(()));
    assert_eq!(spent(&l), [16, 11, 11, 5]);
}

#[test]
fn error_names_the_first_overdrawn_node_from_the_spender() {
    let mut l = vec![node(None, 1, 0), node(Some(0), 1, 0), node(Some(1), 1, 0)];
    assert_eq!(try_spend(&mut l, 2, 2), Err(Err::Overdrawn(2)));
    l[2].allowance = 5;
    assert_eq!(try_spend(&mut l, 2, 2), Err(Err::Overdrawn(1)));
    l[1].allowance = 5;
    assert_eq!(try_spend(&mut l, 2, 2), Err(Err::Overdrawn(0)));
    l[0].allowance = 5;
    assert_eq!(try_spend(&mut l, 2, 2), Ok(()));
}

#[test]
fn zero_spend_succeeds_on_an_exhausted_chain() {
    let mut l = vec![node(None, 3, 3), node(Some(0), 3, 3)];
    assert_eq!(try_spend(&mut l, 1, 0), Ok(()));
    assert_eq!(spent(&l), [3, 3]);
    assert_eq!(try_spend(&mut l, 1, 1), Err(Err::Overdrawn(1)));
}

#[test]
fn overflow_fails_safely() {
    let max = u128::MAX;
    // The sum overflows at the spender.
    let mut l = vec![node(None, max, 0), node(Some(0), max, max - 1)];
    assert_eq!(try_spend(&mut l, 1, 2), Err(Err::Overdrawn(1)));
    assert_eq!(try_spend(&mut l, 1, max), Err(Err::Overdrawn(1)));
    // Exactly reaching u128::MAX is fine.
    assert_eq!(try_spend(&mut l, 1, 1), Ok(()));
    assert_eq!(spent(&l), [1, max]);
    // The sum overflows at an ancestor after the spender passed.
    let mut l = vec![node(None, max, max), node(Some(0), max, 0)];
    assert_eq!(try_spend(&mut l, 1, 1), Err(Err::Overdrawn(0)));
    assert_eq!(try_spend(&mut l, 1, max), Err(Err::Overdrawn(0)));
    assert_eq!(spent(&l), [max, 0]);
}

#[test]
fn refill_overflow_and_missing_node_change_nothing() {
    let max = u128::MAX;
    let mut l = vec![node(None, max - 1, 0)];
    let before = snapshot(&l);
    assert!(matches!(
        refill(&mut l, 0, 2),
        Err(RefillError::Overflow(0))
    ));
    assert!(matches!(
        refill(&mut l, 1, 1),
        Err(RefillError::NoSuchNode(1))
    ));
    assert_eq!(snapshot(&l), before);
    assert!(refill(&mut l, 0, 1).is_ok());
    assert_eq!(l[0].allowance, max);
    assert_eq!(l[0].spent, 0);
}

#[test]
fn malformed_ledgers_fail_without_change() {
    let mut empty: Vec<Node> = vec![];
    assert_eq!(try_spend(&mut empty, 0, 1), Err(Err::NoSuchNode(0)));
    let mut l = vec![node(None, 10, 0), node(Some(0), 10, 0)];
    assert_eq!(try_spend(&mut l, 2, 1), Err(Err::NoSuchNode(2)));
    // A self-link and a forward link both break "parents come first".
    let mut l = vec![node(Some(0), 10, 0)];
    assert_eq!(try_spend(&mut l, 0, 1), Err(Err::BadParent(0)));
    let mut l = vec![
        node(None, 10, 0),
        node(Some(2), 10, 0),
        node(Some(1), 10, 0),
    ];
    assert_eq!(try_spend(&mut l, 2, 1), Err(Err::BadParent(1)));
    // The walk checks each node's allowance before its parent link.
    assert_eq!(try_spend(&mut l, 2, 11), Err(Err::Overdrawn(2)));
}

/// A plain-Rust reading of the semantics: the chain from `at` to its root,
/// spender first, or the first error.
fn reference_chain(
    l: &[(Option<usize>, u128, u128)],
    at: usize,
    amount: u128,
) -> Result<Vec<usize>, Err> {
    let mut chain = vec![];
    let mut current = at;
    loop {
        let Some(&(parent, allowance, spent)) = l.get(current) else {
            return Err(Err::NoSuchNode(current));
        };
        if spent.checked_add(amount).is_none_or(|t| t > allowance) {
            return Err(Err::Overdrawn(current));
        }
        chain.push(current);
        match parent {
            None => return Ok(chain),
            Some(p) if p < current => current = p,
            Some(_) => return Err(Err::BadParent(current)),
        }
    }
}

/// Whether `a` is `i` or one of its ancestors.
fn within(l: &[(Option<usize>, u128, u128)], i: usize, a: usize) -> bool {
    let mut current = i;
    loop {
        if current == a {
            return true;
        }
        match l[current].0 {
            Some(p) if p < current => current = p,
            _ => return false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Op {
    Spend(usize, u128),
    Refill(usize, u128),
}

/// Every sequence of up to `max_len` ops drawn from `universe`.
fn sequences(universe: &[Op], max_len: usize) -> Vec<Vec<Op>> {
    let mut out = vec![vec![]];
    let mut frontier = vec![vec![]];
    for _ in 0..max_len {
        let mut next = vec![];
        for seq in &frontier {
            for op in universe {
                let mut longer: Vec<Op> = seq.clone();
                longer.push(*op);
                next.push(longer);
            }
        }
        out.extend(next.iter().cloned());
        frontier = next;
    }
    out
}

/// Over every run of up to four ops on an oversubscribed tree:
///
/// - `spend` agrees with the reference chain;
/// - a success charges exactly the chain by the amount and changes nothing
///   else; a failure changes nothing;
/// - every node's spent stays within its allowance;
/// - each node's spent equals the total of successful spends at or under it,
///   so that total never exceeds the node's allowance.
#[test]
fn exhaustive_runs_on_an_oversubscribed_tree() {
    let max = u128::MAX;
    // 0: root 10. 1, 2: children of 0 with 8 each (oversubscribed).
    // 3: child of 1 with 20 (more than its parent). 4: a second root at u128::MAX.
    let start = || {
        vec![
            node(None, 10, 0),
            node(Some(0), 8, 0),
            node(Some(0), 8, 0),
            node(Some(1), 20, 0),
            node(None, max, 0),
        ]
    };
    let universe = [
        Op::Spend(3, 5),
        Op::Spend(2, 4),
        Op::Spend(1, 3),
        Op::Spend(0, 0),
        Op::Spend(4, max),
        Op::Spend(4, 1),
        Op::Spend(5, 1),
        Op::Refill(1, 4),
        Op::Refill(0, 5),
        Op::Refill(0, max),
    ];
    let (mut successes, mut failures) = (0usize, 0usize);
    for ops in sequences(&universe, 4) {
        let mut l = start();
        let mut log: Vec<(usize, u128)> = vec![];
        for op in &ops {
            let before = snapshot(&l);
            match *op {
                Op::Spend(at, amount) => {
                    let expected = reference_chain(&before, at, amount);
                    let got = spend(&mut l, at, amount).map_err(|e| err(&e));
                    match expected {
                        Ok(chain) => {
                            assert_eq!(got, Ok(()), "{ops:?}");
                            successes += 1;
                            log.push((at, amount));
                            for (j, (b, a)) in before.iter().zip(snapshot(&l)).enumerate() {
                                let charged = if chain.contains(&j) { amount } else { 0 };
                                assert_eq!((b.0, b.1, b.2 + charged), a, "{ops:?}");
                            }
                        }
                        Err(e) => {
                            assert_eq!(got, Err(e), "{ops:?}");
                            failures += 1;
                            assert_eq!(snapshot(&l), before, "{ops:?}");
                        }
                    }
                }
                Op::Refill(at, extra) => {
                    let got = refill(&mut l, at, extra);
                    let after = snapshot(&l);
                    if let Some(Some(raised)) = before.get(at).map(|n| n.1.checked_add(extra)) {
                        assert!(got.is_ok());
                        assert_eq!(after[at], (before[at].0, raised, before[at].2));
                    } else {
                        assert!(got.is_err());
                        assert_eq!(after, before);
                    }
                }
            }
            let now = snapshot(&l);
            for (a, &(_, allowance, spent)) in now.iter().enumerate() {
                assert!(spent <= allowance, "{ops:?}");
                let under: u128 = log
                    .iter()
                    .filter(|&&(i, _)| within(&now, i, a))
                    .map(|&(_, x)| x)
                    .sum();
                assert_eq!(under, spent, "{ops:?}");
            }
        }
    }
    assert!(
        successes > 1_000 && failures > 1_000,
        "{successes} {failures}"
    );
}
