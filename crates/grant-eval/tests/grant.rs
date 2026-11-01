//! The generic grant over a toy vocabulary: actions are `u8`, caveats are
//! upper bounds.

mod common;

use grant_eval::{allows, allows_all, Check};

struct AtMost(u8);

impl Check<u8> for AtMost {
    fn holds(&self, action: &u8) -> bool {
        *action <= self.0
    }
}

#[test]
fn empty_grant_allows_every_action() {
    let empty: [AtMost; 0] = [];
    for a in 0..=u8::MAX {
        assert!(allows(&empty, &a));
    }
    assert!(allows_all(&empty, &[0, 255]));
}

#[test]
fn allows_requires_every_caveat() {
    let grant = [AtMost(10), AtMost(5)];
    assert!(allows(&grant, &5));
    assert!(!allows(&grant, &6));
    assert!(!allows(&grant, &11));
}

#[test]
fn allows_all_requires_every_action() {
    let grant = [AtMost(10)];
    assert!(allows_all(&grant, &[]));
    assert!(allows_all(&grant, &[0, 10, 3]));
    assert!(!allows_all(&grant, &[0, 11, 3]));
    assert!(!allows_all(&grant, &[0, 3, 11]));
}

#[test]
fn exhaustive_attenuation_and_reference_agreement() {
    let bounds = [0u8, 1, 5, 254, 255];
    let actions = [0u8, 1, 2, 5, 6, 254, 255];
    let seen = common::check_exhaustive(
        |i| AtMost(bounds[i]),
        bounds.len(),
        |i| actions[i],
        actions.len(),
        |c, a| *a <= c.0,
    );
    assert!(seen.checks > 10_000, "{seen:?}");
}
