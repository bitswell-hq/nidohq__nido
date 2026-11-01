//! Exhaustive checks over small generated grants and actions.
//!
//! Each vocabulary's test file supplies a finite universe of caveats and
//! actions as constructors indexed `0..n`, plus a reference predicate written
//! in plain idiomatic Rust (`==`, `starts_with`, `iter().any`). The checks
//! build every grant of up to `MAX_LEN` caveats from the universe.

use grant_eval::{allows, allows_all, Check};

const MAX_LEN: usize = 3;

/// Every sequence of up to `max_len` indices below `n`.
fn sequences(n: usize, max_len: usize) -> Vec<Vec<usize>> {
    let mut out = vec![Vec::new()];
    let mut frontier = vec![Vec::new()];
    for _ in 0..max_len {
        let mut next = Vec::new();
        for seq in &frontier {
            for i in 0..n {
                let mut longer = seq.clone();
                longer.push(i);
                next.push(longer);
            }
        }
        out.extend(next.iter().cloned());
        frontier = next;
    }
    out
}

fn build<T>(indices: &[usize], make: &impl Fn(usize) -> T) -> Vec<T> {
    indices.iter().map(|&i| make(i)).collect()
}

/// Counts of what the exhaustive run observed, so a test can assert it was
/// not vacuous.
#[derive(Debug, Default)]
pub struct Observed {
    pub checks: usize,
    pub allowed: usize,
    pub denied: usize,
}

/// Attenuation monotonicity: inserting a caveat at any position of any grant
/// never turns a denial into an allow. The stronger statement checked is
/// `allows(g with c inserted, a) == allows(g, a) && holds(c, a)`.
///
/// Also checks `allows` against `reference` (every caveat satisfies the
/// reference predicate), and `allows_all` on every pair of actions against
/// `allows` on each.
pub fn check_exhaustive<A, C: Check<A>>(
    caveat: impl Fn(usize) -> C,
    n_caveats: usize,
    action: impl Fn(usize) -> A,
    n_actions: usize,
    reference: impl Fn(&C, &A) -> bool,
) -> Observed {
    let mut seen = Observed::default();
    let actions: Vec<A> = (0..n_actions).map(&action).collect();
    for seq in sequences(n_caveats, MAX_LEN) {
        let grant = build(&seq, &caveat);
        for a in &actions {
            let base = allows(&grant, a);
            assert_eq!(
                base,
                grant.iter().all(|c| reference(c, a)),
                "allows disagrees with the reference for grant {seq:?}"
            );
            if base {
                seen.allowed += 1;
            } else {
                seen.denied += 1;
            }
            for extra in 0..n_caveats {
                let holds = caveat(extra).holds(a);
                for pos in 0..=seq.len() {
                    let mut narrowed_seq = seq.clone();
                    narrowed_seq.insert(pos, extra);
                    let narrowed = build(&narrowed_seq, &caveat);
                    let after = allows(&narrowed, a);
                    assert!(
                        base || !after,
                        "adding caveat {extra} at {pos} to {seq:?} turned a denial into an allow"
                    );
                    assert_eq!(after, base && holds, "grant {narrowed_seq:?}");
                    seen.checks += 1;
                }
            }
        }
        for i in 0..n_actions {
            for j in 0..n_actions {
                let pair = [action(i), action(j)];
                assert_eq!(
                    allows_all(&grant, &pair),
                    allows(&grant, &pair[0]) && allows(&grant, &pair[1]),
                    "allows_all on actions {i}, {j} with grant {seq:?}"
                );
            }
        }
    }
    assert!(seen.allowed > 0 && seen.denied > 0, "{seen:?}");
    seen
}
