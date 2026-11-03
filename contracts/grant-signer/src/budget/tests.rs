//! The budget path against `grant_eval::budget`, the ledger `formal/`
//! proves, on lineage ledgers as the contract builds them (root first, each
//! node's parent the one before it).
//!
//! Every run starts from a lineage of one to six grants whose allowances and
//! spent amounts are at most `i128::MAX`, as the contract stores them, and
//! takes four steps: a refill of one grant, an `overdrawn_at` check at the
//! signing grant, or a batch of transfers charged at the signing grant. Each
//! step's outcome, the overdrawn grant and the ledger after it agree, except
//! for the one stated difference: a refill whose `extra` or raised allowance
//! is above `i128::MAX`, which `grant_eval` takes and the contract refuses
//! with `AllowanceTooLarge`. That ends the run, since the two ledgers then
//! differ by design.

extern crate std;

use alloc::vec::Vec;
use grant_eval::budget as g;

use super::{chain, overdrawn_at, refill, spend_all};
use crate::error::GrantError as Error;

const MAX: u128 = i128::MAX as u128;

/// The `SplitMix64` generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// An amount a grant holds or a transfer moves: at most `i128::MAX`,
    /// weighted toward zero, small values and the bound.
    fn amount(&mut self) -> u128 {
        match self.below(6) {
            0 => 0,
            1 => u128::from(self.below(20)),
            2 => MAX,
            3 => MAX - u128::from(self.below(3)),
            _ => u128::from(self.below(1000)),
        }
    }

    /// Any `u128`, as a refill's `extra` or an `overdrawn_at` amount: an
    /// [`Rng::amount`], or one above `i128::MAX`.
    fn wide(&mut self) -> u128 {
        match self.below(6) {
            0 => MAX + 1 + u128::from(self.below(3)),
            1 => u128::MAX - u128::from(self.below(3)),
            _ => self.amount(),
        }
    }
}

#[derive(Default)]
struct Counts {
    spends_accepted: u32,
    spends_overdrawn: u32,
    fits: u32,
    overdrawn_at_spender: u32,
    overdrawn_at_ancestor: u32,
    overdrawn_above_i128: u32,
    refills: u32,
    refills_above_i128: u32,
}

/// One run: the contract's view of a lineage, as each grant's allowance and
/// spent amount, and `grant_eval`'s ledger of it.
struct Run {
    grants: Vec<(u128, u128)>,
    ledger: Vec<g::Node>,
}

impl Run {
    fn new(rng: &mut Rng) -> Self {
        let n = 1 + usize::try_from(rng.below(6)).unwrap();
        let mut run = Run {
            grants: Vec::new(),
            ledger: Vec::new(),
        };
        for i in 0..n {
            let allowance = rng.amount();
            let spent = if rng.below(4) == 0 {
                0
            } else {
                rng.amount().min(allowance)
            };
            run.grants.push((allowance, spent));
            run.ledger.push(g::Node {
                parent: i.checked_sub(1),
                allowance,
                spent,
            });
        }
        run
    }

    fn spender(&self) -> usize {
        self.grants.len() - 1
    }

    /// A refill of one grant. Returns `false` on the stated difference.
    fn refill(&mut self, rng: &mut Rng, c: &mut Counts) -> bool {
        let node = usize::try_from(rng.below(self.grants.len() as u64)).unwrap();
        let extra = rng.wide();
        let (allowance, spent) = self.grants[node];
        let ours = refill(allowance, spent, extra);
        match allowance.checked_add(extra) {
            Some(raised) if raised <= MAX => {
                assert!(g::refill(&mut self.ledger, node, extra).is_ok());
                assert_eq!(ours, Ok(raised));
                self.grants[node].0 = raised;
                c.refills += 1;
                true
            }
            _ => {
                assert_eq!(ours, Err(Error::AllowanceTooLarge));
                c.refills_above_i128 += 1;
                false
            }
        }
    }

    /// `overdrawn_at` at the signing grant against `check_spend`.
    fn check(&self, rng: &mut Rng, c: &mut Counts) {
        let amount = rng.wide();
        let ours = overdrawn_at(&chain(&self.grants).unwrap(), amount);
        let theirs = match g::check_spend(&self.ledger, self.spender(), amount) {
            Ok(()) => None,
            Err(g::SpendError::Overdrawn(i)) => Some(i),
            Err(g::SpendError::NoSuchNode(_) | g::SpendError::BadParent(_)) => {
                panic!("a lineage ledger is well formed")
            }
        };
        assert_eq!(ours, theirs, "overdrawn grant differs");
        match ours {
            None => c.fits += 1,
            Some(_) if amount > MAX => c.overdrawn_above_i128 += 1,
            Some(i) if i == self.spender() => c.overdrawn_at_spender += 1,
            Some(_) => c.overdrawn_at_ancestor += 1,
        }
    }

    /// One authorization's transfers, charged at the signing grant.
    fn spend(&mut self, rng: &mut Rng, c: &mut Counts) {
        let amounts: Vec<u128> = (0..=rng.below(3)).map(|_| rng.amount()).collect();
        let ours = spend_all(chain(&self.grants).unwrap(), &amounts);
        // The contract's previous loop: `grant_eval::budget::spend` per
        // transfer on a copy, kept only if every one succeeds.
        let mut after: Vec<g::Node> = self
            .ledger
            .iter()
            .map(|n| g::Node {
                parent: n.parent,
                allowance: n.allowance,
                spent: n.spent,
            })
            .collect();
        let spender = self.spender();
        let theirs = amounts
            .iter()
            .all(|&a| g::spend(&mut after, spender, a).is_ok());
        match ours {
            Ok(spent) => {
                assert!(theirs, "spend accepted only by the contract");
                for (grant, s) in self.grants.iter_mut().zip(spent) {
                    grant.1 = s;
                }
                self.ledger = after;
                c.spends_accepted += 1;
            }
            Err(e) => {
                assert_eq!(e, Error::Overdrawn);
                assert!(!theirs, "spend accepted only by grant_eval");
                c.spends_overdrawn += 1;
            }
        }
    }

    /// Both hold the same allowances and spent amounts.
    fn assert_same(&self) {
        assert_eq!(self.grants.len(), self.ledger.len());
        for (&(allowance, spent), n) in self.grants.iter().zip(&self.ledger) {
            assert_eq!((allowance, spent), (n.allowance, n.spent));
        }
    }
}

#[test]
fn budget_path_agrees_with_grant_eval_on_lineage_ledgers() {
    let mut rng = Rng(20_261_103);
    let mut c = Counts::default();
    for _ in 0..200_000 {
        let mut run = Run::new(&mut rng);
        for _ in 0..4 {
            match rng.below(5) {
                0 => {
                    if !run.refill(&mut rng, &mut c) {
                        // The ledgers now differ by design.
                        break;
                    }
                }
                1 => run.check(&mut rng, &mut c),
                _ => run.spend(&mut rng, &mut c),
            }
            run.assert_same();
        }
    }
    std::println!(
        "spends accepted {}, overdrawn {}; overdrawn_at fits {}, at the spender {}, \
         at an ancestor {}, above i128::MAX {}; refills {}, above i128::MAX (refused) {}",
        c.spends_accepted,
        c.spends_overdrawn,
        c.fits,
        c.overdrawn_at_spender,
        c.overdrawn_at_ancestor,
        c.overdrawn_above_i128,
        c.refills,
        c.refills_above_i128,
    );
    // Every kind of outcome is reached, so the agreement is not vacuous.
    for (what, count) in [
        ("spends accepted", c.spends_accepted),
        ("spends overdrawn", c.spends_overdrawn),
        ("checks that fit", c.fits),
        ("overdrawn at the spender", c.overdrawn_at_spender),
        ("overdrawn at an ancestor", c.overdrawn_at_ancestor),
        ("overdrawn above i128::MAX", c.overdrawn_above_i128),
        ("refills", c.refills),
        ("refills above i128::MAX", c.refills_above_i128),
    ] {
        assert!(count > 0, "no run reached: {what}");
    }
}

#[test]
fn amounts_up_to_i128_max_are_taken_and_larger_ones_refused() {
    assert_eq!(refill(0, 0, MAX), Ok(MAX));
    assert_eq!(refill(MAX, MAX, 0), Ok(MAX));
    assert_eq!(refill(0, 0, MAX + 1), Err(Error::AllowanceTooLarge));
    assert_eq!(refill(1, 0, MAX), Err(Error::AllowanceTooLarge));
    assert_eq!(refill(1, 0, u128::MAX), Err(Error::AllowanceTooLarge));

    assert!(chain(&[(MAX, MAX), (MAX, 0)]).is_ok());
    assert_eq!(
        chain(&[(MAX, 0), (MAX + 1, 0)]).err(),
        Some(Error::AllowanceTooLarge)
    );

    let tree = chain(&[(MAX, 0), (MAX, 0)]).unwrap();
    assert_eq!(overdrawn_at(&tree, MAX), None);
    assert_eq!(overdrawn_at(&tree, MAX + 1), Some(1));
    assert_eq!(spend_all(tree, &[MAX]), Ok(alloc::vec![MAX, MAX]));
}
