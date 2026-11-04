//! The chain vocabulary against `rule_eval` on generated grants and
//! contexts: on every grant that names its contracts,
//! `grant_eval::chain::allows_all(grant, actions)` equals `rule_eval::allows_all`
//! over the grant's rule set (`lowering`), and `allows` on each action equals
//! `rule_eval::allows`.
//!
//! Grants are one to six caveats over a small alphabet, at least one of them
//! `ContractIn`; batches are zero to four actions. The alphabet makes payloads
//! collide across value constructors (the same bytes as `Bytes`, `Address`,
//! `Symbol` and `Other`), lists empty and repeated, argument indices past the
//! last argument and at `u32::MAX`, and bounds at the `i128` extremes, so
//! that most comparisons are near a verdict's boundary.

mod lowering;

use grant_eval::chain::{Action, Caveat, Val};

const RUNS: usize = 200_000;

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

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }

    fn pick<T: Clone>(&mut self, list: &[T]) -> T {
        list[self.below(list.len())].clone()
    }

    fn ids(&mut self, alphabet: &[&[u8]]) -> Vec<Vec<u8>> {
        (0..self.below(4))
            .map(|_| self.pick(alphabet).to_vec())
            .collect()
    }

    fn index(&mut self) -> u32 {
        self.pick(&[0, 0, 1, 1, 2, 3, u32::MAX])
    }

    fn bytes(&mut self) -> Vec<u8> {
        self.pick(&[&b""[..], b"CA", b"transfer", &[0, 0, 0, 3, 0, 0, 0, 1]])
            .to_vec()
    }

    fn val(&mut self) -> Val {
        match self.below(7) {
            0 => Val::I128(self.pick(&[i128::MIN, -1, 0, 1, 100, 101, i128::MAX])),
            1 => Val::U64(self.pick(&[0, 1, 100, u64::MAX])),
            2 => Val::Bool(self.below(2) == 0),
            3 => Val::Bytes(self.bytes()),
            4 => Val::Address(self.bytes()),
            5 => Val::Symbol(self.bytes()),
            _ => Val::Other(self.bytes()),
        }
    }

    fn caveat(&mut self) -> Caveat {
        match self.below(5) {
            0 => Caveat::ContractIn(self.ids(CONTRACTS)),
            1 => Caveat::FunctionIn(self.ids(FUNCTIONS)),
            2 => {
                Caveat::ArgI128AtMost(self.index(), self.pick(&[i128::MIN, -1, 0, 100, i128::MAX]))
            }
            _ => Caveat::ArgEq(self.index(), self.val()),
        }
    }

    fn grant(&mut self) -> Vec<Caveat> {
        let mut grant: Vec<Caveat> = (0..self.below(6)).map(|_| self.caveat()).collect();
        let at = self.below(grant.len() + 1);
        let named = Caveat::ContractIn(self.ids(CONTRACTS));
        grant.insert(at, named);
        grant
    }

    fn action(&mut self) -> Action {
        if self.below(12) == 0 {
            return Action::CreateContract {
                wasm_hash: self.bytes(),
            };
        }
        Action::Invoke {
            contract: self.pick(CONTRACTS).to_vec(),
            function: self.pick(FUNCTIONS).to_vec(),
            args: (0..self.below(4)).map(|_| self.val()).collect(),
        }
    }
}

const CONTRACTS: &[&[u8]] = &[b"CA", b"CB", b"CC", b"transfer"];
const FUNCTIONS: &[&[u8]] = &[b"transfer", b"swap", b"CA", b""];

#[test]
fn generated_grants_and_contexts_agree() {
    let mut rng = Rng(0x6e32_7275_6c65_7365);
    let mut seen = lowering::Seen::default();
    for _ in 0..RUNS {
        let grant = rng.grant();
        let actions: Vec<Action> = (0..rng.below(5)).map(|_| rng.action()).collect();
        lowering::agree(&grant, &actions, &mut seen);
    }
    println!("{seen:?}");
    assert_eq!(seen.compared, RUNS);
    assert!(
        seen.allowed > RUNS / 20 && seen.denied > RUNS / 20,
        "{seen:?}"
    );
}
