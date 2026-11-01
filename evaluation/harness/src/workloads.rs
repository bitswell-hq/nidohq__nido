//! The scripted agent sessions replayed at the Soroban boundary
//! (`soroban::workloads`). Each is a sequence of admin steps (the owner's)
//! and agent calls, with the outcome each call is expected to have.

/// A contract the session names.
#[derive(Clone, Copy, Debug)]
pub enum Target {
    /// The budget asset.
    Asset,
    /// The other token the account holds.
    Other,
    /// Instance `i` of the evaluation dApp.
    Dapp(usize),
}

/// A party the session pays.
#[derive(Clone, Copy, Debug)]
pub enum Who {
    Bob,
    Carol,
}

#[derive(Clone, Debug)]
pub enum CaveatSpec {
    ContractIn(Vec<Target>),
    FunctionIn(Vec<&'static str>),
    /// Argument `index` is this party's address.
    ArgIs(u32, Who),
    /// Argument `index` is an `i128` of at most this.
    AmountAtMost(u32, i128),
}

#[derive(Clone, Debug)]
pub enum Call {
    /// `token.transfer(account, to, amount)`.
    Transfer {
        token: Target,
        to: Who,
        amount: i128,
    },
    /// `dapp.forward(account, token, to, amount)`: one nested transfer.
    Forward {
        dapp: usize,
        token: Target,
        to: Who,
        amount: i128,
    },
    /// `dapp[path[0]].hop(…)` through every instance of `path`, then the
    /// transfer: `path.len() + 1` contexts deep.
    Hop {
        path: Vec<usize>,
        token: Target,
        to: Who,
        amount: i128,
    },
}

/// What a call is expected to do: be allowed, or be refused with this
/// grant signer error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    Allowed,
    NotAllowed,
    Overdrawn,
}

#[derive(Clone, Debug)]
pub enum Step {
    /// The owner issues a root grant over the budget asset.
    Issue {
        agent: &'static str,
        caveats: Vec<CaveatSpec>,
        allowance: u128,
    },
    /// `from`'s holder delegates to a sub-agent `agent`.
    Delegate {
        from: &'static str,
        agent: &'static str,
        caveats: Vec<CaveatSpec>,
        allowance: u128,
    },
    Call {
        agent: &'static str,
        call: Call,
        expect: Expect,
    },
}

pub struct Workload {
    pub name: &'static str,
    pub steps: Vec<Step>,
}

/// Agent names to holder-key seeds.
#[must_use]
pub fn seed(agent: &str) -> u8 {
    match agent {
        "payments" => 101,
        "payroll" => 102,
        "router" => 103,
        "swapper" => 104,
        _ => 199,
    }
}

fn pay(agent: &'static str, to: Who, amount: i128, expect: Expect) -> Step {
    Step::Call {
        agent,
        call: Call::Transfer {
            token: Target::Asset,
            to,
            amount,
        },
        expect,
    }
}

/// A payments agent with a per-call cap and a budget, and a payroll
/// sub-agent pinned to one payee with its own allowance.
#[must_use]
pub fn payments() -> Workload {
    use Expect::{Allowed, NotAllowed, Overdrawn};
    Workload {
        name: "payments",
        steps: vec![
            Step::Issue {
                agent: "payments",
                caveats: vec![
                    CaveatSpec::ContractIn(vec![Target::Asset]),
                    CaveatSpec::FunctionIn(vec!["transfer"]),
                    CaveatSpec::AmountAtMost(2, 100),
                ],
                allowance: 400,
            },
            pay("payments", Who::Bob, 50, Allowed),
            pay("payments", Who::Carol, 80, Allowed),
            pay("payments", Who::Bob, 120, NotAllowed),
            Step::Delegate {
                from: "payments",
                agent: "payroll",
                caveats: vec![CaveatSpec::ArgIs(1, Who::Bob)],
                allowance: 150,
            },
            pay("payroll", Who::Bob, 60, Allowed),
            pay("payroll", Who::Bob, 60, Allowed),
            pay("payroll", Who::Bob, 60, Overdrawn),
            pay("payroll", Who::Carol, 10, NotAllowed),
            pay("payments", Who::Bob, 100, Allowed),
            pay("payments", Who::Bob, 100, Overdrawn),
        ],
    }
}

/// A DeFi-router agent whose calls nest the account's transfers up to four
/// contexts deep, and a swapper sub-agent narrowed to the direct router.
#[must_use]
pub fn defi_router() -> Workload {
    use Expect::{Allowed, NotAllowed, Overdrawn};
    let forward = |agent, token, to, amount, expect| Step::Call {
        agent,
        call: Call::Forward {
            dapp: 0,
            token,
            to,
            amount,
        },
        expect,
    };
    let hop = |agent, path: Vec<usize>, to, amount, expect| Step::Call {
        agent,
        call: Call::Hop {
            path,
            token: Target::Asset,
            to,
            amount,
        },
        expect,
    };
    Workload {
        name: "defi-router",
        steps: vec![
            Step::Issue {
                agent: "router",
                caveats: vec![
                    CaveatSpec::ContractIn(vec![
                        Target::Dapp(0),
                        Target::Dapp(1),
                        Target::Dapp(2),
                        Target::Asset,
                    ]),
                    CaveatSpec::FunctionIn(vec!["forward", "hop", "transfer"]),
                ],
                allowance: 300,
            },
            forward("router", Target::Asset, Who::Bob, 40, Allowed),
            hop("router", vec![0, 1], Who::Bob, 30, Allowed),
            hop("router", vec![0, 1, 2], Who::Carol, 20, Allowed),
            Step::Delegate {
                from: "router",
                agent: "swapper",
                caveats: vec![
                    CaveatSpec::ContractIn(vec![Target::Dapp(0), Target::Asset]),
                    CaveatSpec::FunctionIn(vec!["forward", "transfer"]),
                ],
                allowance: 100,
            },
            forward("swapper", Target::Asset, Who::Bob, 50, Allowed),
            hop("swapper", vec![0, 1], Who::Bob, 10, NotAllowed),
            forward("swapper", Target::Asset, Who::Bob, 60, Overdrawn),
            forward("swapper", Target::Other, Who::Bob, 5, NotAllowed),
            forward("router", Target::Asset, Who::Carol, 200, Overdrawn),
        ],
    }
}

#[must_use]
pub fn all() -> Vec<Workload> {
    vec![payments(), defi_router()]
}
