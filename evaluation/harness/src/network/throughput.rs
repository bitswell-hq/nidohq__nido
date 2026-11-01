//! Relay throughput against the size of the channel pool, and sibling
//! sub-agents spending at once through the relay against a shared ancestor's
//! allowance.
//!
//! Every transaction is an agent's budget-asset transfer through the grant
//! signer of a factory-minted account, built and signed before the clock
//! starts (the fixture's host is single-threaded); client threads then send
//! them to the relay as the browser does and wait for each to settle.

use std::collections::VecDeque;
use std::sync::{Arc, Barrier, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};
use soroban_sdk::xdr::{HostFunction, SorobanAuthorizationEntry};

use super::relay::{Handle, Reply, Running};
use super::Net;
use crate::soroban::attacks::delegate_setup;
use crate::soroban::fixture::{agent, Fixture, GrantView};

/// One prepared call: the host function, its signed entries and the API key
/// of the agent that sends it.
#[derive(Clone)]
struct Prepared {
    api_key: String,
    func: HostFunction,
    auth: Vec<SorobanAuthorizationEntry>,
}

/// A budget-asset transfer of `amount` to Bob by grant `grant`'s holder
/// (seed `seed`), signed.
fn transfer(f: &Fixture, grant: u32, seed: u8, amount: i128) -> Prepared {
    let args = f.transfer_args(&f.bob, amount);
    let tree = f.node(&f.asset, "transfer", &args, std::vec![]);
    let entry = f.agent_entry(grant, &agent(seed), None, tree);
    Prepared {
        api_key: f.api_key(grant),
        func: super::invoke(
            &nido_integration_tests::world::strkey(&f.asset),
            "transfer",
            args.iter().map(|v| f.sc(v)).collect(),
        ),
        auth: vec![entry],
    }
}

/// What happened to one sent call.
#[derive(Clone, Debug, Serialize)]
pub struct Sent {
    pub api_key: String,
    /// Seconds from the run's start to the accepted submission.
    pub submitted_at: f64,
    /// Seconds from the accepted submission to the settled status.
    pub latency: f64,
    /// `CHANNELS_BUSY` answers before the submission was accepted.
    pub busy: u32,
    pub reply: Reply,
}

/// Send `calls` through `relay` from `clients` threads, each taking the next
/// call when its previous one has settled; a `CHANNELS_BUSY` answer puts the
/// call back after a short wait. With `together`, every client sends its
/// first call at the same instant.
fn drive(relay: &Handle, calls: Vec<Prepared>, clients: usize, together: bool) -> (Vec<Sent>, f64) {
    let queue = Arc::new(Mutex::new(calls.into_iter().collect::<VecDeque<_>>()));
    let out = Arc::new(Mutex::new(Vec::new()));
    let barrier = Arc::new(Barrier::new(clients));
    let start = Instant::now();
    std::thread::scope(|s| {
        for _ in 0..clients {
            let (queue, out, barrier) =
                (Arc::clone(&queue), Arc::clone(&out), Arc::clone(&barrier));
            s.spawn(move || {
                let mut first = true;
                loop {
                    let Some(call) = queue.lock().expect("queue").pop_front() else {
                        if first && together {
                            barrier.wait();
                        }
                        return;
                    };
                    if first && together {
                        barrier.wait();
                    }
                    first = false;
                    let mut busy = 0;
                    loop {
                        let at = start.elapsed().as_secs_f64();
                        let sent = Instant::now();
                        let reply = relay
                            .call(&call.api_key, &call.func, &call.auth)
                            .expect("the relay answers");
                        if reply.code.as_deref() == Some("CHANNELS_BUSY") {
                            busy += 1;
                            std::thread::sleep(Duration::from_millis(20));
                            continue;
                        }
                        out.lock().expect("results").push(Sent {
                            api_key: call.api_key.clone(),
                            submitted_at: at,
                            latency: sent.elapsed().as_secs_f64(),
                            busy,
                            reply,
                        });
                        break;
                    }
                }
            });
        }
    });
    let wall = start.elapsed().as_secs_f64();
    let sent = Arc::try_unwrap(out)
        .expect("threads done")
        .into_inner()
        .expect("results");
    (sent, wall)
}

/// The including ledger of each submitted transaction and, for one that
/// failed on chain, why.
fn settle_details(net: &Net, sent: &mut [Sent], signer: &str) {
    for s in sent {
        super::relay::settle(&net.rpc, &mut s.reply, signer);
    }
}

/// Throughput at one pool size.
#[derive(Debug, Serialize)]
pub struct Point {
    pub channels: usize,
    pub clients: usize,
    pub transactions: usize,
    pub confirmed: usize,
    pub failed: usize,
    pub refused: usize,
    pub busy_answers: u32,
    pub wall_seconds: f64,
    pub confirmed_per_second: f64,
    pub first_ledger: Option<u32>,
    pub last_ledger: Option<u32>,
    /// Confirmed transactions per ledger that included any.
    pub per_ledger: Vec<(u32, usize)>,
    pub latency_median: f64,
    pub latency_p90: f64,
    pub latency_max: f64,
    pub sent: Vec<Sent>,
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss
    )]
    let i = ((sorted.len() - 1) as f64 * q).round() as usize;
    sorted[i]
}

/// Relay throughput against the channel pool's size: at each size `n`, `2n`
/// clients send `per_channel * n` transfers by one agent, keeping every
/// channel leased.
///
/// # Errors
///
/// If the relay does not start.
#[allow(clippy::cast_precision_loss)]
pub fn sweep(net: &Arc<Net>, quick: bool) -> Result<Value, String> {
    let per_channel = if quick { 4 } else { 15 };
    let f = Fixture::on_network(net, "throughput", 0, None);
    let seed = 60;
    let grant = f.issue(
        &agent(seed),
        &[f.contract_in(&[&f.asset]), f.function_in(&["transfer"])],
        1_000_000,
    );
    let agents = f.relay_agents(net);
    let mut points = Vec::new();
    let ledger_interval = ledger_interval(net)?;
    for channels in [1usize, 2, 4, 8] {
        let calls: Vec<Prepared> = (0..per_channel * channels)
            .map(|_| transfer(&f, grant, seed, 1))
            .collect();
        let running = Running::start(net, &agents, &net.channels[..channels], 2 * channels + 2)?;
        let ledger_before = net.ledger()?;
        let (mut sent, wall) = drive(&running.handle(), calls, 2 * channels, false);
        drop(running);
        settle_details(
            net,
            &mut sent,
            &nido_integration_tests::world::strkey(&f.signer),
        );
        let confirmed = sent
            .iter()
            .filter(|s| s.reply.settled.as_deref() == Some("confirmed"))
            .count();
        let failed = sent
            .iter()
            .filter(|s| s.reply.settled.as_deref() == Some("failed"))
            .count();
        let mut lat: Vec<f64> = sent.iter().map(|s| s.latency).collect();
        lat.sort_by(f64::total_cmp);
        let mut per_ledger: Vec<(u32, usize)> = Vec::new();
        for s in sent
            .iter()
            .filter(|s| s.reply.settled.as_deref() == Some("confirmed"))
        {
            if let Some(l) = s.reply.ledger {
                match per_ledger.iter_mut().find(|(x, _)| *x == l) {
                    Some((_, n)) => *n += 1,
                    None => per_ledger.push((l, 1)),
                }
            }
        }
        per_ledger.sort_unstable();
        let point = Point {
            channels,
            clients: 2 * channels,
            transactions: sent.len(),
            confirmed,
            failed,
            refused: sent.len() - confirmed - failed,
            busy_answers: sent.iter().map(|s| s.busy).sum(),
            wall_seconds: wall,
            confirmed_per_second: confirmed as f64 / wall,
            first_ledger: Some(ledger_before),
            last_ledger: per_ledger.last().map(|p| p.0),
            per_ledger,
            latency_median: quantile(&lat, 0.5),
            latency_p90: quantile(&lat, 0.9),
            latency_max: lat.last().copied().unwrap_or_default(),
            sent,
        };
        eprintln!(
            "throughput: {channels} channel(s): {confirmed}/{} confirmed in {wall:.1} s, {:.2}/s",
            point.transactions, point.confirmed_per_second
        );
        points.push(point);
    }
    Ok(json!({
        "per_channel": per_channel,
        "ledger_interval_seconds": ledger_interval,
        "relay": {
            "poll_interval_ms": 250,
            "client_poll_interval_ms": 100,
            "busy_retry_ms": 20,
        },
        "points": points,
    }))
}

/// The mean time between ledger closes over the last ledgers the RPC server
/// holds.
fn ledger_interval(net: &Net) -> Result<f64, String> {
    let latest = net.ledger()?;
    let start = latest.saturating_sub(20).max(2);
    let r = net
        .rpc
        .call(
            "getLedgers",
            &json!({ "startLedger": start, "pagination": { "limit": 21 } }),
        )
        .map_err(|e| e.to_string())?;
    let times: Vec<u64> = r
        .get("ledgers")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|l| {
            l.get("ledgerCloseTime").and_then(|t| {
                t.as_str()
                    .and_then(|s| s.parse().ok())
                    .or_else(|| t.as_u64())
            })
        })
        .collect();
    match (times.first(), times.last()) {
        #[allow(clippy::cast_precision_loss)]
        (Some(a), Some(b)) if times.len() > 1 => Ok((b - a) as f64 / (times.len() - 1) as f64),
        _ => Err("getLedgers: no close times".into()),
    }
}

/// One round of siblings spending at once.
#[derive(Debug, Serialize)]
pub struct Round {
    pub number: usize,
    pub root_allowance: u128,
    pub sibling_allowance: u128,
    pub siblings: usize,
    pub amount: i128,
    pub sent: Vec<Sent>,
    pub before: Vec<GrantView>,
    pub after: Vec<GrantView>,
    /// What the root's budget node was charged.
    pub root_spent: u128,
    /// What the account's balance fell by, and Bob's rose by.
    pub account_paid: i128,
    pub bob_received: i128,
    pub within_allowance: bool,
    /// The root's charge, the account's payment and Bob's receipt are equal,
    /// and are the amount times the confirmed transfers.
    pub charges_match_transfers: bool,
    /// Each sibling's budget node was charged the amount if its transfer was
    /// confirmed, and nothing otherwise.
    pub siblings_charged_as_confirmed: bool,
}

/// Siblings delegated from one root grant, their allowances together far
/// over the root's, each sending a transfer at the same instant through the
/// relay on its own channel. Each relay simulation runs against the state
/// before any of them lands, so more are submitted than the root can pay
/// for; the chain applies them in order and the grant signer refuses those
/// past the root's allowance.
///
/// # Errors
///
/// If the relay does not start.
pub fn race(net: &Arc<Net>) -> Result<Value, String> {
    let (rounds, siblings, root_allowance, sibling_allowance, amount) =
        (3, 8, 100u128, 100u128, 30i128);
    let mut out = Vec::new();
    for round in 0..rounds {
        let f = Fixture::on_network(net, &format!("race-{round}"), 0, None);
        let root_seed = 70;
        let root = f.issue(
            &agent(root_seed),
            &[f.contract_in(&[&f.asset]), f.function_in(&["transfer"])],
            root_allowance,
        );
        let mut kids = Vec::new();
        for i in 0..siblings {
            let seed = 71 + u8::try_from(i).expect("few siblings");
            let id = f.next_id();
            let out = delegate_setup(
                &f,
                root,
                &agent(root_seed),
                root,
                &agent(seed),
                &[],
                sibling_allowance,
            );
            assert!(out.is_allowed(), "delegation: {out:?}");
            kids.push((id, seed));
        }
        let calls: Vec<Prepared> = kids
            .iter()
            .map(|(id, seed)| transfer(&f, *id, *seed, amount))
            .collect();
        let before_grants: Vec<GrantView> = f.grants().iter().map(GrantView::from).collect();
        let account_before = f.balance(&f.asset, &f.account.address);
        let bob_before = f.balance(&f.asset, &f.bob);
        let agents = f.relay_agents(net);
        let running = Running::start(net, &agents, &net.channels, 2 * siblings)?;
        let (mut sent, _) = drive(&running.handle(), calls, siblings, true);
        drop(running);
        settle_details(
            net,
            &mut sent,
            &nido_integration_tests::world::strkey(&f.signer),
        );
        let after: Vec<GrantView> = f.grants().iter().map(GrantView::from).collect();
        let root_spent: u128 = after[root as usize].spent.parse().expect("a u128");
        let account_paid = account_before - f.balance(&f.asset, &f.account.address);
        let bob_received = f.balance(&f.asset, &f.bob) - bob_before;
        let confirmed = sent
            .iter()
            .filter(|s| s.reply.settled.as_deref() == Some("confirmed"))
            .count();
        eprintln!(
            "race {round}: {confirmed} of {siblings} confirmed, root spent {root_spent} of {root_allowance}"
        );
        let siblings_charged_as_confirmed = kids.iter().all(|(id, _)| {
            let key = f.api_key(*id);
            let landed = sent
                .iter()
                .any(|s| s.api_key == key && s.reply.settled.as_deref() == Some("confirmed"));
            let want = if landed {
                amount.to_string()
            } else {
                before_grants[*id as usize].spent.clone()
            };
            after[*id as usize].spent == want
        });
        out.push(Round {
            siblings_charged_as_confirmed,
            number: round,
            root_allowance,
            sibling_allowance,
            siblings,
            amount,
            within_allowance: root_spent <= root_allowance,
            charges_match_transfers: i128::try_from(root_spent).ok() == Some(account_paid)
                && account_paid == bob_received
                && account_paid == amount * i128::try_from(confirmed).expect("few"),
            sent,
            before: before_grants,
            after,
            root_spent,
            account_paid,
            bob_received,
        });
    }
    Ok(json!({ "rounds": out }))
}
