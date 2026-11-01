//! Unit tests: every refusal, the timelock boundary, revocation at each
//! stage, signer authorization, and the exact events each step emits.

extern crate std;

use crate::{
    EnclaveImageRegistry, EnclaveImageRegistryClient, MeasurementActivated, MeasurementApproved,
    MeasurementProposed, MeasurementQueued, MeasurementRevocationVoted, MeasurementRevoked,
    RegistryError, Status, MAX_SIGNERS, TIMELOCK_LEDGERS,
};
use soroban_sdk::testutils::{Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke};
use soroban_sdk::{vec, Address, BytesN, Env, Event as _, IntoVal, Vec};

const START: u32 = 1_000;

struct Setup {
    e: Env,
    id: Address,
    signers: std::vec::Vec<Address>,
}

impl Setup {
    fn client(&self) -> EnclaveImageRegistryClient<'_> {
        EnclaveImageRegistryClient::new(&self.e, &self.id)
    }
}

fn env() -> Env {
    let e = Env::default();
    e.ledger().with_mut(|l| {
        l.sequence_number = START;
        l.min_persistent_entry_ttl = 1_000_000;
        l.max_entry_ttl = 10_000_000;
    });
    e
}

fn setup(n: u32, threshold: u32) -> Setup {
    let e = env();
    let signers: std::vec::Vec<Address> = (0..n).map(|_| Address::generate(&e)).collect();
    let mut list = Vec::new(&e);
    for s in &signers {
        list.push_back(s.clone());
    }
    let id = e.register(EnclaveImageRegistry, (list, threshold));
    e.mock_all_auths();
    Setup { e, id, signers }
}

fn m(e: &Env, b: u8) -> BytesN<32> {
    BytesN::from_array(e, &[b; 32])
}

fn advance(e: &Env, ledgers: u32) {
    e.ledger().with_mut(|l| l.sequence_number += ledgers);
}

fn register(e: &Env, signers: Vec<Address>, threshold: u32) {
    e.register(EnclaveImageRegistry, (signers, threshold));
}

#[test]
fn timelock_is_fourteen_days_of_five_second_ledgers() {
    assert_eq!(TIMELOCK_LEDGERS, 14 * 17_280);
    let s = setup(3, 2);
    assert_eq!(s.client().timelock_ledgers(), 241_920);
    assert_eq!(s.client().threshold(), 2);
    assert_eq!(s.client().signers().len(), 3);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn constructor_refuses_no_signers() {
    let e = env();
    register(&e, Vec::new(&e), 1);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn constructor_refuses_too_many_signers() {
    let e = env();
    let mut list = Vec::new(&e);
    for _ in 0..=MAX_SIGNERS {
        list.push_back(Address::generate(&e));
    }
    register(&e, list, 2);
}

#[test]
#[should_panic(expected = "Error(Contract, #1)")]
fn constructor_refuses_a_repeated_signer() {
    let e = env();
    let a = Address::generate(&e);
    register(&e, vec![&e, a.clone(), Address::generate(&e), a], 2);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn constructor_refuses_threshold_zero() {
    let e = env();
    register(&e, vec![&e, Address::generate(&e)], 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn constructor_refuses_threshold_above_the_signer_count() {
    let e = env();
    register(
        &e,
        vec![&e, Address::generate(&e), Address::generate(&e)],
        3,
    );
}

/// Proposal, approval to the threshold, the timelock to the exact ledger,
/// activation, and every event along the way.
#[test]
fn a_measurement_activates_only_after_the_threshold_and_the_timelock() {
    let s = setup(3, 2);
    let c = s.client();
    let mm = m(&s.e, 7);

    let r = c.approve(&s.signers[0], &mm);
    assert_eq!(r.status, Status::Pending);
    assert_eq!(r.proposed_at, START);
    assert_eq!(
        s.e.events().all().filter_by_contract(&s.id),
        [
            MeasurementProposed {
                measurement: mm.clone(),
                proposer: s.signers[0].clone(),
            }
            .to_xdr(&s.e, &s.id),
            MeasurementApproved {
                measurement: mm.clone(),
                signer: s.signers[0].clone(),
                approvals: 1,
            }
            .to_xdr(&s.e, &s.id),
        ]
    );
    assert!(!c.is_active(&mm));
    assert_eq!(
        c.try_approve(&s.signers[0], &mm),
        Err(Ok(RegistryError::AlreadyVoted))
    );

    advance(&s.e, 5);
    let r = c.approve(&s.signers[1], &mm);
    let active_from = START + 5 + TIMELOCK_LEDGERS;
    assert_eq!(r.status, Status::Queued);
    assert_eq!(r.active_from, active_from);
    assert_eq!(
        s.e.events().all().filter_by_contract(&s.id),
        [
            MeasurementApproved {
                measurement: mm.clone(),
                signer: s.signers[1].clone(),
                approvals: 2,
            }
            .to_xdr(&s.e, &s.id),
            MeasurementQueued {
                measurement: mm.clone(),
                active_from,
            }
            .to_xdr(&s.e, &s.id),
        ]
    );
    assert!(!c.is_active(&mm), "queued is not active");
    assert_eq!(
        c.try_approve(&s.signers[2], &mm),
        Err(Ok(RegistryError::NotPending)),
        "votes past the threshold are refused"
    );

    advance(&s.e, TIMELOCK_LEDGERS - 1);
    assert_eq!(s.e.ledger().sequence(), active_from - 1);
    assert_eq!(
        c.try_activate(&mm),
        Err(Ok(RegistryError::TimelockNotElapsed))
    );
    assert!(!c.is_active(&mm));

    advance(&s.e, 1);
    let r = c.activate(&mm);
    assert_eq!(r.status, Status::Active);
    assert_eq!(r.activated_at, active_from);
    assert_eq!(
        s.e.events().all().filter_by_contract(&s.id),
        [MeasurementActivated {
            measurement: mm.clone()
        }
        .to_xdr(&s.e, &s.id)]
    );
    assert!(c.is_active(&mm));
    assert_eq!(c.try_activate(&mm), Err(Ok(RegistryError::NotQueued)));
    assert!(!c.is_active(&m(&s.e, 8)), "another measurement");
}

#[test]
fn activate_refuses_unknown_and_pending_measurements() {
    let s = setup(3, 2);
    let c = s.client();
    let mm = m(&s.e, 1);
    assert_eq!(
        c.try_activate(&mm),
        Err(Ok(RegistryError::UnknownMeasurement))
    );
    c.approve(&s.signers[0], &mm);
    advance(&s.e, TIMELOCK_LEDGERS * 2);
    assert_eq!(
        c.try_activate(&mm),
        Err(Ok(RegistryError::NotQueued)),
        "a proposal below the threshold never activates, however old"
    );
}

#[test]
fn only_signers_vote() {
    let s = setup(3, 2);
    let c = s.client();
    let outsider = Address::generate(&s.e);
    assert_eq!(
        c.try_approve(&outsider, &m(&s.e, 1)),
        Err(Ok(RegistryError::NotASigner))
    );
    assert_eq!(
        c.try_revoke(&outsider, &m(&s.e, 1)),
        Err(Ok(RegistryError::NotASigner))
    );
}

/// A signer's vote needs that signer's own authorization: a call whose
/// only authorization comes from another signer is refused.
#[test]
fn a_vote_needs_the_voting_signers_authorization() {
    let s = setup(3, 2);
    let c = s.client();
    let mm = m(&s.e, 3);
    let args = (s.signers[0].clone(), mm.clone()).into_val(&s.e);
    let by_other = c
        .mock_auths(&[MockAuth {
            address: &s.signers[1],
            invoke: &MockAuthInvoke {
                contract: &s.id,
                fn_name: "approve",
                args,
                sub_invokes: &[],
            },
        }])
        .try_approve(&s.signers[0], &mm);
    assert!(by_other.is_err());
    assert_eq!(c.measurement(&mm), None, "nothing recorded");

    let args = (s.signers[0].clone(), mm.clone()).into_val(&s.e);
    let by_self = c
        .mock_auths(&[MockAuth {
            address: &s.signers[0],
            invoke: &MockAuthInvoke {
                contract: &s.id,
                fn_name: "approve",
                args,
                sub_invokes: &[],
            },
        }])
        .try_approve(&s.signers[0], &mm);
    assert!(by_self.is_ok());
}

/// Revocation reaches the threshold at once, at any stage, and is final.
#[test]
fn revocation_takes_effect_at_the_threshold_from_every_stage() {
    for stage in [Status::Pending, Status::Queued, Status::Active] {
        let s = setup(3, 2);
        let c = s.client();
        let mm = m(&s.e, 9);
        c.approve(&s.signers[0], &mm);
        if stage != Status::Pending {
            c.approve(&s.signers[1], &mm);
        }
        if stage == Status::Active {
            advance(&s.e, TIMELOCK_LEDGERS);
            c.activate(&mm);
            assert!(c.is_active(&mm));
        }
        assert_eq!(c.measurement(&mm).unwrap().status, stage);

        let r = c.revoke(&s.signers[2], &mm);
        assert_eq!(r.status, stage, "one vote of two");
        assert_eq!(
            s.e.events().all().filter_by_contract(&s.id),
            [MeasurementRevocationVoted {
                measurement: mm.clone(),
                signer: s.signers[2].clone(),
                revocations: 1,
            }
            .to_xdr(&s.e, &s.id)]
        );
        assert_eq!(
            c.try_revoke(&s.signers[2], &mm),
            Err(Ok(RegistryError::AlreadyVoted))
        );

        advance(&s.e, 1);
        let r = c.revoke(&s.signers[0], &mm);
        assert_eq!(r.status, Status::Revoked);
        assert_eq!(r.revoked_at, s.e.ledger().sequence());
        assert_eq!(
            s.e.events().all().filter_by_contract(&s.id),
            [
                MeasurementRevocationVoted {
                    measurement: mm.clone(),
                    signer: s.signers[0].clone(),
                    revocations: 2,
                }
                .to_xdr(&s.e, &s.id),
                MeasurementRevoked {
                    measurement: mm.clone()
                }
                .to_xdr(&s.e, &s.id),
            ]
        );
        assert!(!c.is_active(&mm));
        assert_eq!(
            c.try_approve(&s.signers[2], &mm),
            Err(Ok(RegistryError::Revoked))
        );
        assert_eq!(c.try_activate(&mm), Err(Ok(RegistryError::Revoked)));
        assert_eq!(
            c.try_revoke(&s.signers[1], &mm),
            Err(Ok(RegistryError::Revoked))
        );
        advance(&s.e, TIMELOCK_LEDGERS);
        assert!(!c.is_active(&mm), "revocation is final");
    }
}

#[test]
fn revoking_an_unknown_measurement_is_refused() {
    let s = setup(2, 1);
    assert_eq!(
        s.client().try_revoke(&s.signers[0], &m(&s.e, 4)),
        Err(Ok(RegistryError::UnknownMeasurement))
    );
}

/// With a 1-of-1 multisig the proposal itself queues, and the timelock
/// still applies in full.
#[test]
fn a_single_signer_registry_still_waits_out_the_timelock() {
    let s = setup(1, 1);
    let c = s.client();
    let mm = m(&s.e, 5);
    let r = c.approve(&s.signers[0], &mm);
    assert_eq!(r.status, Status::Queued);
    assert_eq!(r.active_from, START + TIMELOCK_LEDGERS);
    assert_eq!(
        c.try_activate(&mm),
        Err(Ok(RegistryError::TimelockNotElapsed))
    );
    advance(&s.e, TIMELOCK_LEDGERS);
    c.activate(&mm);
    assert!(c.is_active(&mm));
}

#[test]
fn renew_extends_without_changing_state() {
    let s = setup(3, 2);
    let c = s.client();
    let mm = m(&s.e, 6);
    c.approve(&s.signers[0], &mm);
    let before = c.measurement(&mm);
    c.renew(&mm);
    c.renew(&m(&s.e, 0));
    assert_eq!(c.measurement(&mm), before);
    assert_eq!(c.measurement(&m(&s.e, 0)), None);
}
