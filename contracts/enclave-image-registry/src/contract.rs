use crate::error::RegistryError as Error;
use crate::{
    Measurement, MeasurementActivated, MeasurementApproved, MeasurementProposed, MeasurementQueued,
    MeasurementRevocationVoted, MeasurementRevoked, Status, MAX_SIGNERS, TIMELOCK_LEDGERS, VERSION,
};
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, symbol_short, Address, BytesN, Env,
    Symbol, Vec,
};

const SIGNERS: Symbol = symbol_short!("signers");
const THRESHOLD: Symbol = symbol_short!("threshold");

#[contracttype]
#[derive(Clone)]
enum Key {
    Measurement(BytesN<32>),
}

#[contract]
pub struct EnclaveImageRegistry;

fn signers(e: &Env) -> Vec<Address> {
    e.storage()
        .instance()
        .get(&SIGNERS)
        .expect("set at construction")
}

fn threshold(e: &Env) -> u32 {
    e.storage()
        .instance()
        .get(&THRESHOLD)
        .expect("set at construction")
}

fn extend_instance(e: &Env) {
    let max = e.storage().max_ttl();
    e.storage().instance().extend_ttl(max, max);
}

fn load(e: &Env, measurement: &BytesN<32>) -> Option<Measurement> {
    e.storage()
        .persistent()
        .get(&Key::Measurement(measurement.clone()))
}

fn store(e: &Env, measurement: &BytesN<32>, record: &Measurement) {
    let key = Key::Measurement(measurement.clone());
    e.storage().persistent().set(&key, record);
    let max = e.storage().max_ttl();
    e.storage().persistent().extend_ttl(&key, max, max);
    extend_instance(e);
}

/// `signer` must be a registry signer and authorize this call.
fn authorize(e: &Env, signer: &Address) -> Result<(), Error> {
    if !signers(e).contains(signer) {
        return Err(Error::NotASigner);
    }
    signer.require_auth();
    Ok(())
}

#[contractimpl]
impl EnclaveImageRegistry {
    /// Fixes the multisig: `1 ≤ threshold ≤ len(signers) ≤ MAX_SIGNERS`,
    /// signers distinct.
    // `#[contractimpl]` entry point: the SDK ABI takes owned arguments.
    #[allow(clippy::needless_pass_by_value)]
    pub fn __constructor(e: Env, signers: Vec<Address>, threshold: u32) {
        let n = signers.len();
        if n == 0 || n > MAX_SIGNERS {
            panic_with_error!(&e, Error::InvalidSigners);
        }
        for (i, s) in signers.iter().enumerate() {
            if signers.iter().skip(i + 1).any(|t| t == s) {
                panic_with_error!(&e, Error::InvalidSigners);
            }
        }
        if threshold == 0 || threshold > n {
            panic_with_error!(&e, Error::InvalidThreshold);
        }
        e.storage().instance().set(&SIGNERS, &signers);
        e.storage().instance().set(&THRESHOLD, &threshold);
        extend_instance(&e);
    }

    /// `signer` votes to approve `measurement`. The first vote is the
    /// proposal. The vote that reaches the threshold queues the measurement
    /// with `active_from = now + TIMELOCK_LEDGERS`.
    ///
    /// # Errors
    /// [`Error::NotASigner`], [`Error::Revoked`], [`Error::NotPending`] once
    /// queued or active, [`Error::AlreadyVoted`].
    ///
    /// # Panics
    /// If the ledger sequence is within [`TIMELOCK_LEDGERS`] of `u32::MAX`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn approve(e: Env, signer: Address, measurement: BytesN<32>) -> Result<Measurement, Error> {
        authorize(&e, &signer)?;
        let now = e.ledger().sequence();
        let mut record = if let Some(record) = load(&e, &measurement) {
            record
        } else {
            MeasurementProposed {
                measurement: measurement.clone(),
                proposer: signer.clone(),
            }
            .publish(&e);
            Measurement {
                status: Status::Pending,
                approvals: Vec::new(&e),
                revocations: Vec::new(&e),
                proposed_at: now,
                active_from: 0,
                activated_at: 0,
                revoked_at: 0,
            }
        };
        match record.status {
            Status::Pending => {}
            Status::Revoked => return Err(Error::Revoked),
            Status::Queued | Status::Active => return Err(Error::NotPending),
        }
        if record.approvals.contains(&signer) {
            return Err(Error::AlreadyVoted);
        }
        record.approvals.push_back(signer.clone());
        MeasurementApproved {
            measurement: measurement.clone(),
            signer,
            approvals: record.approvals.len(),
        }
        .publish(&e);
        if record.approvals.len() >= threshold(&e) {
            let active_from = now
                .checked_add(TIMELOCK_LEDGERS)
                .expect("ledger sequence below u32::MAX - TIMELOCK_LEDGERS");
            record.status = Status::Queued;
            record.active_from = active_from;
            MeasurementQueued {
                measurement: measurement.clone(),
                active_from,
            }
            .publish(&e);
        }
        store(&e, &measurement, &record);
        Ok(record)
    }

    /// Activates a queued measurement once its timelock has elapsed.
    /// Permissionless: the multisig's decision and the timelock are already
    /// on record.
    ///
    /// # Errors
    /// [`Error::UnknownMeasurement`], [`Error::Revoked`], [`Error::NotQueued`]
    /// unless queued, [`Error::TimelockNotElapsed`] before `active_from`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn activate(e: Env, measurement: BytesN<32>) -> Result<Measurement, Error> {
        let Some(mut record) = load(&e, &measurement) else {
            return Err(Error::UnknownMeasurement);
        };
        match record.status {
            Status::Queued => {}
            Status::Revoked => return Err(Error::Revoked),
            Status::Pending | Status::Active => return Err(Error::NotQueued),
        }
        let now = e.ledger().sequence();
        if now < record.active_from {
            return Err(Error::TimelockNotElapsed);
        }
        record.status = Status::Active;
        record.activated_at = now;
        MeasurementActivated {
            measurement: measurement.clone(),
        }
        .publish(&e);
        store(&e, &measurement, &record);
        Ok(record)
    }

    /// `signer` votes to revoke `measurement`, at any stage before
    /// revocation. The vote that reaches the threshold revokes it at once.
    ///
    /// # Errors
    /// [`Error::NotASigner`], [`Error::UnknownMeasurement`],
    /// [`Error::Revoked`], [`Error::AlreadyVoted`].
    #[allow(clippy::needless_pass_by_value)]
    pub fn revoke(e: Env, signer: Address, measurement: BytesN<32>) -> Result<Measurement, Error> {
        authorize(&e, &signer)?;
        let Some(mut record) = load(&e, &measurement) else {
            return Err(Error::UnknownMeasurement);
        };
        if record.status == Status::Revoked {
            return Err(Error::Revoked);
        }
        if record.revocations.contains(&signer) {
            return Err(Error::AlreadyVoted);
        }
        record.revocations.push_back(signer.clone());
        MeasurementRevocationVoted {
            measurement: measurement.clone(),
            signer,
            revocations: record.revocations.len(),
        }
        .publish(&e);
        if record.revocations.len() >= threshold(&e) {
            record.status = Status::Revoked;
            record.revoked_at = e.ledger().sequence();
            MeasurementRevoked {
                measurement: measurement.clone(),
            }
            .publish(&e);
        }
        store(&e, &measurement, &record);
        Ok(record)
    }

    /// Whether custodians may release shares to an enclave with
    /// `measurement`.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn is_active(e: &Env, measurement: BytesN<32>) -> bool {
        load(e, &measurement).is_some_and(|r| r.status == Status::Active)
    }

    /// Everything recorded about `measurement`, if it was ever proposed.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn measurement(e: &Env, measurement: BytesN<32>) -> Option<Measurement> {
        load(e, &measurement)
    }

    /// The multisig's signers, fixed at construction.
    #[must_use]
    pub fn signers(e: &Env) -> Vec<Address> {
        signers(e)
    }

    /// Votes needed to approve or revoke, fixed at construction.
    #[must_use]
    pub fn threshold(e: &Env) -> u32 {
        threshold(e)
    }

    /// See [`TIMELOCK_LEDGERS`].
    #[must_use]
    pub fn timelock_ledgers() -> u32 {
        TIMELOCK_LEDGERS
    }

    /// See [`VERSION`].
    #[must_use]
    pub fn version() -> u32 {
        VERSION
    }

    /// Extends the instance, the code, and `measurement`'s record (if any)
    /// to the network maximum TTL. Changes nothing else.
    #[allow(clippy::needless_pass_by_value)]
    pub fn renew(e: &Env, measurement: BytesN<32>) {
        extend_instance(e);
        let key = Key::Measurement(measurement);
        if e.storage().persistent().has(&key) {
            let max = e.storage().max_ttl();
            e.storage().persistent().extend_ttl(&key, max, max);
        }
    }
}
