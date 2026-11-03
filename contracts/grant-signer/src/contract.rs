use alloc::vec::Vec as AVec;
use grant_eval::chain;
use soroban_sdk::auth::{Context, ContractContext, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::{
    contract, contractimpl, contracttype, Address, BytesN, Env, Executable, Symbol, TryFromVal, Vec,
};

use crate::error::GrantError as Error;
use crate::{actions, budget};
use crate::{Caveat, Grant, GrantSignature};

#[contracttype]
enum Key {
    /// The account this contract serves (instance).
    Account,
    /// The id the next grant gets (instance).
    NextId,
    /// One grant (persistent).
    Grant(u32),
}

#[contract]
pub struct GrantSigner;

fn account(e: &Env) -> Address {
    e.storage()
        .instance()
        .get(&Key::Account)
        .expect("set at construction")
}

fn load(e: &Env, id: u32) -> Result<Grant, Error> {
    e.storage()
        .persistent()
        .get(&Key::Grant(id))
        .ok_or(Error::NoSuchGrant)
}

fn save(e: &Env, id: u32, grant: &Grant) {
    let key = Key::Grant(id);
    let max = e.storage().max_ttl();
    e.storage().persistent().set(&key, grant);
    e.storage().persistent().extend_ttl(&key, max, max);
    e.storage().instance().extend_ttl(max, max);
}

fn create(e: &Env, grant: &Grant) -> Result<u32, Error> {
    let id: u32 = e.storage().instance().get(&Key::NextId).unwrap_or(0);
    let next = id.checked_add(1).ok_or(Error::Overflow)?;
    e.storage().instance().set(&Key::NextId, &next);
    save(e, id, grant);
    Ok(id)
}

/// `id` and its ancestors, root first (`Ledger.IsLineage` in `formal/`).
/// Refuses if any of them is revoked, so revoking a grant revokes every grant
/// delegated from it.
fn lineage(e: &Env, id: u32) -> Result<AVec<(u32, Grant)>, Error> {
    let mut out = AVec::new();
    let mut current = id;
    loop {
        let grant = load(e, current)?;
        if grant.revoked {
            return Err(Error::Revoked);
        }
        let parent = grant.parent;
        out.push((current, grant));
        match parent {
            None => break,
            // A parent's id is smaller than its child's (`create` allocates
            // ids in order and a parent exists before its children), so the
            // walk ends.
            Some(p) => current = p,
        }
    }
    out.reverse();
    Ok(out)
}

/// The budget tree of a lineage: one node per grant, root first, each
/// node's parent the one before it (`Ledger.chain` in `formal/`, which proves
/// that spends on it are the whole ledger's, restricted to the lineage).
fn ledger(lineage: &[(u32, Grant)]) -> Result<AVec<rule_eval::Node>, Error> {
    let grants: AVec<(u128, u128)> = lineage
        .iter()
        .map(|(_, g)| (g.allowance, g.spent))
        .collect();
    budget::chain(&grants)
}

/// Whether `c` is `delegate(parent, …)` on this contract with `parent` the
/// signing grant.
fn is_own_delegation(e: &Env, c: &ContractContext, signer: u32) -> bool {
    c.fn_name == Symbol::new(e, "delegate")
        && c.args
            .first()
            .and_then(|v| u32::try_from_val(e, &v).ok())
            .is_some_and(|parent| parent == signer)
}

// `#[contractimpl]` entry points: the SDK ABI takes owned arguments.
#[allow(clippy::needless_pass_by_value)]
#[contractimpl]
impl GrantSigner {
    /// Serve `account`: its authorization issues, revokes, rotates and
    /// refills grants.
    pub fn __constructor(e: Env, account: Address) {
        e.storage().instance().set(&Key::Account, &account);
    }

    /// The account this contract serves.
    #[must_use]
    pub fn account(e: Env) -> Address {
        account(&e)
    }

    /// Grant `id`, if it exists.
    #[must_use]
    pub fn grant(e: Env, id: u32) -> Option<Grant> {
        e.storage().persistent().get(&Key::Grant(id))
    }

    /// Issue a root grant to the holder of `key`, with a budget of
    /// `allowance` in the Stellar Asset Contract `asset`. Requires the
    /// account's authorization. Returns the grant's id.
    ///
    /// # Errors
    ///
    /// [`Error::NotStellarAsset`] if `asset` is not a Stellar Asset Contract,
    /// [`Error::AllowanceTooLarge`] if `allowance` is above `i128::MAX`,
    /// [`Error::Overflow`] if the grant ids are exhausted.
    pub fn issue(
        e: Env,
        key: BytesN<32>,
        caveats: Vec<Caveat>,
        asset: Address,
        allowance: u128,
    ) -> Result<u32, Error> {
        account(&e).require_auth();
        if asset.executable() != Some(Executable::StellarAsset) {
            return Err(Error::NotStellarAsset);
        }
        budget::amount(allowance)?;
        create(
            &e,
            &Grant {
                parent: None,
                key,
                caveats,
                asset,
                allowance,
                spent: 0,
                revoked: false,
            },
        )
    }

    /// Delegate from grant `parent` to the holder of `key`: a child grant
    /// with `parent`'s caveats followed by `caveats`, so it allows at most
    /// what `parent` allows, and a budget node of `allowance` under
    /// `parent`'s. Requires this contract's own authorization, which its
    /// `__check_auth` gives only to `parent`'s holder. Returns the child's id.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchGrant`] if `parent` does not exist,
    /// [`Error::AllowanceTooLarge`] if `allowance` is above `i128::MAX`,
    /// [`Error::Overflow`] if the grant ids are exhausted.
    pub fn delegate(
        e: Env,
        parent: u32,
        key: BytesN<32>,
        caveats: Vec<Caveat>,
        allowance: u128,
    ) -> Result<u32, Error> {
        e.current_contract_address().require_auth();
        let from = load(&e, parent)?;
        budget::amount(allowance)?;
        let mut all = from.caveats;
        all.append(&caveats);
        create(
            &e,
            &Grant {
                parent: Some(parent),
                key,
                caveats: all,
                asset: from.asset,
                allowance,
                spent: 0,
                revoked: false,
            },
        )
    }

    /// Revoke grant `id`, and with it every grant delegated from it.
    /// Requires the account's authorization.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchGrant`] if `id` does not exist.
    pub fn revoke(e: Env, id: u32) -> Result<(), Error> {
        account(&e).require_auth();
        let mut grant = load(&e, id)?;
        grant.revoked = true;
        save(&e, id, &grant);
        Ok(())
    }

    /// Replace grant `id`'s holder key. Requires the account's
    /// authorization.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchGrant`] if `id` does not exist.
    pub fn rotate(e: Env, id: u32, key: BytesN<32>) -> Result<(), Error> {
        account(&e).require_auth();
        let mut grant = load(&e, id)?;
        grant.key = key;
        save(&e, id, &grant);
        Ok(())
    }

    /// Raise grant `id`'s allowance by `extra`, with `rule_eval::refill` on
    /// a tree of the one grant (`Ledger.refillGrant` in `formal/`). Requires
    /// the account's authorization.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchGrant`] if `id` does not exist,
    /// [`Error::AllowanceTooLarge`] if `extra` or the raised allowance is
    /// above `i128::MAX`.
    pub fn refill(e: Env, id: u32, extra: u128) -> Result<(), Error> {
        account(&e).require_auth();
        let mut grant = load(&e, id)?;
        grant.allowance = budget::refill(grant.allowance, grant.spent, extra)?;
        save(&e, id, &grant);
        Ok(())
    }

    /// Where a refill request for a spend of `amount` under grant `id` goes:
    /// the nearest grant on its lineage that cannot take `amount`, or `None`
    /// if the spend fits.
    ///
    /// # Errors
    ///
    /// [`Error::NoSuchGrant`] or [`Error::Revoked`] for `id`'s lineage.
    /// [`Error::AllowanceTooLarge`] if a grant on it holds an amount above
    /// `i128::MAX`, which no grant this contract stored does.
    pub fn overdrawn_at(e: Env, id: u32, amount: u128) -> Result<Option<u32>, Error> {
        let lineage = lineage(&e, id)?;
        let tree = ledger(&lineage)?;
        Ok(budget::overdrawn_at(&tree, amount).map(|i| lineage[i].0))
    }
}

#[contractimpl]
impl CustomAccountInterface for GrantSigner {
    type Signature = GrantSignature;
    type Error = Error;

    /// Authorize `contexts` for the holder of `signature.grant`; see the
    /// crate documentation for the checks, in order. The host calls this both
    /// for the account, as its delegated signer, and for this contract's own
    /// address, with the same arguments.
    #[allow(clippy::needless_pass_by_value)]
    fn __check_auth(
        e: Env,
        signature_payload: Hash<32>,
        signature: GrantSignature,
        contexts: Vec<Context>,
    ) -> Result<(), Error> {
        let lineage = lineage(&e, signature.grant)?;
        let holder = &lineage[lineage.len() - 1].1;
        e.crypto().ed25519_verify(
            &holder.key,
            &signature_payload.to_bytes().into(),
            &signature.signature,
        );

        let me = e.current_contract_address();
        let account = account(&e);
        let mut acts = AVec::new();
        let mut spends = AVec::new();
        for context in contexts.iter() {
            let Context::Contract(c) = &context else {
                // A creation context: no grant authorizes one, whichever of
                // this contract's two roles asks.
                return Err(Error::ContractCreation);
            };
            if c.contract == me {
                if !is_own_delegation(&e, c, signature.grant) {
                    return Err(Error::NotHolder);
                }
                continue;
            }
            if c.contract == account {
                return Err(Error::AccountCall);
            }
            if c.contract == holder.asset {
                spends.push(actions::transfer_amount(&e, c).ok_or(Error::UnmeteredCall)?);
            }
            acts.push(actions::invoke(&e, c));
        }
        if !chain::allows_all(&actions::caveats(&holder.caveats), &acts) {
            return Err(Error::NotAllowed);
        }

        if spends.is_empty() {
            return Ok(());
        }
        // All or nothing: `Ledger.spendAll`, then `Ledger.writeBack`.
        let spent = budget::spend_all(ledger(&lineage)?, &spends)?;
        for ((id, grant), spent) in lineage.into_iter().zip(spent) {
            if spent != grant.spent {
                save(&e, id, &Grant { spent, ..grant });
            }
        }
        Ok(())
    }
}
