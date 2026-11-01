use crate::error::EmailGuardianError as Error;
use crate::registry::DkimRegistryClient;
use crate::statement::{self, MAX_STATEMENT_LEN};
use crate::verifier::VerifierIdentityClient;
use crate::{
    EmailApproval, GuardianConfig, ALLOW_ALL, ALLOW_CANCEL, ALLOW_COMPROMISE, ALLOW_LOST_KEY,
    ALLOW_RECONFIGURE, ALLOW_UPGRADE, MAX_PIN_LIFETIME_LEDGERS, VERSION,
};
use perch_recovery_interface::zk::{
    is_canonical_field, split_hi_lo, ProofVerifierClient, ProofVerifierError,
};
use perch_recovery_interface::{address_payload, AddressKind};
use soroban_sdk::auth::{Context, CustomAccountInterface};
use soroban_sdk::crypto::Hash;
use soroban_sdk::{
    contract, contractimpl, panic_with_error, symbol_short, Address, Bytes, BytesN, Env, Symbol,
    TryFromVal, Vec,
};

const CONFIG: Symbol = symbol_short!("config");

#[contract]
pub struct EmailGuardian;

fn contract_id(e: &Env, address: &Address) -> Option<[u8; 32]> {
    match address_payload(e, address)? {
        (AddressKind::Contract, id) => Some(id),
        (AddressKind::Account, _) => None,
    }
}

fn validate(e: &Env, config: &GuardianConfig) -> Result<(), Error> {
    if contract_id(e, &config.account).is_none() {
        return Err(Error::AccountNotContract);
    }
    if contract_id(e, &config.controller).is_none() || config.controller == config.account {
        return Err(Error::ControllerNotContract);
    }
    if contract_id(e, &config.registry).is_none() || contract_id(e, &config.verifier).is_none() {
        return Err(Error::DependencyNotContract);
    }
    let commitment = config.commitment.to_array();
    if commitment == [0u8; 32] || !is_canonical_field(&commitment) {
        return Err(Error::NonCanonicalCommitment);
    }
    if config.key_pin.len() > 1 {
        return Err(Error::InvalidPin);
    }
    if let Some(pin) = config.key_pin.first() {
        let now = e.ledger().sequence();
        let latest = now.saturating_add(MAX_PIN_LIFETIME_LEDGERS);
        if !is_canonical_field(&pin.root.to_array())
            || pin.valid_until_ledger < now
            || pin.valid_until_ledger > latest
        {
            return Err(Error::InvalidPin);
        }
    }
    if config.allowed_actions == 0 || config.allowed_actions & !ALLOW_ALL != 0 {
        return Err(Error::InvalidAllowedActions);
    }
    match VerifierIdentityClient::new(e, &config.verifier).try_circuit_id() {
        Ok(Ok(id)) if id == config.circuit_id => Ok(()),
        _ => Err(Error::CircuitMismatch),
    }
}

fn load(e: &Env) -> GuardianConfig {
    e.storage()
        .instance()
        .get(&CONFIG)
        .expect("set at construction")
}

fn extend(e: &Env) {
    let max = e.storage().max_ttl();
    e.storage().instance().extend_ttl(max, max);
}

/// The `ALLOW_*` bit of a Perch action code; `0` for any other code.
fn action_bit(action: u8) -> u32 {
    match action {
        1 => ALLOW_LOST_KEY,
        2 => ALLOW_COMPROMISE,
        3 => ALLOW_CANCEL,
        4 => ALLOW_RECONFIGURE,
        5 => ALLOW_UPGRADE,
        _ => 0,
    }
}

/// The controller entry point that collects approvals of `action`'s
/// statements (Perch spec §5, §6.3).
fn entry_point(e: &Env, action: u8) -> Symbol {
    match action {
        4 | 5 => Symbol::new(e, "approve_change"),
        _ => Symbol::new(e, "submit_guardian"),
    }
}

/// `C || digest_hi || digest_lo || key_root`.
fn public_inputs(e: &Env, config: &GuardianConfig, digest: &[u8; 32], root: &[u8; 32]) -> Bytes {
    let (hi, lo) = split_hi_lo(digest);
    let mut inputs = Bytes::from_array(e, &config.commitment.to_array());
    inputs.extend_from_array(&hi);
    inputs.extend_from_array(&lo);
    inputs.extend_from_array(root);
    inputs
}

/// Every `__check_auth` check, in the order `EmailGuardianError` lists them.
fn check(
    e: &Env,
    config: &GuardianConfig,
    approval: &EmailApproval,
    contexts: &Vec<Context>,
) -> Result<(), Error> {
    // The controller's `require_auth_for_args((digest,))`, and nothing else.
    if contexts.len() != 1 {
        return Err(Error::UnexpectedContext);
    }
    let Context::Contract(ctx) = contexts.get_unchecked(0) else {
        return Err(Error::UnexpectedContext);
    };
    if ctx.contract != config.controller || ctx.args.len() != 1 {
        return Err(Error::UnexpectedContext);
    }
    let digest = BytesN::<32>::try_from_val(e, &ctx.args.get_unchecked(0))
        .map_err(|_| Error::UnexpectedContext)?
        .to_array();

    // The statement is the digest's preimage.
    if e.crypto().sha256(&approval.statement).to_array() != digest {
        return Err(Error::DigestMismatch);
    }
    let len = approval.statement.len() as usize;
    if len > MAX_STATEMENT_LEN {
        return Err(Error::MalformedStatement);
    }
    let mut buf = [0u8; MAX_STATEMENT_LEN];
    approval.statement.copy_into_slice(&mut buf[..len]);
    let s = statement::parse(&buf[..len]).ok_or(Error::MalformedStatement)?;

    // It names this network, this guardian's account, and its controller.
    if s.network_id != e.ledger().network_id().to_array() {
        return Err(Error::WrongNetwork);
    }
    if Some(s.account) != contract_id(e, &config.account) {
        return Err(Error::WrongAccount);
    }
    if Some(s.controller) != contract_id(e, &config.controller) {
        return Err(Error::WrongController);
    }

    // The action is allowed and arrived through its own entry point.
    if config.allowed_actions & action_bit(s.action) == 0 {
        return Err(Error::ActionNotAllowed);
    }
    if ctx.fn_name != entry_point(e, s.action) {
        return Err(Error::WrongEntryPoint);
    }

    if e.ledger().sequence() > s.valid_until_ledger {
        return Err(Error::StatementExpired);
    }

    // The key root: the unexpired pin, or one the registry accepts now.
    let root = approval.key_root.to_array();
    if !is_canonical_field(&root) {
        return Err(Error::NonCanonicalRoot);
    }
    let pinned = config.key_pin.first().is_some_and(|pin| {
        pin.root == approval.key_root && e.ledger().sequence() <= pin.valid_until_ledger
    });
    if !pinned {
        match DkimRegistryClient::new(e, &config.registry).try_is_accepted_root(&approval.key_root)
        {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => return Err(Error::UnknownRoot),
            _ => return Err(Error::RegistryUnavailable),
        }
    }

    // Public inputs from the guardian's own values only.
    let inputs = public_inputs(e, config, &digest, &root);
    match ProofVerifierClient::new(e, &config.verifier).try_verify_proof(&inputs, &approval.proof) {
        Ok(Ok(())) => Ok(()),
        Err(Ok(ProofVerifierError::VkParseError)) => Err(Error::VerifierUnavailable),
        Err(Ok(_)) => Err(Error::ProofRejected),
        _ => Err(Error::VerifierUnavailable),
    }
}

#[contractimpl]
impl EmailGuardian {
    /// Fix the configuration. Refuses (see [`Error`]'s construction
    /// variants) unless every address has the right kind, `C` and the pin
    /// root are canonical field elements, the pin expires within
    /// [`MAX_PIN_LIFETIME_LEDGERS`], the action set is valid, and the
    /// verifier reports `circuit_id`.
    // `#[contractimpl]` entry point: the SDK ABI takes owned arguments.
    #[allow(clippy::needless_pass_by_value)]
    pub fn __constructor(e: Env, config: GuardianConfig) {
        if let Err(err) = validate(&e, &config) {
            panic_with_error!(&e, err);
        }
        e.storage().instance().set(&CONFIG, &config);
        extend(&e);
    }

    /// The configuration fixed at construction.
    #[must_use]
    pub fn config(e: &Env) -> GuardianConfig {
        load(e)
    }

    /// See [`VERSION`].
    #[must_use]
    pub fn version(_e: &Env) -> u32 {
        VERSION
    }

    /// Extend the instance and its code to the network's maximum TTL.
    /// Permissionless; changes nothing else.
    pub fn renew(e: &Env) {
        extend(e);
    }
}

#[contractimpl]
impl CustomAccountInterface for EmailGuardian {
    type Signature = EmailApproval;
    type Error = Error;

    /// Approve the one digest the controller asks about when `approval`
    /// proves an email for it; see [`check`] for the order of checks. The
    /// host's signature payload is not used: the proof binds the statement,
    /// and the controller counts this guardian at most once per statement.
    // The SDK macro forwards every argument by name, the unused one included.
    #[allow(clippy::used_underscore_binding)]
    fn __check_auth(
        e: Env,
        _signature_payload: Hash<32>,
        approval: EmailApproval,
        auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        check(&e, &load(&e), &approval, &auth_contexts)
    }
}
