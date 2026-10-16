use admin_sep::Administratable;
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype,
    deploy::DeployerWithAddress, Address, Bytes, BytesN, Env, String, Symbol,
};
use soroban_sdk_tools::{contractstorage, InstanceItem};
use stellar_accounts::smart_account::Signer;

// A pinned name is resolved directly from the pin without consulting the
// registry (`Self::resolve`), so there is no "registry disagrees with the
// pin" condition to report. Account creation's failure modes (an
// unresolvable registry name for an unpinned name, a reused salt) surface as
// the registry's or the host's own errors; `FactoryError` covers only the
// scheduled-change entry points.

mod perch_account {
    //! Embeds Perch's smart-account wasm (`perch-account`, the deployed bytes
    //! `just perch-infra` fetches by the manifest's hash) so the factory derives
    //! the deploy hash from the bytes instead of hardcoding it:
    //!
    //!  1. `build.rs` stages `target/wasm32v1-none/contract/perch_account.wasm`
    //!     and emits `PERCH_ACCOUNT_WASM` pointing at it.
    //!  2. `include_bytes!(env!("PERCH_ACCOUNT_WASM"))` embeds those bytes.
    //!  3. At runtime the factory computes `sha256(WASM)` (see
    //!     `super::Contract::account_wasm_hash`) and deploys that hash.
    //!
    //! For `deploy_v2` to resolve, the same bytes must already be installed
    //! on-chain. Once Perch's release workstream publishes the account wasm,
    //! this embed is checked against the published hash instead of a local
    //! build.

    /// Raw Perch account wasm, embedded at build time.
    pub const WASM: &[u8] = include_bytes!(env!("PERCH_ACCOUNT_WASM"));
}

/// Stellar Registry "unverified" testnet contract — the one that holds
/// bare-name → contract-id mappings. Calling `fetch_contract_id("verifier")`
/// on it returns the registered `WebAuthn` verifier; `resolve` below relies on
/// that for unpinned names.
///
/// For mainnet or an alternate registry build, change this constant and
/// redeploy the factory.
const REGISTRY: &str = "CDBL7MNO7UI5OAAIC67UIWKQ4P3S6RVQSFCQXUHUW6TOFCXSYRPNHY4S";

mod registry {
    use soroban_sdk::*;
    #[contractclient(name = "RegistryClient")]
    pub trait RegistryInterface {
        fn fetch_contract_id(name: String) -> Address;
    }
}

/// A change to what the factory gives the accounts it creates from then on.
/// Each one waits out the factory's delay between `schedule_change` and
/// `execute_change`; nothing changes the factory's code or verifier pin
/// immediately.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Change {
    /// Replace the factory's wasm with the installed wasm of this hash, and
    /// with it the account code the factory embeds.
    Upgrade(BytesN<32>),
    /// Pin this `WebAuthn` verifier for every account created afterwards.
    PinVerifier(Address),
}

/// The scheduled change. There is at most one.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingChange {
    /// Assigned in order and never reused.
    pub id: u64,
    pub change: Change,
    /// The first ledger at which `execute_change` accepts it.
    pub executable_at: u32,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum FactoryError {
    /// Another change is scheduled; cancel it first.
    ChangePending = 1,
    /// No change is scheduled.
    NoPendingChange = 2,
    /// The id is not the scheduled change's.
    WrongChange = 3,
    /// The scheduled change's delay has not passed.
    ChangeNotReady = 4,
    /// No delay is stored: this wasm was installed by an upgrade from
    /// factory code that predates the delay, so no constructor set one.
    /// Every change is refused; deploy a fresh factory instead.
    NoDelay = 5,
    /// The ledger the change would become executable at overflows.
    DelayOverflow = 6,
}

/// A change was scheduled. Watchers have until `executable_at` to react.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeScheduled {
    #[topic]
    pub id: u64,
    pub change: Change,
    pub executable_at: u32,
}

/// A scheduled change took effect. For an upgrade, the new wasm runs from
/// the next invocation.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeExecuted {
    #[topic]
    pub id: u64,
    pub change: Change,
}

/// A scheduled change was dropped without taking effect.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangeCancelled {
    #[topic]
    pub id: u64,
    pub change: Change,
}

/// The admin was set, at construction or by `set_admin`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChanged {
    pub admin: Address,
}

#[contractstorage]
pub struct Config {
    /// Cached `sha256(perch_account::WASM)`.
    account: InstanceItem<BytesN<32>>,
    // The `admin` is not stored here: admin/set_admin come from the shared
    // `admin-sep` crate, which owns its own `ADMIN` key.
    /// The address for the `"verifier"` registry name. `None` = unpinned:
    /// resolve from the registry and trust it. Once set (by the constructor
    /// or a `PinVerifier` change), `resolve("verifier")` returns this address
    /// directly and never consults the registry, so a repointed, broken, or
    /// unreachable registry can neither swap the passkey verifier under new
    /// accounts nor block their creation.
    pinned_verifier: InstanceItem<Address>,
    /// Ledgers from `schedule_change` to the first ledger the change may
    /// execute. Set once, by the constructor.
    delay: InstanceItem<u32>,
    pending: InstanceItem<PendingChange>,
    /// The id the next `schedule_change` assigns.
    next_change_id: InstanceItem<u64>,
}

#[contract]
pub struct Contract;

// admin/set_admin come from the shared `admin-sep` crate
// (`Administratable`). Only the WebAuthn verifier moved to Perch (its
// constructorless `perch-webauthn-verifier`, which this factory pins); the
// factory stays Nido's, because Perch's factory derives an address from the
// admin signers and a Nido passkey's RP ID is the account's own subdomain, so
// the address has to exist before the passkey does. The admin schedules,
// executes, and cancels changes to the factory's code and verifier pin, each
// after the delay, and has no authority over any deployed account. The admin
// is any address, so it can be a multisig smart account.
//
// `Upgradable` is deliberately not implemented: its `upgrade` replaces the
// wasm at once. An upgrade is a `Change::Upgrade` instead.
#[contractimpl(contracttrait)]
impl Administratable for Contract {
    /// admin-sep's default, plus an `AdminChanged` event so watchers see who
    /// can schedule changes. Takes effect at once: rotating the admin changes
    /// who may schedule, not what the factory does, and a change scheduled
    /// before the rotation still waits out its delay.
    fn set_admin(e: &Env, new_admin: Address) {
        let store = e.storage().instance();
        if let Some(current) = store.get::<_, Address>(admin_sep::STORAGE_KEY) {
            current.require_auth();
        }
        store.set(admin_sep::STORAGE_KEY, &new_admin);
        AdminChanged { admin: new_admin }.publish(e);
    }
}

#[contractimpl]
impl Contract {
    /// `verifier` pins the `WebAuthn` verifier from the first account on
    /// (`None` leaves it to the registry). `delay_ledgers` is how long every
    /// later change waits; it cannot change without an upgrade.
    // `#[contractimpl]` entry point: the SDK's XDR-based ABI takes owned
    // `Address` by value. `set_admin` on first call (no admin yet) skips the
    // auth check.
    #[allow(clippy::needless_pass_by_value)]
    pub fn __constructor(e: &Env, admin: Address, verifier: Option<Address>, delay_ledgers: u32) {
        Self::set_admin(e, admin);
        if let Some(verifier) = verifier {
            Config::set_pinned_verifier(e, &verifier);
        }
        Config::set_delay(e, &delay_ledgers);
    }

    /// Schedule `change`, executable `change_delay()` ledgers from now.
    /// Admin only. One change at a time: refused while another is
    /// scheduled. Returns its id.
    // `#[contractimpl]` entry point; SDK ABI requires owned `Change`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn schedule_change(e: &Env, change: Change) -> Result<u64, FactoryError> {
        Self::admin(e).require_auth();
        let config = Config::new(e);
        if config.pending.has() {
            return Err(FactoryError::ChangePending);
        }
        let delay = config.delay.get().ok_or(FactoryError::NoDelay)?;
        let executable_at = e
            .ledger()
            .sequence()
            .checked_add(delay)
            .ok_or(FactoryError::DelayOverflow)?;
        let id = config.next_change_id.get().unwrap_or(0);
        config.next_change_id.set(&(id + 1));
        config.pending.set(&PendingChange {
            id,
            change: change.clone(),
            executable_at,
        });
        ChangeScheduled {
            id,
            change,
            executable_at,
        }
        .publish(e);
        Ok(id)
    }

    /// Apply the scheduled change `id` once its delay has passed. Admin
    /// only.
    pub fn execute_change(e: &Env, id: u64) -> Result<(), FactoryError> {
        Self::admin(e).require_auth();
        let pending = Self::pending(e, id)?;
        if e.ledger().sequence() < pending.executable_at {
            return Err(FactoryError::ChangeNotReady);
        }
        let config = Config::new(e);
        config.pending.remove();
        ChangeExecuted {
            id,
            change: pending.change.clone(),
        }
        .publish(e);
        match pending.change {
            Change::PinVerifier(verifier) => config.pinned_verifier.set(&verifier),
            Change::Upgrade(wasm_hash) => {
                // Load-bearing: the new wasm embeds different account bytes,
                // and a surviving cache would make every later
                // `create_account` deploy the old account wasm.
                config.account.remove();
                e.deployer().update_current_contract_wasm(wasm_hash);
            }
        }
        Ok(())
    }

    /// Drop the scheduled change `id` without applying it. Admin only.
    pub fn cancel_change(e: &Env, id: u64) -> Result<(), FactoryError> {
        Self::admin(e).require_auth();
        let pending = Self::pending(e, id)?;
        Config::new(e).pending.remove();
        ChangeCancelled {
            id,
            change: pending.change,
        }
        .publish(e);
        Ok(())
    }

    /// The scheduled change, if any.
    pub fn pending_change(e: &Env) -> Option<PendingChange> {
        Config::get_pending(e)
    }

    /// Ledgers every change waits between scheduling and execution. `None`
    /// only on a factory whose wasm predates the delay (see
    /// `FactoryError::NoDelay`).
    pub fn change_delay(e: &Env) -> Option<u32> {
        Config::get_delay(e)
    }

    /// The pinned `verifier` address, or `None` if unpinned.
    pub fn pinned_verifier(e: &Env) -> Option<Address> {
        Config::get_pinned_verifier(e)
    }

    /// Deploy a Perch smart account at `get_c_address(salt)` whose
    /// constructor rule ("admin", scoped to the account itself) is the passkey
    /// `key`, checked by the `WebAuthn` verifier. Everything else — further
    /// signers, rules, and recovery — arrives through the account's first
    /// `apply_doc`.
    // `#[contractimpl]` entry point; SDK ABI requires owned `BytesN<65>`.
    #[allow(clippy::needless_pass_by_value)]
    pub fn create_account(e: &Env, salt: &BytesN<32>, key: BytesN<65>) -> Address {
        let verifier = Self::resolve(e, "verifier");
        let admin_signers = soroban_sdk::vec![e, Signer::External(verifier, key.to_bytes())];
        Self::deployer(e, salt).deploy_v2(Self::account_wasm_hash(e), (&admin_signers,))
    }

    pub fn get_c_address(e: &Env, salt: &BytesN<32>) -> Address {
        Self::deployer(e, salt).deployed_address()
    }

    /// Recompute and store the embedded account-wasm hash, returning it.
    /// Admin-gated repair for the cache `execute_change` clears on an
    /// upgrade: after upgrading a factory whose old code did not clear it
    /// (the upgrade transaction runs the old code), the stale cache survives;
    /// calling this once afterwards repairs it. It can only store the hash of
    /// the bytes this wasm embeds.
    pub fn refresh_account_wasm_hash(e: &Env) -> BytesN<32> {
        Self::admin(e).require_auth();
        let hash = Self::compute_account_wasm_hash(e);
        Config::set_account(e, &hash);
        hash
    }

    /// The scheduled change, if its id is `id`.
    fn pending(e: &Env, id: u64) -> Result<PendingChange, FactoryError> {
        let pending = Config::get_pending(e).ok_or(FactoryError::NoPendingChange)?;
        if pending.id != id {
            return Err(FactoryError::WrongChange);
        }
        Ok(pending)
    }

    fn deployer(e: &Env, salt: &BytesN<32>) -> DeployerWithAddress {
        e.deployer().with_current_contract(salt.clone())
    }

    fn resolve(env: &Env, name: &str) -> Address {
        if let Some(pinned) = Self::pinned_for(env, name) {
            return pinned;
        }
        let key = Symbol::new(env, name);
        if let Some(addr) = env.storage().instance().get::<_, Address>(&key) {
            return addr;
        }
        let client = registry::RegistryClient::new(env, &Address::from_str(env, REGISTRY));
        let addr = client.fetch_contract_id(&String::from_str(env, name));
        env.storage().instance().set(&key, &addr);
        addr
    }

    /// The pinned address for `name`, or `None` if unpinned. Only
    /// `"verifier"` is pinnable (the only name `resolve` looks up).
    fn pinned_for(env: &Env, name: &str) -> Option<Address> {
        match name {
            "verifier" => Config::get_pinned_verifier(env),
            _ => None,
        }
    }

    /// SHA-256 of the embedded account wasm — the installed hash `deploy_v2`
    /// expects. Cached in instance storage after the first call.
    fn account_wasm_hash(e: &Env) -> BytesN<32> {
        if let Some(cached) = Config::get_account(e) {
            return cached;
        }
        let hash = Self::compute_account_wasm_hash(e);
        Config::set_account(e, &hash);
        hash
    }

    /// Freshly compute `sha256(perch_account::WASM)` without the cache.
    fn compute_account_wasm_hash(e: &Env) -> BytesN<32> {
        e.crypto()
            .sha256(&Bytes::from_slice(e, perch_account::WASM))
            .to_bytes()
    }
}

#[cfg(test)]
mod test {
    // `#[contractimpl]`'s generated invoke wrappers bind every non-`Env`
    // param, which clippy counts as a use of the `_`-prefixed stub params.
    #![allow(clippy::used_underscore_binding)]

    use super::*;
    use soroban_sdk::testutils::{
        Address as _, Events as _, Ledger as _, MockAuth, MockAuthInvoke,
    };
    use soroban_sdk::{
        contract, contractclient, contractimpl, Env, Event as _, Executable, IntoVal, TryFromVal,
    };

    /// The delay every test factory is constructed with.
    const DELAY: u32 = 100;

    /// A Perch account wasm an earlier factory build embedded (the
    /// integration suite's committed copy): the stale cache the upgrade test
    /// seeds names it.
    const PREVIOUS_ACCOUNT_WASM: &[u8] =
        include_bytes!("../../../crates/integration-tests/fixtures/old-perch-account.wasm");

    // Minimal mock: every `fetch_contract_id` call returns a fixed address.
    #[contract]
    struct MockRegistry;

    #[contractimpl]
    impl MockRegistry {
        // `#[contractimpl]` entry point; SDK ABI requires owned `Address`.
        #[allow(clippy::needless_pass_by_value)]
        pub fn __constructor(env: &Env, fixed: Address) {
            env.storage()
                .instance()
                .set(&Symbol::new(env, "fixed"), &fixed);
        }
        pub fn fetch_contract_id(env: &Env, _name: String) -> Address {
            env.storage()
                .instance()
                .get::<_, Address>(&Symbol::new(env, "fixed"))
                .unwrap()
        }
    }

    /// A registry that panics on every lookup: proves a pinned name never
    /// reaches it.
    #[contract]
    struct PanicRegistry;

    #[contractimpl]
    impl PanicRegistry {
        pub fn fetch_contract_id(_env: &Env, _name: String) -> Address {
            panic!("registry consulted")
        }
    }

    /// Stands in for the `WebAuthn` verifier at account construction: OZ's
    /// `add_context_rule` canonicalizes every External signer's key through
    /// the verifier's `batch_canonicalize_key`.
    #[contract]
    struct StubVerifier;

    #[contractimpl]
    impl StubVerifier {
        // `#[contractimpl]` entry point; SDK ABI requires owned `Vec<Val>`.
        #[allow(clippy::needless_pass_by_value)]
        pub fn batch_canonicalize_key(
            e: &Env,
            key_data: soroban_sdk::Vec<soroban_sdk::Val>,
        ) -> soroban_sdk::Vec<Bytes> {
            let mut out = soroban_sdk::Vec::new(e);
            for k in key_data.iter() {
                out.push_back(Bytes::try_from_val(e, &k).unwrap_or_else(|_| Bytes::new(e)));
            }
            out
        }
    }

    /// The deployed account's read surface (Perch's `PerchSmartAccount`).
    #[contractclient(name = "AccountClient")]
    trait AccountReads {
        fn applied_doc_hash(e: Env) -> Option<BytesN<32>>;
        fn applied_doc(e: Env) -> Option<Bytes>;
        fn recovery_controller(e: Env) -> Option<Address>;
        fn get_context_rules_count(e: Env) -> u32;
        fn get_context_rule(e: Env, id: u32) -> stellar_accounts::smart_account::ContextRule;
    }

    /// A factory administered by `admin`, unpinned, with [`DELAY`].
    fn factory(env: &Env, admin: &Address) -> Address {
        env.register(Contract, (admin.clone(), None::<Address>, DELAY))
    }

    /// A factory whose registry resolves `"verifier"` to a stub verifier,
    /// with the embedded account wasm installed. Returns the factory, the
    /// verifier, and the admin.
    fn setup(env: &Env) -> (Address, Address, Address) {
        env.mock_all_auths();
        let verifier = env.register(StubVerifier, ());
        env.register_at(
            &Address::from_str(env, REGISTRY),
            MockRegistry,
            (verifier.clone(),),
        );
        env.deployer().upload_contract_wasm(perch_account::WASM);
        let admin = Address::generate(env);
        (factory(env, &admin), verifier, admin)
    }

    /// The verifier named by the admin rule of an account the factory made.
    fn verifier_of(env: &Env, account: &Address) -> Address {
        let rule = AccountClient::new(env, account).get_context_rule(&0);
        match rule.signers.get(0).unwrap() {
            Signer::External(verifier, _) => verifier,
            Signer::Delegated(_) => panic!("not a passkey signer"),
        }
    }

    fn salt(env: &Env, n: u8) -> BytesN<32> {
        BytesN::from_array(env, &[n; 32])
    }

    fn key(env: &Env, n: u8) -> BytesN<65> {
        BytesN::from_array(env, &[n; 65])
    }

    fn advance(env: &Env, ledgers: u32) {
        env.ledger().with_mut(|l| l.sequence_number += ledgers);
    }

    /// `factory.fn_name(args)`, for a `MockAuth` that authorizes exactly it.
    fn call<'a>(
        factory: &'a Address,
        fn_name: &'a str,
        args: soroban_sdk::Vec<soroban_sdk::Val>,
    ) -> MockAuthInvoke<'a> {
        MockAuthInvoke {
            contract: factory,
            fn_name,
            args,
            sub_invokes: &[],
        }
    }

    #[test]
    fn resolve_caches_after_first_lookup() {
        let env = Env::default();
        env.mock_all_auths();
        let registry_addr = Address::from_str(&env, REGISTRY);
        let expected = Address::generate(&env);
        env.register_at(&registry_addr, MockRegistry, (expected.clone(),));

        let factory_addr = factory(&env, &Address::generate(&env));
        let first = env.as_contract(&factory_addr, || Contract::resolve(&env, "verifier"));
        env.register_at(&registry_addr, PanicRegistry, ());
        let second = env.as_contract(&factory_addr, || Contract::resolve(&env, "verifier"));
        assert_eq!(first, expected);
        assert_eq!(first, second, "the second lookup is served from the cache");
    }

    #[test]
    fn get_c_address_uses_random_salt() {
        let env = Env::default();
        env.mock_all_auths();
        let factory_addr = factory(&env, &Address::generate(&env));
        let salt_a = salt(&env, 1);
        let salt_b = salt(&env, 2);

        let first = env.as_contract(&factory_addr, || Contract::get_c_address(&env, &salt_a));
        let second = env.as_contract(&factory_addr, || Contract::get_c_address(&env, &salt_b));
        let first_again = env.as_contract(&factory_addr, || Contract::get_c_address(&env, &salt_a));

        assert_ne!(first, second);
        assert_eq!(first, first_again);
    }

    /// `create_account` deploys a Perch account at the predicted address with
    /// exactly one rule: "admin", scoped to the account itself, whose only
    /// signer is the passkey checked by the resolved verifier. No document,
    /// no recovery controller: both arrive with the first `apply_doc`.
    #[test]
    fn create_account_deploys_a_perch_account_with_the_passkey_admin_rule() {
        let env = Env::default();
        let (factory, verifier, _) = setup(&env);
        let client = ContractClient::new(&env, &factory);
        let salt = salt(&env, 9);
        let key = key(&env, 3);

        let predicted = client.get_c_address(&salt);
        let account = client.create_account(&salt, &key);
        assert_eq!(predicted, account);

        let reads = AccountClient::new(&env, &account);
        assert_eq!(reads.applied_doc_hash(), None);
        assert_eq!(reads.applied_doc(), None);
        assert_eq!(reads.recovery_controller(), None);
        assert_eq!(reads.get_context_rules_count(), 1);
        let rule = reads.get_context_rule(&0);
        assert_eq!(rule.name, String::from_str(&env, "admin"));
        assert_eq!(
            rule.context_type,
            stellar_accounts::smart_account::ContextRuleType::CallContract(account.clone())
        );
        assert_eq!(
            rule.signers,
            soroban_sdk::vec![&env, Signer::External(verifier, key.to_bytes())]
        );
        assert!(rule.policies.is_empty());
    }

    #[test]
    fn create_account_twice_with_the_same_salt_is_rejected() {
        let env = Env::default();
        let (factory, _, _) = setup(&env);
        let client = ContractClient::new(&env, &factory);
        let salt = salt(&env, 10);
        let key = key(&env, 4);
        client.create_account(&salt, &key);
        assert!(client.try_create_account(&salt, &key).is_err());
    }

    /// The open setup race (THREAT_MODEL 10, L5; nidohq/nido#245): the address
    /// derives from the salt alone and `create_account` is permissionless, so
    /// whoever submits a salt first owns its address, with their own key as
    /// the admin, and the owner's later call fails as a reused salt. This pins
    /// today's behaviour; launch gate MAINNET_READINESS A6 requires the wallet
    /// to detect it (or the factory to prevent it) before mainnet.
    #[test]
    fn whoever_submits_the_salt_first_owns_the_address() {
        let env = Env::default();
        let (factory, verifier, _) = setup(&env);
        let client = ContractClient::new(&env, &factory);
        let salt = salt(&env, 11);
        let owner_key = key(&env, 5);
        let front_runner_key = key(&env, 6);

        let address = client.create_account(&salt, &front_runner_key);
        assert_eq!(address, client.get_c_address(&salt));
        assert!(client.try_create_account(&salt, &owner_key).is_err());

        let admin = AccountClient::new(&env, &address).get_context_rule(&0);
        assert_eq!(
            admin.signers,
            soroban_sdk::vec![
                &env,
                Signer::External(verifier, front_runner_key.to_bytes())
            ],
            "the admin is the front-runner's key, not the owner's"
        );
    }

    /// The hash the factory deploys must equal the hash the host assigns when
    /// the same bytes are installed, or `deploy_v2` cannot resolve it.
    #[test]
    fn account_wasm_hash_equals_uploaded_wasm_hash() {
        let env = Env::default();
        env.mock_all_auths();
        assert!(
            !perch_account::WASM.is_empty(),
            "embedded account wasm is empty"
        );
        let uploaded = env.deployer().upload_contract_wasm(perch_account::WASM);
        let factory_addr = factory(&env, &Address::generate(&env));
        let derived = env.as_contract(&factory_addr, || Contract::account_wasm_hash(&env));
        assert_eq!(derived, uploaded);
    }

    #[test]
    fn account_wasm_hash_caches_first_computation() {
        let env = Env::default();
        env.mock_all_auths();
        let factory_addr = factory(&env, &Address::generate(&env));
        env.as_contract(&factory_addr, || {
            assert!(Config::get_account(&env).is_none());
            let fresh = Contract::compute_account_wasm_hash(&env);
            assert_eq!(Contract::account_wasm_hash(&env), fresh);
            assert_eq!(Config::get_account(&env), Some(fresh.clone()));
            assert_eq!(Contract::account_wasm_hash(&env), fresh);
        });
    }

    #[test]
    fn the_constructor_sets_the_admin_the_pin_and_the_delay() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let verifier = Address::generate(&env);
        let id = env.register(Contract, (admin.clone(), Some(verifier.clone()), DELAY));
        let client = ContractClient::new(&env, &id);
        assert_eq!(client.admin(), admin);
        assert_eq!(client.pinned_verifier(), Some(verifier));
        assert_eq!(client.change_delay(), Some(DELAY));
        assert_eq!(client.pending_change(), None);

        let unpinned = factory(&env, &admin);
        assert_eq!(ContractClient::new(&env, &unpinned).pinned_verifier(), None);
    }

    #[test]
    fn set_admin_rotates_admin_and_announces_it() {
        let env = Env::default();
        env.mock_all_auths();
        let new_admin = Address::generate(&env);
        let id = factory(&env, &Address::generate(&env));
        let client = ContractClient::new(&env, &id);
        client.set_admin(&new_admin);
        assert_eq!(
            env.events().all().filter_by_contract(&id),
            [AdminChanged {
                admin: new_admin.clone()
            }
            .to_xdr(&env, &id)]
        );
        assert_eq!(client.admin(), new_admin);
    }

    #[test]
    fn set_admin_requires_current_admin_auth() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let imposter = Address::generate(&env);
        let new_admin = Address::generate(&env);
        let id = factory(&env, &admin);
        let client = ContractClient::new(&env, &id);

        let res = client
            .mock_auths(&[MockAuth {
                address: &imposter,
                invoke: &call(&id, "set_admin", (new_admin.clone(),).into_val(&env)),
            }])
            .try_set_admin(&new_admin);
        assert!(res.is_err());
        assert_eq!(client.admin(), admin);
    }

    #[test]
    fn refresh_account_wasm_hash_repairs_stale_cache() {
        let env = Env::default();
        env.mock_all_auths();
        let id = factory(&env, &Address::generate(&env));
        let client = ContractClient::new(&env, &id);
        env.as_contract(&id, || {
            Config::set_account(&env, &BytesN::from_array(&env, &[7u8; 32]));
        });
        let refreshed = client.refresh_account_wasm_hash();
        let expected = env.as_contract(&id, || Contract::compute_account_wasm_hash(&env));
        assert_eq!(refreshed, expected);

        env.set_auths(&[]);
        assert!(client.try_refresh_account_wasm_hash().is_err());
    }

    /// Nobody but the admin can schedule, execute, or cancel a change, for
    /// either kind, and a refused call leaves the schedule as it was.
    #[test]
    fn only_the_admin_can_schedule_execute_or_cancel_a_change() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let imposter = Address::generate(&env);
        let id = factory(&env, &admin);
        let client = ContractClient::new(&env, &id);
        let wasm = env.deployer().upload_contract_wasm(perch_account::WASM);
        let changes = [
            Change::Upgrade(wasm),
            Change::PinVerifier(Address::generate(&env)),
        ];

        for change in changes {
            let schedule = |who: &Address| {
                client
                    .mock_auths(&[MockAuth {
                        address: who,
                        invoke: &call(&id, "schedule_change", (change.clone(),).into_val(&env)),
                    }])
                    .try_schedule_change(&change)
            };
            assert!(schedule(&imposter).is_err());
            env.set_auths(&[]);
            assert!(
                client.try_schedule_change(&change).is_err(),
                "no auth at all"
            );
            assert_eq!(client.pending_change(), None);

            let n = schedule(&admin).unwrap().unwrap();
            let pending = client.pending_change().unwrap();
            advance(&env, DELAY);

            let execute = call(&id, "execute_change", (n,).into_val(&env));
            let cancel = call(&id, "cancel_change", (n,).into_val(&env));
            let by = |address, invoke| [MockAuth { address, invoke }];
            assert!(client
                .mock_auths(&by(&imposter, &execute))
                .try_execute_change(&n)
                .is_err());
            assert!(client
                .mock_auths(&by(&imposter, &cancel))
                .try_cancel_change(&n)
                .is_err());
            assert_eq!(client.pending_change(), Some(pending));
            client.mock_auths(&by(&admin, &cancel)).cancel_change(&n);
        }
        assert_eq!(client.pinned_verifier(), None);
    }

    /// A pin change takes effect only once its delay has passed, and only at
    /// `execute_change`: accounts created while it is pending get the
    /// current pin, accounts created after it get the new one.
    #[test]
    fn a_verifier_pin_waits_out_the_delay() {
        let env = Env::default();
        let (factory, registry_verifier, _) = setup(&env);
        let client = ContractClient::new(&env, &factory);
        let pinned = env.register(StubVerifier, ());

        let start = env.ledger().sequence();
        let n = client.schedule_change(&Change::PinVerifier(pinned.clone()));
        let scheduled = PendingChange {
            id: n,
            change: Change::PinVerifier(pinned.clone()),
            executable_at: start + DELAY,
        };
        assert_eq!(
            env.events().all().filter_by_contract(&factory),
            [ChangeScheduled {
                id: n,
                change: scheduled.change.clone(),
                executable_at: scheduled.executable_at,
            }
            .to_xdr(&env, &factory)]
        );
        assert_eq!(client.pending_change(), Some(scheduled.clone()));

        advance(&env, DELAY - 1);
        assert_eq!(
            client.try_execute_change(&n),
            Err(Ok(FactoryError::ChangeNotReady))
        );
        let during = client.create_account(&salt(&env, 20), &key(&env, 20));
        assert_eq!(verifier_of(&env, &during), registry_verifier);
        assert_eq!(client.pinned_verifier(), None);

        advance(&env, 1);
        client.execute_change(&n);
        assert_eq!(
            env.events().all().filter_by_contract(&factory),
            [ChangeExecuted {
                id: n,
                change: scheduled.change,
            }
            .to_xdr(&env, &factory)]
        );
        assert_eq!(client.pinned_verifier(), Some(pinned.clone()));
        assert_eq!(client.pending_change(), None);
        let after = client.create_account(&salt(&env, 21), &key(&env, 21));
        assert_eq!(verifier_of(&env, &after), pinned);
        assert_eq!(
            verifier_of(&env, &during),
            registry_verifier,
            "an existing account keeps its verifier"
        );
    }

    /// One change at a time; a cancelled change never executes; ids are
    /// never reused, so an approval for one change cannot act on another.
    #[test]
    fn one_change_at_a_time_and_a_cancelled_change_never_executes() {
        let env = Env::default();
        env.mock_all_auths();
        let id = factory(&env, &Address::generate(&env));
        let client = ContractClient::new(&env, &id);
        let first = Change::PinVerifier(Address::generate(&env));
        let second = Change::PinVerifier(Address::generate(&env));

        let a = client.schedule_change(&first);
        assert_eq!(
            client.try_schedule_change(&second),
            Err(Ok(FactoryError::ChangePending))
        );
        assert_eq!(
            client.try_cancel_change(&(a + 1)),
            Err(Ok(FactoryError::WrongChange))
        );
        client.cancel_change(&a);
        assert_eq!(
            env.events().all().filter_by_contract(&id),
            [ChangeCancelled {
                id: a,
                change: first,
            }
            .to_xdr(&env, &id)]
        );
        advance(&env, DELAY);
        assert_eq!(
            client.try_execute_change(&a),
            Err(Ok(FactoryError::NoPendingChange))
        );
        assert_eq!(client.pinned_verifier(), None);

        let b = client.schedule_change(&second);
        assert_eq!(b, a + 1);
        advance(&env, DELAY);
        assert_eq!(
            client.try_execute_change(&a),
            Err(Ok(FactoryError::WrongChange))
        );
        client.execute_change(&b);
        assert_eq!(
            client.try_cancel_change(&b),
            Err(Ok(FactoryError::NoPendingChange))
        );
    }

    /// The account code a factory deploys comes from the cached hash, and an
    /// executed upgrade clears it, so the code that runs next derives the
    /// hash of the account wasm it embeds. (The test host runs the new wasm
    /// after the upgrade, so the account minted after it is checked in the
    /// integration suite, `factory_governance.rs`, against the factory wasm.)
    #[test]
    fn executing_an_upgrade_clears_the_cached_account_hash() {
        let env = Env::default();
        let (factory, _, _) = setup(&env);
        let client = ContractClient::new(&env, &factory);
        let previous = env.deployer().upload_contract_wasm(PREVIOUS_ACCOUNT_WASM);
        env.as_contract(&factory, || Config::set_account(&env, &previous));
        let minted = client.create_account(&salt(&env, 30), &key(&env, 30));
        assert_eq!(
            minted.executable(),
            Some(Executable::Wasm(previous.clone())),
            "the cached hash is what deploys"
        );

        let code = factory.executable();
        let next = env.deployer().upload_contract_wasm(perch_account::WASM);
        let n = client.schedule_change(&Change::Upgrade(next.clone()));
        advance(&env, DELAY - 1);
        assert_eq!(
            client.try_execute_change(&n),
            Err(Ok(FactoryError::ChangeNotReady))
        );
        assert_eq!(factory.executable(), code);
        env.as_contract(&factory, || {
            assert_eq!(Config::get_account(&env), Some(previous.clone()));
        });

        advance(&env, 1);
        client.execute_change(&n);
        assert_eq!(factory.executable(), Some(Executable::Wasm(next)));
        env.as_contract(&factory, || {
            assert_eq!(Config::get_account(&env), None);
            assert_eq!(
                Contract::account_wasm_hash(&env),
                Contract::compute_account_wasm_hash(&env)
            );
        });
    }

    /// A factory whose wasm was swapped in by pre-delay code has no stored
    /// delay, and refuses every change rather than applying one at once.
    #[test]
    fn a_factory_without_a_stored_delay_refuses_every_change() {
        let env = Env::default();
        env.mock_all_auths();
        let id = factory(&env, &Address::generate(&env));
        let client = ContractClient::new(&env, &id);
        env.as_contract(&id, || Config::new(&env).delay.remove());
        assert_eq!(client.change_delay(), None);
        assert_eq!(
            client.try_schedule_change(&Change::PinVerifier(Address::generate(&env))),
            Err(Ok(FactoryError::NoDelay))
        );
    }

    /// With the verifier pinned, `create_account` never constructs the
    /// registry client: a registry that panics on any lookup is unreachable,
    /// and the account's passkey signer names the pinned verifier.
    #[test]
    fn pinned_resolve_never_consults_registry() {
        let env = Env::default();
        env.register_at(&Address::from_str(&env, REGISTRY), PanicRegistry, ());
        env.deployer().upload_contract_wasm(perch_account::WASM);
        let pinned = env.register(StubVerifier, ());
        let factory = env.register(
            Contract,
            (Address::generate(&env), Some(pinned.clone()), DELAY),
        );

        let account =
            ContractClient::new(&env, &factory).create_account(&salt(&env, 43), &key(&env, 7));
        assert_eq!(verifier_of(&env, &account), pinned);
    }
}
