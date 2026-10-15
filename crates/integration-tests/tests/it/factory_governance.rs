//! Changes to Nido's factory under ENFORCING authorization, against the
//! factory wasm: who may schedule, execute, and cancel a change to the code
//! or the verifier pin, that every change waits out the delay the factory
//! publishes (`change_delay`), and that an executed upgrade leaves no cached
//! account hash behind.
//!
//! The admin is a Nido account, as a mainnet multisig would be: it
//! authorizes through a rule its own document scopes to the factory, signed
//! by its passkey, and the factory only calls `admin.require_auth()`. A
//! multisig is the same rule with more signers and a threshold. A stranger
//! holding a rule scoped to the factory signs validly for its own address,
//! which is not the admin's.

use nido_integration_tests::world::{
    contract_at, err, world, Account, Change, Doc, FactoryClient, FactoryError, Passkey,
    PendingChange, World,
};
use nido_integration_tests::{
    FACTORY_WASM, OLD_PERCH_ACCOUNT_WASM, PERCH_ACCOUNT_WASM, PERCH_WEBAUTHN_VERIFIER_WASM,
};
use soroban_sdk::{Address, BytesN, Executable, Symbol};
use stellar_accounts::smart_account::Signer;

/// The delay the governed factory is constructed with.
const DELAY: u32 = 5_000;

/// A factory administered by a Nido account, beside the world's own.
struct Governed {
    w: World,
    factory: Address,
    operators: Account,
    stranger: Account,
}

/// A Nido account whose document lets its owner act at `factory`.
fn holder(w: &World, label: &str, factory: &Address) -> Account {
    let account = w.mint(label, Passkey::labelled(label), std::vec![]);
    let doc = Doc {
        signers: std::vec![("owner", account.key("owner").pubkey())],
        rules: std::vec![("factory", factory.clone())],
        recovery: None,
    };
    w.apply(&account, &doc, 0)
        .expect("document scoped to the factory");
    account
}

fn governed() -> Governed {
    let w = world();
    let factory = contract_at(&w.env, "governed-factory");
    let operators = holder(&w, "operators", &factory);
    let stranger = holder(&w, "stranger", &factory);
    w.env.register_at(
        &factory,
        FACTORY_WASM,
        (operators.address.clone(), Some(w.verifier.clone()), DELAY),
    );
    w.env.set_auths(&[]);
    Governed {
        w,
        factory,
        operators,
        stranger,
    }
}

type Call<T> = Result<T, Result<FactoryError, soroban_sdk::InvokeError>>;

impl Governed {
    fn client(&self) -> FactoryClient<'_> {
        FactoryClient::new(&self.w.env, &self.factory)
    }

    /// `factory.fn_name(args)` authorized by `by`'s passkey through its
    /// factory rule.
    fn signed<T>(
        &self,
        by: &Account,
        fn_name: &str,
        args: std::vec::Vec<soroban_sdk::xdr::ScVal>,
        call: impl FnOnce(&FactoryClient<'_>) -> T,
    ) -> T {
        let root = self.w.invocation(&self.factory, fn_name, args);
        let entry = self.w.signed(by, "owner", "factory", root);
        self.w.with_auths(&[entry], || call(&self.client()))
    }

    fn schedule(&self, by: &Account, change: &Change) -> Call<u64> {
        self.signed(
            by,
            "schedule_change",
            std::vec![self.w.sc(change.clone())],
            |c| c.try_schedule_change(change).map(Result::unwrap),
        )
    }

    fn execute(&self, by: &Account, id: u64) -> Call<()> {
        self.signed(by, "execute_change", std::vec![self.w.sc(id)], |c| {
            c.try_execute_change(&id).map(Result::unwrap)
        })
    }

    fn cancel(&self, by: &Account, id: u64) -> Call<()> {
        self.signed(by, "cancel_change", std::vec![self.w.sc(id)], |c| {
            c.try_cancel_change(&id).map(Result::unwrap)
        })
    }

    /// Mint through the governed factory; creation needs no authorization.
    fn mint(&self, n: u8) -> Address {
        self.client().create_account(
            &BytesN::from_array(&self.w.env, &[n; 32]),
            &BytesN::from_array(&self.w.env, &Passkey::new(u64::from(n)).pubkey()),
        )
    }

    /// The verifier an account's admin passkey names.
    fn verifier_of(&self, account: &Address) -> Address {
        let rule = nido_integration_tests::SmartAccountClient::new(&self.w.env, account)
            .get_context_rule(&0);
        match rule.signers.get(0).unwrap() {
            Signer::External(verifier, _) => verifier,
            Signer::Delegated(_) => panic!("not a passkey signer"),
        }
    }
}

/// Only the admin can schedule, execute, or cancel a change. A stranger's
/// valid signature, or none at all, changes nothing; the admin's cancel
/// drops the change for good.
#[test]
fn only_the_admin_can_schedule_execute_or_cancel_a_change() {
    let g = governed();
    let pin = Change::PinVerifier(contract_at(&g.w.env, "any-verifier"));

    assert!(g.schedule(&g.stranger, &pin).is_err());
    assert!(g.client().try_schedule_change(&pin).is_err(), "no auth");
    assert_eq!(g.client().pending_change(), None);

    let id = g.schedule(&g.operators, &pin).expect("the admin schedules");
    let pending = g.client().pending_change().unwrap();
    g.w.advance(DELAY);
    assert!(g.execute(&g.stranger, id).is_err());
    assert!(g.cancel(&g.stranger, id).is_err());
    assert!(g.client().try_execute_change(&id).is_err(), "no auth");
    assert_eq!(g.client().pending_change(), Some(pending));
    assert_eq!(g.client().pinned_verifier(), Some(g.w.verifier.clone()));

    assert_eq!(g.cancel(&g.operators, id), Ok(()));
    assert_eq!(
        err(g.execute(&g.operators, id)),
        FactoryError::NoPendingChange
    );
    assert_eq!(g.client().pinned_verifier(), Some(g.w.verifier.clone()));
}

/// A repin waits out the published delay and reaches only accounts created
/// after it executes; an account created while it was pending keeps the
/// verifier it was created with.
#[test]
fn a_repin_waits_out_the_published_delay() {
    let g = governed();
    assert_eq!(g.client().change_delay(), Some(DELAY));
    let next = contract_at(&g.w.env, "webauthn-verifier-next");
    g.w.env.register_at(&next, PERCH_WEBAUTHN_VERIFIER_WASM, ());
    g.w.env.set_auths(&[]);

    let pin = Change::PinVerifier(next.clone());
    let id = g.schedule(&g.operators, &pin).unwrap();
    assert_eq!(
        g.client().pending_change(),
        Some(PendingChange {
            id,
            change: pin,
            executable_at: g.w.ledger() + DELAY,
        })
    );

    g.w.advance(DELAY - 1);
    assert_eq!(
        err(g.execute(&g.operators, id)),
        FactoryError::ChangeNotReady
    );
    let during = g.mint(1);
    assert_eq!(g.verifier_of(&during), g.w.verifier);

    g.w.advance(1);
    assert_eq!(g.execute(&g.operators, id), Ok(()));
    assert_eq!(g.client().pinned_verifier(), Some(next.clone()));
    assert_eq!(g.verifier_of(&g.mint(2)), next);
    assert_eq!(g.verifier_of(&during), g.w.verifier);
}

/// An upgrade waits out the published delay, installs exactly the scheduled
/// wasm, and clears the cached account hash, so the next account is the
/// account wasm the running factory embeds. The stale cache is seeded
/// directly: it is what a factory build embedding an earlier account leaves
/// behind, and the first mint shows the factory honours it.
#[test]
fn an_upgrade_waits_out_the_published_delay_and_new_accounts_get_the_embedded_account() {
    let g = governed();
    let env = &g.w.env;
    let previous = env.deployer().upload_contract_wasm(OLD_PERCH_ACCOUNT_WASM);
    let embedded = env.deployer().upload_contract_wasm(PERCH_ACCOUNT_WASM);
    // The factory's account-hash cache (`Config::account`, which
    // `#[contractstorage]` keys by the field's name).
    env.as_contract(&g.factory, || {
        env.storage()
            .instance()
            .set(&Symbol::new(env, "Account"), &previous);
    });
    assert_eq!(
        g.mint(10).executable(),
        Some(Executable::Wasm(previous.clone())),
        "the seeded cache is what deploys"
    );

    let code = match g.factory.executable() {
        Some(Executable::Wasm(hash)) => hash,
        other => panic!("factory executable {other:?}"),
    };
    let id = g
        .schedule(&g.operators, &Change::Upgrade(code.clone()))
        .unwrap();
    assert!(g.execute(&g.stranger, id).is_err());
    g.w.advance(DELAY - 1);
    assert_eq!(
        err(g.execute(&g.operators, id)),
        FactoryError::ChangeNotReady
    );
    assert_eq!(
        g.mint(11).executable(),
        Some(Executable::Wasm(previous)),
        "nothing changes before execution"
    );

    g.w.advance(1);
    assert_eq!(g.execute(&g.operators, id), Ok(()));
    assert_eq!(g.factory.executable(), Some(Executable::Wasm(code)));
    assert_eq!(g.mint(12).executable(), Some(Executable::Wasm(embedded)));
}
