mod common;

use grant_eval::chain::{allows, allows_all, holds, val_eq, Action, Caveat, Val};

const TOKEN: &[u8] = b"CTOKEN";
const POOL: &[u8] = b"CPOOL";
const OTHER: &[u8] = b"COTHER";
const ALICE: &[u8] = b"GALICE";
const BOB: &[u8] = b"GBOB";

fn ids(list: &[&[u8]]) -> Vec<Vec<u8>> {
    list.iter().map(|s| s.to_vec()).collect()
}

fn invoke(contract: &[u8], function: &[u8], args: Vec<Val>) -> Action {
    Action::Invoke {
        contract: contract.to_vec(),
        function: function.to_vec(),
        args,
    }
}

/// `TOKEN.transfer(ALICE, BOB, amount)`.
fn transfer(amount: i128) -> Action {
    invoke(
        TOKEN,
        b"transfer",
        vec![
            Val::Address(ALICE.to_vec()),
            Val::Address(BOB.to_vec()),
            Val::I128(amount),
        ],
    )
}

fn create_contract() -> Action {
    Action::CreateContract {
        wasm_hash: b"wasm-hash".to_vec(),
    }
}

#[test]
fn contract_in() {
    let c = Caveat::ContractIn(ids(&[TOKEN, POOL]));
    assert!(holds(&c, &transfer(1)));
    assert!(holds(&c, &invoke(POOL, b"swap", vec![])));
    assert!(!holds(&c, &invoke(OTHER, b"transfer", vec![])));
    assert!(!holds(&Caveat::ContractIn(vec![]), &transfer(1)));
}

#[test]
fn contract_ids_compare_exactly() {
    let c = Caveat::ContractIn(ids(&[TOKEN]));
    assert!(!holds(&c, &invoke(b"CTOKE", b"transfer", vec![])));
    assert!(!holds(&c, &invoke(b"CTOKENX", b"transfer", vec![])));
    assert!(!holds(&c, &invoke(b"ctoken", b"transfer", vec![])));
}

#[test]
fn function_in() {
    let c = Caveat::FunctionIn(ids(&[b"transfer", b"approve"]));
    assert!(holds(&c, &transfer(1)));
    assert!(holds(&c, &invoke(OTHER, b"approve", vec![])));
    assert!(!holds(&c, &invoke(TOKEN, b"burn", vec![])));
    assert!(!holds(&c, &invoke(TOKEN, b"transfe", vec![])));
}

#[test]
fn arg_i128_at_most() {
    let c = Caveat::ArgI128AtMost(2, 100);
    assert!(holds(&c, &transfer(100)));
    assert!(holds(&c, &transfer(-5)));
    assert!(holds(&c, &transfer(i128::MIN)));
    assert!(!holds(&c, &transfer(101)));
    assert!(!holds(&c, &transfer(i128::MAX)));
    assert!(holds(
        &Caveat::ArgI128AtMost(2, i128::MAX),
        &transfer(i128::MAX)
    ));
}

#[test]
fn arg_i128_at_most_missing_or_wrongly_typed_argument() {
    let c = Caveat::ArgI128AtMost(2, 100);
    // Index past the end of the argument list.
    assert!(!holds(&c, &invoke(TOKEN, b"transfer", vec![])));
    assert!(!holds(&Caveat::ArgI128AtMost(3, 100), &transfer(1)));
    assert!(!holds(&Caveat::ArgI128AtMost(u32::MAX, 100), &transfer(1)));
    // A small amount of the wrong type is still denied.
    for wrong in [
        Val::U64(1),
        Val::Bool(false),
        Val::Bytes(vec![1]),
        Val::Address(ALICE.to_vec()),
        Val::Symbol(b"one".to_vec()),
    ] {
        let action = invoke(
            TOKEN,
            b"transfer",
            vec![
                Val::Address(ALICE.to_vec()),
                Val::Address(BOB.to_vec()),
                wrong,
            ],
        );
        assert!(!holds(&c, &action));
    }
}

#[test]
fn arg_eq() {
    let to_bob = Caveat::ArgEq(1, Val::Address(BOB.to_vec()));
    assert!(holds(&to_bob, &transfer(1)));
    let to_alice = Caveat::ArgEq(1, Val::Address(ALICE.to_vec()));
    assert!(!holds(&to_alice, &transfer(1)));
    assert!(holds(&Caveat::ArgEq(2, Val::I128(7)), &transfer(7)));
    assert!(!holds(&Caveat::ArgEq(2, Val::I128(7)), &transfer(8)));
}

#[test]
fn arg_eq_missing_or_wrongly_typed_argument() {
    assert!(!holds(&Caveat::ArgEq(3, Val::I128(1)), &transfer(1)));
    // Same bytes under a different variant is a different value.
    assert!(!holds(
        &Caveat::ArgEq(1, Val::Bytes(BOB.to_vec())),
        &transfer(1)
    ));
    assert!(!holds(
        &Caveat::ArgEq(1, Val::Symbol(BOB.to_vec())),
        &transfer(1)
    ));
    assert!(!holds(&Caveat::ArgEq(2, Val::U64(1)), &transfer(1)));
}

#[test]
fn val_eq_is_variant_and_payload_equality() {
    let all = || {
        vec![
            Val::I128(1),
            Val::U64(1),
            Val::Bool(true),
            Val::Bytes(vec![1]),
            Val::Address(vec![1]),
            Val::Symbol(vec![1]),
        ]
    };
    for (i, a) in all().iter().enumerate() {
        for (j, b) in all().iter().enumerate() {
            assert_eq!(val_eq(a, b), i == j, "{i} vs {j}");
        }
    }
    assert!(!val_eq(&Val::I128(1), &Val::I128(2)));
    assert!(!val_eq(&Val::U64(1), &Val::U64(2)));
    assert!(!val_eq(&Val::Bool(true), &Val::Bool(false)));
    assert!(!val_eq(&Val::Bytes(vec![1]), &Val::Bytes(vec![1, 0])));
    assert!(!val_eq(&Val::Address(vec![1]), &Val::Address(vec![2])));
    assert!(!val_eq(&Val::Symbol(vec![]), &Val::Symbol(vec![0])));
}

#[test]
fn create_contract_is_denied_by_every_caveat() {
    let every = [
        Caveat::ContractIn(ids(&[TOKEN, b"wasm-hash"])),
        Caveat::FunctionIn(ids(&[b"transfer"])),
        Caveat::ArgI128AtMost(0, i128::MAX),
        Caveat::ArgEq(0, Val::Bytes(b"wasm-hash".to_vec())),
    ];
    for c in &every {
        assert!(!holds(c, &create_contract()));
        assert!(!allows(std::slice::from_ref(c), &create_contract()));
    }
}

#[test]
fn empty_grant_allows_everything() {
    assert!(allows(&[], &transfer(i128::MAX)));
    assert!(allows(&[], &create_contract()));
    assert!(allows_all(&[], &[transfer(1), create_contract()]));
    assert!(allows_all(&[], &[]));
}

#[test]
fn grant_requires_every_caveat() {
    let grant = [
        Caveat::ContractIn(ids(&[TOKEN])),
        Caveat::FunctionIn(ids(&[b"transfer"])),
        Caveat::ArgI128AtMost(2, 100),
    ];
    assert!(allows(&grant, &transfer(100)));
    assert!(!allows(&grant, &transfer(101)));
    assert!(!allows(&grant, &invoke(TOKEN, b"burn", vec![Val::I128(1)])));
    assert!(!allows(&grant, &invoke(OTHER, b"transfer", vec![])));
}

#[test]
fn allows_all_denies_when_one_nested_context_is_disallowed() {
    let grant = [
        Caveat::ContractIn(ids(&[TOKEN, POOL])),
        Caveat::ArgI128AtMost(2, 100),
    ];
    // A pool call whose authorization tree also contains a token transfer.
    let swap = || {
        invoke(
            POOL,
            b"swap",
            vec![Val::Address(ALICE.to_vec()), Val::Bool(true), Val::I128(10)],
        )
    };
    assert!(allows_all(&grant, &[swap(), transfer(50)]));
    assert!(!allows_all(&grant, &[swap(), transfer(500)]));
    assert!(!allows_all(
        &grant,
        &[swap(), transfer(50), create_contract()]
    ));
    assert!(!allows_all(
        &grant,
        &[swap(), invoke(OTHER, b"transfer", vec![]), transfer(50)]
    ));
}

const N_CAVEATS: usize = 9;

fn caveat(i: usize) -> Caveat {
    match i {
        0 => Caveat::ContractIn(ids(&[TOKEN])),
        1 => Caveat::ContractIn(ids(&[TOKEN, POOL])),
        2 => Caveat::ContractIn(vec![]),
        3 => Caveat::FunctionIn(ids(&[b"transfer"])),
        4 => Caveat::ArgI128AtMost(2, 100),
        5 => Caveat::ArgI128AtMost(0, 0),
        6 => Caveat::ArgEq(0, Val::Address(ALICE.to_vec())),
        7 => Caveat::ArgEq(1, Val::Symbol(b"up".to_vec())),
        8 => Caveat::ArgEq(2, Val::I128(100)),
        _ => unreachable!(),
    }
}

const N_ACTIONS: usize = 10;

fn action(i: usize) -> Action {
    match i {
        0 => transfer(50),
        1 => transfer(100),
        2 => transfer(101),
        3 => transfer(i128::MIN),
        4 => invoke(
            POOL,
            b"swap",
            vec![Val::I128(-1), Val::Symbol(b"up".to_vec())],
        ),
        5 => invoke(OTHER, b"transfer", vec![Val::Address(ALICE.to_vec())]),
        6 => invoke(TOKEN, b"transfer", vec![]),
        7 => invoke(
            TOKEN,
            b"transfer",
            vec![
                Val::Address(ALICE.to_vec()),
                Val::Address(BOB.to_vec()),
                Val::U64(50),
            ],
        ),
        8 => invoke(POOL, b"transfer", vec![Val::Bytes(ALICE.to_vec())]),
        9 => create_contract(),
        _ => unreachable!(),
    }
}

/// The chain semantics in plain Rust.
fn reference(caveat: &Caveat, action: &Action) -> bool {
    let Action::Invoke {
        contract,
        function,
        args,
    } = action
    else {
        return false;
    };
    match caveat {
        Caveat::ContractIn(list) => list.iter().any(|x| x == contract),
        Caveat::FunctionIn(list) => list.iter().any(|x| x == function),
        Caveat::ArgI128AtMost(index, bound) => {
            matches!(args.get(*index as usize), Some(Val::I128(v)) if v <= bound)
        }
        Caveat::ArgEq(index, expected) => match (args.get(*index as usize), expected) {
            (Some(Val::I128(x)), Val::I128(y)) => x == y,
            (Some(Val::U64(x)), Val::U64(y)) => x == y,
            (Some(Val::Bool(x)), Val::Bool(y)) => x == y,
            (Some(Val::Bytes(x)), Val::Bytes(y))
            | (Some(Val::Address(x)), Val::Address(y))
            | (Some(Val::Symbol(x)), Val::Symbol(y)) => x == y,
            _ => false,
        },
    }
}

#[test]
fn exhaustive_attenuation_and_reference_agreement() {
    let seen = common::check_exhaustive(caveat, N_CAVEATS, action, N_ACTIONS, reference);
    assert!(seen.checks > 100_000, "{seen:?}");
}
