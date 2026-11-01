//! The DKIM key registry as wasm (`docs/email-recovery/spec.md` §7.3, §7.6):
//! no upgrade path, and the resources of its entry points.
//!
//! The registry's rules are pinned by its unit tests
//! (`contracts/dkim-registry/src/test.rs`) and, through the email guardian,
//! by `email_guardian.rs`.

use nido_dkim_registry::TIMELOCK_ATTESTED_LEDGERS;
use nido_dns_attestation_mock::{fixture, key_hash, modulus_2048};
use nido_integration_tests::email::TestRegistry;
use nido_integration_tests::world::world;
use nido_integration_tests::DKIM_REGISTRY_WASM;
use soroban_sdk::BytesN;
use wasmparser::{ExternalKind, Parser, Payload, TypeRef};

/// Every function the registry exports: governance, attestations,
/// execution, views, and keep-alives.
const EXPORTED: [&str; 20] = [
    "__constructor",
    "approve",
    "attest",
    "config",
    "eligible_at",
    "execute",
    "is_accepted_root",
    "key_hash",
    "leaf",
    "leaf_at",
    "proposal",
    "propose_add",
    "propose_retire",
    "propose_revoke",
    "renew",
    "renew_path",
    "root",
    "siblings",
    "state",
    "version",
];

/// Host functions that deploy or replace contract code (`soroban-env-common`
/// `env.json`, module `l`): `create_contract` (`3`), `upload_wasm` (`5`),
/// `update_current_contract_wasm` (`6`), `create_contract_with_constructor`
/// (`e`).
const CODE_CHANGING_IMPORTS: [(&str, &str); 4] = [("l", "3"), ("l", "5"), ("l", "6"), ("l", "e")];

/// The wasm cannot change its own code: it imports no host function that
/// replaces or deploys code, and it exports exactly the entry points above
/// (no `upgrade`, no admin, no setter).
#[test]
fn the_registry_has_no_upgrade_path() {
    let mut imports = std::vec::Vec::new();
    let mut exports = std::vec::Vec::new();
    for payload in Parser::new(0).parse_all(DKIM_REGISTRY_WASM) {
        match payload.unwrap() {
            Payload::ImportSection(section) => {
                for import in section {
                    let import = import.unwrap();
                    if matches!(import.ty, TypeRef::Func(_)) {
                        imports.push((import.module.to_owned(), import.name.to_owned()));
                    }
                }
            }
            Payload::ExportSection(section) => {
                for export in section {
                    let export = export.unwrap();
                    if export.kind == ExternalKind::Func {
                        exports.push(export.name.to_owned());
                    }
                }
            }
            _ => {}
        }
    }
    assert!(!imports.is_empty(), "the wasm calls the host");
    for (module, name) in CODE_CHANGING_IMPORTS {
        assert!(
            !imports.iter().any(|(m, n)| m == module && n == name),
            "imports {module}.{name}"
        );
    }
    exports.sort();
    assert_eq!(exports, EXPORTED);
}

/// Resources of the registry's entry points as wasm, read with
/// `cost_estimate().resources()` after each call, and the SDK's fee estimate
/// for them (`cost_estimate().fee()`, a hardcoded snapshot of mainnet fee
/// rates, not a network measurement): a proposal (the key hash
/// over the 2048-bit modulus), an attestation (parsing and the Ed25519
/// check), an activation (the 16-level root recomputation), and
/// `is_accepted_root`, the call every email approval through a registry
/// root makes.
#[test]
fn dkim_registry_costs() {
    let w = world();
    let registry = TestRegistry::deploy(&w, "costs");
    let client = registry.client(&w);
    let record = fixture("rsa2048-a");
    let n = modulus_2048(&record.parse().unwrap()).unwrap();

    let report = |case: &str| {
        let r = w.env.cost_estimate().resources();
        let fee = w.env.cost_estimate().fee();
        println!(
            "{{\"case\":\"{case}\",\"instructions\":{},\"mem_bytes\":{},\"read_entries\":{},\"disk_read_bytes\":{},\"write_entries\":{},\"write_bytes\":{},\"event_bytes\":{},\"fee_without_rent_stroops\":{},\"rent_stroops\":{}}}",
            r.instructions,
            r.mem_bytes,
            r.memory_read_entries + r.disk_read_entries,
            r.disk_read_bytes,
            r.write_entries,
            r.write_bytes,
            r.contract_events_size_bytes,
            fee.total - fee.persistent_entry_rent - fee.temporary_entry_rent,
            fee.persistent_entry_rent + fee.temporary_entry_rent,
        );
        r
    };

    let id = registry.propose_add(&w, 0, &record.domain, &n);
    report("propose_add");
    registry.approve(&w, 1, id);
    report("approve");
    registry.approve(&w, 2, id);
    registry.attest(&w, id, 0, &record);
    let attest = report("attest");
    registry.attest(&w, id, 1, &record);

    w.advance(TIMELOCK_ATTESTED_LEDGERS);
    let root = client.execute(&id);
    let activation = report("execute (activation: 16-level root recomputation)");
    assert!(client.is_accepted_root(&root));
    let check = report("is_accepted_root (accepted)");
    assert!(!client.is_accepted_root(&BytesN::from_array(&w.env, &[1u8; 32])));
    report("is_accepted_root (refused)");

    let kh = BytesN::from_array(&w.env, &key_hash(&n));
    let rid = registry.propose_revoke(&w, 3, &record.domain, &kh);
    registry.approve(&w, 4, rid);
    report("approve (revocation: removal and refusal)");

    // Loose ceilings, far below the network's per-transaction limits, so a
    // regression that multiplies the cost is caught here.
    assert!(check.instructions < 2_000_000, "is_accepted_root");
    assert!(attest.instructions < 5_000_000, "attest");
    assert!(activation.instructions < 50_000_000, "activation");
}
