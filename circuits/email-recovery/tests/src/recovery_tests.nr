//! The recovery relation (`email_recovery::recovery`, spec obligations C1 to
//! C6) over the Gmail-shaped header signed by test key A: the honest witness
//! is accepted, and changing any public input, or any private input that
//! links the email to them, is refused at the obligation it breaks.

use crate::vectors::{
    DIGEST_HI, DIGEST_LO, GMAIL_HEADER, GMAIL_SIG, KEY_A_MODULUS, KEY_A_REDC, KEY_B_MODULUS,
    OUTLOOK_HEADER, OUTLOOK_SIG, RHO,
};
use email_recovery::pack::{address_commitment, key_hash};
use email_recovery::recovery::verify_recovery_email;
use email_recovery::registry::{empty_subtree, merkle_root, registry_leaf};
use email_recovery::spec::HEADER_MAX;

global ADDRESS: str<23> = "alice.example@gmail.com";
global ACCOUNT_CODE: Field = 0x0102030405060708090a0b0c0d0e0f10;

fn bytes<let M: u32, let L: u32>(s: [u8; L]) -> BoundedVec<u8, M> {
    BoundedVec::from_array(s)
}

/// A header block at the circuit's bound, `HEADER_MAX`.
fn header<let L: u32>(h: [u8; L]) -> BoundedVec<u8, HEADER_MAX> {
    BoundedVec::from_array(h)
}

fn commitment<let L: u32>(address: str<L>, code: Field) -> Field {
    address_commitment(bytes(address.as_bytes()), code)
}

fn leaf<let L: u32>(domain: str<L>, modulus: [u128; 18]) -> Field {
    registry_leaf(bytes(domain.as_bytes()), key_hash(modulus))
}

/// The siblings of index 0 in a tree whose only leaf is at index 0.
fn lone_siblings() -> [Field; 16] {
    let mut s = [0; 16];
    for i in 0..16 {
        s[i] = empty_subtree(i);
    }
    s
}

/// Siblings of an arbitrary populated tree.
fn busy_siblings() -> [Field; 16] {
    let mut s = [0; 16];
    for i in 0..16 {
        s[i] = (i as Field + 1) * 0x1000001;
    }
    s
}

struct Witness {
    commitment: Field,
    digest_hi: Field,
    digest_lo: Field,
    key_root: Field,
    signature: [u128; 18],
    modulus: [u128; 18],
    rho: Field,
    account_code: Field,
    key_index: Field,
    key_siblings: [Field; 16],
}

/// The honest witness: Alice's address and code, the digest the Subject
/// carries, and key A for `gmail.com` alone at index 0 of the key tree.
fn honest() -> Witness {
    let siblings = lone_siblings();
    Witness {
        commitment: commitment(ADDRESS, ACCOUNT_CODE),
        digest_hi: DIGEST_HI,
        digest_lo: DIGEST_LO,
        key_root: merkle_root(leaf("gmail.com", KEY_A_MODULUS), 0, siblings),
        signature: GMAIL_SIG,
        modulus: KEY_A_MODULUS,
        rho: RHO,
        account_code: ACCOUNT_CODE,
        key_index: 0,
        key_siblings: siblings,
    }
}

fn prove<let L: u32>(h: str<L>, w: Witness) {
    verify_recovery_email(
        w.commitment,
        w.digest_hi,
        w.digest_lo,
        w.key_root,
        header(h.as_bytes()),
        w.modulus,
        KEY_A_REDC,
        w.signature,
        w.rho,
        w.account_code,
        w.key_index,
        w.key_siblings,
    );
}

/// `C` for this address and code, as `packages/email-recovery` (bb.js) and
/// the integration tests (the Soroban host's Poseidon2) also pin it.
#[test]
fn the_commitment_matches_the_other_implementations() {
    assert(
        commitment(ADDRESS, ACCOUNT_CODE)
            == 0x2c0e895ffe502297a6cf6881711fd974dec6e17f396b4c56977781fd07d5b73c,
    );
}

#[test]
fn an_honest_recovery_email_is_accepted() {
    prove(GMAIL_HEADER, honest());
}

/// The key at a high index of a populated tree: bits of the index choose the
/// side at every level.
#[test]
fn the_key_at_any_index_of_a_populated_tree_is_accepted() {
    let mut w = honest();
    w.key_index = 0xa5c3;
    w.key_siblings = busy_siblings();
    w.key_root = merkle_root(leaf("gmail.com", KEY_A_MODULUS), 0xa5c3, busy_siblings());
    prove(GMAIL_HEADER, w);
}

/// A bare From address under another launch domain (Outlook's shape).
#[test]
fn a_bare_address_at_another_provider_is_accepted() {
    let mut w = honest();
    w.commitment = commitment("bob-smith_99@outlook.com", ACCOUNT_CODE);
    w.signature = OUTLOOK_SIG;
    w.key_root = merkle_root(leaf("outlook.com", KEY_A_MODULUS), 0, lone_siblings());
    prove(OUTLOOK_HEADER, w);
}

#[test(should_fail_with = "recovery: the From address does not open the commitment")]
fn a_commitment_to_another_address_is_refused() {
    let mut w = honest();
    w.commitment = commitment("alice.example@outlook.com", ACCOUNT_CODE);
    prove(GMAIL_HEADER, w);
}

/// The address is committed exactly as signed: no case folding.
#[test(should_fail_with = "recovery: the From address does not open the commitment")]
fn a_commitment_to_a_case_variant_of_the_address_is_refused() {
    let mut w = honest();
    w.commitment = commitment("Alice.Example@gmail.com", ACCOUNT_CODE);
    prove(GMAIL_HEADER, w);
}

/// The same address under another account's code: another account's
/// guardian.
#[test(should_fail_with = "recovery: the From address does not open the commitment")]
fn a_commitment_under_another_account_code_is_refused() {
    let mut w = honest();
    w.commitment = commitment(ADDRESS, ACCOUNT_CODE + 1);
    prove(GMAIL_HEADER, w);
}

#[test(should_fail_with = "recovery: the From address does not open the commitment")]
fn the_wrong_account_code_for_the_commitment_is_refused() {
    let mut w = honest();
    w.account_code = ACCOUNT_CODE + 1;
    prove(GMAIL_HEADER, w);
}

/// Another statement's digest: the Subject carries one statement only.
#[test(should_fail_with = "Subject: value does not open to the statement digest")]
fn another_digest_hi_is_refused() {
    let mut w = honest();
    w.digest_hi = DIGEST_HI + 1;
    prove(GMAIL_HEADER, w);
}

#[test(should_fail_with = "Subject: value does not open to the statement digest")]
fn another_digest_lo_is_refused() {
    let mut w = honest();
    w.digest_lo = DIGEST_LO + 1;
    prove(GMAIL_HEADER, w);
}

#[test(should_fail_with = "Subject: value does not open to the statement digest")]
fn swapped_digest_limbs_are_refused() {
    let mut w = honest();
    w.digest_hi = DIGEST_LO;
    w.digest_lo = DIGEST_HI;
    prove(GMAIL_HEADER, w);
}

#[test(should_fail_with = "Subject: value does not open to the statement digest")]
fn another_rho_is_refused() {
    let mut w = honest();
    w.rho = RHO + 1;
    prove(GMAIL_HEADER, w);
}

#[test(should_fail_with = "recovery: the signing key is not in the key tree")]
fn a_root_without_the_key_is_refused() {
    let mut w = honest();
    w.key_root = empty_subtree(16);
    prove(GMAIL_HEADER, w);
}

/// The signing key registered for another domain: the leaf's domain is the
/// From domain, so the path does not reach that tree's root.
#[test(should_fail_with = "recovery: the signing key is not in the key tree")]
fn the_key_registered_under_another_domain_is_refused() {
    let mut w = honest();
    w.key_root = merkle_root(leaf("outlook.com", KEY_A_MODULUS), 0, lone_siblings());
    prove(GMAIL_HEADER, w);
}

/// A tree holding another key for the domain.
#[test(should_fail_with = "recovery: the signing key is not in the key tree")]
fn a_tree_with_another_key_for_the_domain_is_refused() {
    let mut w = honest();
    w.key_root = merkle_root(leaf("gmail.com", KEY_B_MODULUS), 0, lone_siblings());
    prove(GMAIL_HEADER, w);
}

#[test(should_fail_with = "recovery: the signing key is not in the key tree")]
fn the_wrong_leaf_index_is_refused() {
    let mut w = honest();
    w.key_index = 1;
    prove(GMAIL_HEADER, w);
}

/// The right leaf and path with the index outside the 16-bit range (index
/// + 2^16 has the same low bits).
#[test(should_fail_with = "Field failed to decompose into specified 16 limbs")]
fn a_leaf_index_of_16_or_more_bits_is_refused() {
    let mut w = honest();
    w.key_index = 0x10000;
    prove(GMAIL_HEADER, w);
}

/// The leaf itself presented as the root of an empty path.
#[test(should_fail_with = "recovery: the signing key is not in the key tree")]
fn the_leaf_as_key_root_is_refused() {
    let mut w = honest();
    w.key_root = leaf("gmail.com", KEY_A_MODULUS);
    prove(GMAIL_HEADER, w);
}

/// The registered key's modulus with a signature made under another key.
/// The modular reduction's witness hint finds no quotient, so it fails
/// before any assertion message.
#[test(should_fail)]
fn a_signature_under_another_key_is_refused() {
    let mut w = honest();
    w.modulus = KEY_B_MODULUS;
    w.key_root = merkle_root(leaf("gmail.com", KEY_B_MODULUS), 0, lone_siblings());
    prove(GMAIL_HEADER, w);
}
