//! Every registry change is an event, so watchers and the alert pipeline can
//! announce each proposal, approval, attestation, and tree change publicly
//! (spec §10). Topic 0 is the struct name in snake case; topic 1 the domain
//! (or the proposal id for approvals).

use crate::ProposalKind;
use soroban_sdk::{contractevent, Address, Bytes, BytesN, Vec};

/// A member proposed an addition, retirement, or revocation. For an
/// addition, `modulus` is the full RSA modulus the key hash was computed
/// from; otherwise it is empty.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyProposed {
    #[topic]
    pub domain: Bytes,
    pub id: u32,
    pub kind: ProposalKind,
    pub key_hash: BytesN<32>,
    pub modulus: Bytes,
    pub proposer: Address,
}

/// A member approved a proposal (the proposer's own approval included).
/// `approved` is whether the proposal has reached its threshold.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalApproved {
    #[topic]
    pub id: u32,
    pub member: Address,
    pub approvals: u32,
    pub approved: bool,
}

/// An attester's signed observation of `selector._domainkey.domain` was
/// recorded against proposal `id`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsAttested {
    #[topic]
    pub domain: Bytes,
    pub id: u32,
    pub attester: BytesN<32>,
    pub selector: Bytes,
    pub key_hash: BytesN<32>,
    pub observed_live: bool,
    pub observed_at: u64,
    pub resolvers: Vec<Bytes>,
}

/// A key entered the tree at `index`, producing `root`. `attested` is
/// whether it took the 72-hour path.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyActivated {
    #[topic]
    pub domain: Bytes,
    pub id: u32,
    pub key_hash: BytesN<32>,
    pub index: u32,
    pub root: BytesN<32>,
    pub previous_root: BytesN<32>,
    pub attested: bool,
}

/// A key left the tree. `previous_root` (which holds it) stays acceptable
/// through ledger `previous_accepted_until`.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRetired {
    #[topic]
    pub domain: Bytes,
    pub id: u32,
    pub key_hash: BytesN<32>,
    pub index: u32,
    pub root: BytesN<32>,
    pub previous_root: BytesN<32>,
    pub previous_accepted_until: u32,
}

/// A key was revoked. `refused_roots` are the roots containing it that were
/// acceptable until now and no longer are; `root` is the current root.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRevoked {
    #[topic]
    pub domain: Bytes,
    pub id: u32,
    pub key_hash: BytesN<32>,
    pub root: BytesN<32>,
    pub refused_roots: Vec<BytesN<32>>,
}
