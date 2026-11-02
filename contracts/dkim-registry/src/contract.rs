use crate::attestation::{self, is_domain, MAX_LEN as ATTESTATION_MAX_LEN};
use crate::error::DkimRegistryError as Error;
use crate::events::{
    DnsAttested, KeyActivated, KeyProposed, KeyRetired, KeyRevoked, ProposalApproved,
};
use crate::hash::{is_rsa_2048, Hasher, DOMAIN_MAX, MODULUS_BYTES};
use crate::tree::{self, empty_root, REGISTRY_CAPACITY};
use crate::{
    LeafId, LeafRecord, LiveRoot, Proposal, ProposalKind, RegistryConfig, RegistryState, RootSpan,
    MAX_ATTESTATION_AGE_SECONDS, MAX_ATTESTERS, MAX_CLOCK_SKEW_SECONDS, MAX_DOMAINS,
    MAX_GRACE_SECONDS, MAX_LIVE_ROOTS, MAX_MEMBERS, PROPOSAL_LIFETIME_SECONDS,
    TIMELOCK_ATTESTED_SECONDS, TIMELOCK_SECONDS, VERSION,
};
use perch_zk_primitives::contract_id;
use soroban_sdk::{
    contract, contractimpl, contracttype, panic_with_error, Address, Bytes, BytesN, Env, IntoVal,
    TryFromVal, Val, Vec,
};

#[contracttype]
#[derive(Clone, Debug, PartialEq, Eq)]
enum Key {
    Config,
    State,
    Proposal(u32),
    Leaf(LeafId),
    LeafAt(u32),
}

#[contract]
pub struct DkimRegistry;

// --- storage -----------------------------------------------------------------

fn config(e: &Env) -> RegistryConfig {
    e.storage()
        .instance()
        .get(&Key::Config)
        .expect("set at construction")
}

fn state(e: &Env) -> RegistryState {
    e.storage()
        .instance()
        .get(&Key::State)
        .expect("set at construction")
}

fn extend_instance(e: &Env) {
    let max = e.storage().max_ttl();
    e.storage().instance().extend_ttl(max, max);
}

fn put_state(e: &Env, st: &RegistryState) {
    e.storage().instance().set(&Key::State, st);
    extend_instance(e);
}

fn put_persistent<V: IntoVal<Env, Val>>(e: &Env, key: &Key, value: &V) {
    let max = e.storage().max_ttl();
    e.storage().persistent().set(key, value);
    e.storage().persistent().extend_ttl(key, max, max);
}

fn load_proposal(e: &Env, id: u32) -> Result<Proposal, Error> {
    e.storage()
        .persistent()
        .get(&Key::Proposal(id))
        .ok_or(Error::UnknownProposal)
}

fn leaf_record(e: &Env, leaf: &LeafId) -> Option<LeafRecord> {
    e.storage().persistent().get(&Key::Leaf(leaf.clone()))
}

// --- validation --------------------------------------------------------------

fn has_duplicates<T>(v: &Vec<T>) -> bool
where
    T: PartialEq + IntoVal<Env, Val> + TryFromVal<Env, Val>,
{
    for i in 0..v.len() {
        for j in i + 1..v.len() {
            if v.get_unchecked(i) == v.get_unchecked(j) {
                return true;
            }
        }
    }
    false
}

/// `bytes` copied out of the host, if it fits `N` bytes.
fn to_buf<const N: usize>(bytes: &Bytes) -> Option<([u8; N], usize)> {
    let len = bytes.len() as usize;
    if len > N {
        return None;
    }
    let mut buf = [0u8; N];
    bytes.copy_into_slice(&mut buf[..len]);
    Some((buf, len))
}

fn validate(c: &RegistryConfig) -> Result<(), Error> {
    let members = c.members.len();
    if members == 0 || members > MAX_MEMBERS || has_duplicates(&c.members) {
        return Err(Error::InvalidMembers);
    }
    if c.revoke_threshold == 0 || c.revoke_threshold > c.threshold || c.threshold > members {
        return Err(Error::InvalidThreshold);
    }
    let attesters = c.attesters.len();
    if attesters == 0 || attesters > MAX_ATTESTERS || has_duplicates(&c.attesters) {
        return Err(Error::InvalidAttesters);
    }
    if c.attest_threshold == 0 || c.attest_threshold > attesters {
        return Err(Error::InvalidAttestThreshold);
    }
    if c.grace_seconds > MAX_GRACE_SECONDS {
        return Err(Error::InvalidGrace);
    }
    let domains = c.domains.len();
    if domains == 0 || domains > MAX_DOMAINS || has_duplicates(&c.domains) {
        return Err(Error::InvalidDomains);
    }
    for domain in c.domains.iter() {
        match to_buf::<DOMAIN_MAX>(&domain) {
            Some((buf, len)) if is_domain(&buf[..len]) => {}
            _ => return Err(Error::InvalidDomains),
        }
    }
    Ok(())
}

fn member_index(c: &RegistryConfig, who: &Address) -> Result<u32, Error> {
    c.members
        .first_index_of(who.clone())
        .ok_or(Error::NotAMember)
}

fn check_domain(c: &RegistryConfig, domain: &Bytes) -> Result<(), Error> {
    if c.domains.contains(domain) {
        Ok(())
    } else {
        Err(Error::DomainNotAllowed)
    }
}

/// The ledger's close time, in Unix seconds: the clock every timelock,
/// grace period, and proposal lifetime is measured on.
fn now(e: &Env) -> u64 {
    e.ledger().timestamp()
}

/// A proposal can still be approved, attested, or executed.
fn check_open(e: &Env, p: &Proposal) -> Result<(), Error> {
    if p.executed {
        return Err(Error::ProposalClosed);
    }
    if now(e) > p.created_at.saturating_add(PROPOSAL_LIFETIME_SECONDS) {
        return Err(Error::ProposalExpired);
    }
    Ok(())
}

// --- timelock ----------------------------------------------------------------

/// When an approved addition may execute: 7 days after approval, or 72 hours
/// after both approval and the attester threshold's live observations if the
/// leaf was never revoked. The flag says whether the 72-hour path is the
/// earlier one.
fn eligibility(p: &Proposal, rec: Option<&LeafRecord>) -> Option<(u64, bool)> {
    if p.kind != ProposalKind::Add {
        return None;
    }
    let approved = p.approved_at?;
    let slow = approved.saturating_add(TIMELOCK_SECONDS);
    let never_revoked = rec.is_none_or(|r| r.revoked_by == 0);
    match p.attested_at {
        Some(attested) if never_revoked => {
            let fast = approved
                .max(attested)
                .saturating_add(TIMELOCK_ATTESTED_SECONDS);
            Some((slow.min(fast), fast < slow))
        }
        _ => Some((slow, false)),
    }
}

// --- the tree and its roots -------------------------------------------------

/// Make `new_root` current: the old current root starts its grace period,
/// roots past theirs are dropped, and at most [`MAX_LIVE_ROOTS`] are kept.
/// Returns the superseded root.
fn change_root(
    e: &Env,
    c: &RegistryConfig,
    st: &mut RegistryState,
    new_root: BytesN<32>,
) -> BytesN<32> {
    let at = now(e);
    let previous = st.root.clone();
    st.seq += 1;
    let mut live = Vec::new(e);
    for r in st.live_roots.iter() {
        let superseded_at = r.superseded_at.unwrap_or(at);
        if at <= superseded_at.saturating_add(c.grace_seconds) {
            live.push_back(LiveRoot {
                superseded_at: Some(superseded_at),
                ..r
            });
        }
    }
    if new_root != empty_root(e) {
        live.push_back(LiveRoot {
            root: new_root.clone(),
            seq: st.seq,
            superseded_at: None,
        });
    }
    while live.len() > MAX_LIVE_ROOTS {
        live.remove(0);
    }
    st.live_roots = live;
    st.root = new_root;
    previous
}

fn domain_bytes(domain: &Bytes) -> ([u8; DOMAIN_MAX], usize) {
    to_buf::<DOMAIN_MAX>(domain).expect("allowlisted domains fit")
}

/// Append `leaf_id` at the next index. Returns `(index, previous root)`.
fn insert(
    e: &Env,
    c: &RegistryConfig,
    st: &mut RegistryState,
    leaf_id: &LeafId,
    rec: Option<LeafRecord>,
) -> (u32, BytesN<32>) {
    let mut h = Hasher::new(e);
    let (buf, len) = domain_bytes(&leaf_id.domain);
    let leaf = h.leaf(&buf[..len], &leaf_id.key_hash);
    let index = st.next_index;
    st.next_index += 1;
    let root = tree::set_leaf(e, &mut h, index, &leaf);
    let previous = change_root(e, c, st, root);

    let mut rec = rec.unwrap_or(LeafRecord {
        index,
        present: false,
        spans: Vec::new(e),
        revoked_by: 0,
    });
    rec.index = index;
    rec.present = true;
    rec.spans.push_back(RootSpan {
        from: st.seq,
        to: u32::MAX,
    });
    put_persistent(e, &Key::Leaf(leaf_id.clone()), &rec);
    put_persistent(e, &Key::LeafAt(index), leaf_id);
    (index, previous)
}

/// Empty `rec`'s leaf. Returns the previous root.
fn remove(e: &Env, c: &RegistryConfig, st: &mut RegistryState, rec: &mut LeafRecord) -> BytesN<32> {
    let mut h = Hasher::new(e);
    let root = tree::set_leaf(e, &mut h, rec.index, &BytesN::from_array(e, &[0u8; 32]));
    let previous = change_root(e, c, st, root);
    rec.present = false;
    let last = rec.spans.len() - 1;
    let mut span = rec.spans.get_unchecked(last);
    span.to = st.seq;
    rec.spans.set(last, span);
    e.storage().persistent().remove(&Key::LeafAt(rec.index));
    previous
}

/// Revoke `p`'s leaf: take it out of the tree if present, refuse every live
/// root that contains it, and bar additions proposed before now.
fn revoke(e: &Env, c: &RegistryConfig, st: &mut RegistryState, p: &mut Proposal, id: u32) {
    let leaf_id = LeafId {
        domain: p.domain.clone(),
        key_hash: p.key_hash.clone(),
    };
    let mut rec = leaf_record(e, &leaf_id).unwrap_or(LeafRecord {
        index: 0,
        present: false,
        spans: Vec::new(e),
        revoked_by: 0,
    });
    if rec.present {
        remove(e, c, st, &mut rec);
    }
    let mut refused = Vec::new(e);
    let mut kept = Vec::new(e);
    for r in st.live_roots.iter() {
        if rec.spans.iter().any(|s| s.from <= r.seq && r.seq < s.to) {
            refused.push_back(r.root);
        } else {
            kept.push_back(r);
        }
    }
    st.live_roots = kept;
    rec.revoked_by = id;
    put_persistent(e, &Key::Leaf(leaf_id), &rec);
    p.executed = true;
    KeyRevoked {
        domain: p.domain.clone(),
        id,
        key_hash: p.key_hash.clone(),
        root: st.root.clone(),
        refused_roots: refused,
    }
    .publish(e);
}

// --- proposals ---------------------------------------------------------------

/// Record `member`'s approval; true when it is the one that reaches the
/// proposal's threshold.
fn record_approval(
    e: &Env,
    c: &RegistryConfig,
    p: &mut Proposal,
    id: u32,
    member: &Address,
    index: u32,
) -> Result<bool, Error> {
    let bit = 1u32 << index;
    if p.approvals & bit != 0 {
        return Err(Error::AlreadyApproved);
    }
    p.approvals |= bit;
    let count = p.approvals.count_ones();
    let needed = if p.kind == ProposalKind::Revoke {
        c.revoke_threshold
    } else {
        c.threshold
    };
    let approved = count >= needed;
    let reached_now = approved && p.approved_at.is_none();
    if reached_now {
        p.approved_at = Some(now(e));
    }
    ProposalApproved {
        id,
        member: member.clone(),
        approvals: count,
        approved,
    }
    .publish(e);
    Ok(reached_now)
}

fn create(
    e: &Env,
    c: &RegistryConfig,
    proposer: &Address,
    kind: ProposalKind,
    domain: Bytes,
    key_hash: BytesN<32>,
    modulus: Bytes,
) -> Result<u32, Error> {
    let index = member_index(c, proposer)?;
    let mut st = state(e);
    let id = st.next_proposal;
    st.next_proposal += 1;
    let mut p = Proposal {
        kind,
        domain: domain.clone(),
        key_hash: key_hash.clone(),
        created_at: now(e),
        approvals: 0,
        approved_at: None,
        live: 0,
        blank: 0,
        observed_at: Vec::new(e),
        attested_at: None,
        executed: false,
    };
    KeyProposed {
        domain,
        id,
        kind,
        key_hash,
        modulus,
        proposer: proposer.clone(),
    }
    .publish(e);
    if record_approval(e, c, &mut p, id, proposer, index)? && kind == ProposalKind::Revoke {
        revoke(e, c, &mut st, &mut p, id);
    }
    put_persistent(e, &Key::Proposal(id), &p);
    put_state(e, &st);
    Ok(id)
}

fn modulus_array(modulus: &Bytes) -> Result<[u8; MODULUS_BYTES], Error> {
    match to_buf::<MODULUS_BYTES>(modulus) {
        Some((buf, len)) if is_rsa_2048(&buf[..len]) => Ok(buf),
        _ => Err(Error::KeyNotRsa2048),
    }
}

#[contractimpl]
// `#[contractimpl]` entry points: the SDK ABI takes owned arguments.
#[allow(clippy::needless_pass_by_value)]
impl DkimRegistry {
    /// Fix the configuration and start from the empty tree. Refuses (see
    /// [`Error`]'s construction variants) unless the member and attester
    /// sets are non-empty, bounded, and duplicate-free, the thresholds are in
    /// range, the grace period is at most [`MAX_GRACE_SECONDS`], and every
    /// allowlisted domain is a well-formed lowercase domain.
    pub fn __constructor(e: Env, config: RegistryConfig) {
        if let Err(err) = validate(&config) {
            panic_with_error!(&e, err);
        }
        e.storage().instance().set(&Key::Config, &config);
        put_state(
            &e,
            &RegistryState {
                root: empty_root(&e),
                seq: 0,
                next_index: 0,
                next_proposal: 1,
                live_roots: Vec::new(&e),
            },
        );
    }

    /// Propose admitting the RSA-2048 key `modulus` (256 big-endian bytes)
    /// for `domain`. The registry computes the key hash itself (spec §7.1).
    /// The proposer's approval is counted. Returns the proposal id.
    ///
    /// # Errors
    /// `NotAMember`, `DomainNotAllowed`, `KeyNotRsa2048`, `KeyAlreadyPresent`.
    pub fn propose_add(
        e: &Env,
        proposer: Address,
        domain: Bytes,
        modulus: Bytes,
    ) -> Result<u32, Error> {
        proposer.require_auth();
        let c = config(e);
        member_index(&c, &proposer)?;
        check_domain(&c, &domain)?;
        let key_hash = Hasher::new(e).key_hash(&modulus_array(&modulus)?);
        let leaf_id = LeafId {
            domain: domain.clone(),
            key_hash: key_hash.clone(),
        };
        if leaf_record(e, &leaf_id).is_some_and(|r| r.present) {
            return Err(Error::KeyAlreadyPresent);
        }
        create(
            e,
            &c,
            &proposer,
            ProposalKind::Add,
            domain,
            key_hash,
            modulus,
        )
    }

    /// Propose retiring a key in the tree that its provider no longer
    /// publishes. Returns the proposal id.
    ///
    /// # Errors
    /// `NotAMember`, `DomainNotAllowed`, `KeyNotPresent`.
    pub fn propose_retire(
        e: &Env,
        proposer: Address,
        domain: Bytes,
        key_hash: BytesN<32>,
    ) -> Result<u32, Error> {
        proposer.require_auth();
        let c = config(e);
        member_index(&c, &proposer)?;
        check_domain(&c, &domain)?;
        let leaf_id = LeafId {
            domain: domain.clone(),
            key_hash: key_hash.clone(),
        };
        if !leaf_record(e, &leaf_id).is_some_and(|r| r.present) {
            return Err(Error::KeyNotPresent);
        }
        create(
            e,
            &c,
            &proposer,
            ProposalKind::Retire,
            domain,
            key_hash,
            Bytes::new(e),
        )
    }

    /// Propose revoking `(domain, key_hash)` for compromise, whether it is in
    /// the tree, pending, or unknown. With `revoke_threshold = 1` it takes
    /// effect at once. Returns the proposal id.
    ///
    /// # Errors
    /// `NotAMember`, `DomainNotAllowed`.
    pub fn propose_revoke(
        e: &Env,
        proposer: Address,
        domain: Bytes,
        key_hash: BytesN<32>,
    ) -> Result<u32, Error> {
        proposer.require_auth();
        let c = config(e);
        member_index(&c, &proposer)?;
        check_domain(&c, &domain)?;
        create(
            e,
            &c,
            &proposer,
            ProposalKind::Revoke,
            domain,
            key_hash,
            Bytes::new(e),
        )
    }

    /// `member` approves proposal `id`. The approval that brings a revocation
    /// to `revoke_threshold` also executes it.
    ///
    /// # Errors
    /// `NotAMember`, `UnknownProposal`, `ProposalClosed`, `ProposalExpired`,
    /// `AlreadyApproved`.
    pub fn approve(e: &Env, member: Address, id: u32) -> Result<(), Error> {
        member.require_auth();
        let c = config(e);
        let index = member_index(&c, &member)?;
        let mut p = load_proposal(e, id)?;
        check_open(e, &p)?;
        let reached = record_approval(e, &c, &mut p, id, &member, index)?;
        if reached && p.kind == ProposalKind::Revoke {
            let mut st = state(e);
            revoke(e, &c, &mut st, &mut p, id);
            put_state(e, &st);
        }
        put_persistent(e, &Key::Proposal(id), &p);
        Ok(())
    }

    /// Record attester `attester`'s signed DNS observation (spec §7.5)
    /// against addition or retirement `id`; a newer observation replaces the
    /// attester's earlier one. Permissionless: anyone may relay an
    /// attestation. An invalid `signature` traps in the host.
    ///
    /// # Errors
    /// `NotAnAttester`, `UnknownProposal`, `ProposalClosed`,
    /// `ProposalExpired`, `NotAttestable`, `MalformedAttestation`,
    /// `WrongRegistry`, `AttestationMismatch`, `StaleAttestation`,
    /// `AlreadyAttested`.
    pub fn attest(
        e: &Env,
        id: u32,
        attester: BytesN<32>,
        attestation: Bytes,
        signature: BytesN<64>,
    ) -> Result<(), Error> {
        let c = config(e);
        let index = c
            .attesters
            .first_index_of(attester.clone())
            .ok_or(Error::NotAnAttester)?;
        let mut p = load_proposal(e, id)?;
        check_open(e, &p)?;
        if p.kind == ProposalKind::Revoke {
            return Err(Error::NotAttestable);
        }
        let (buf, len) =
            to_buf::<ATTESTATION_MAX_LEN>(&attestation).ok_or(Error::MalformedAttestation)?;
        let a = attestation::parse(&buf[..len]).ok_or(Error::MalformedAttestation)?;
        let this = contract_id(e, &e.current_contract_address());
        if this.is_none_or(|id| a.registry != id.to_array()) {
            return Err(Error::WrongRegistry);
        }
        if Bytes::from_slice(e, a.domain) != p.domain || a.key_hash != p.key_hash.to_array() {
            return Err(Error::AttestationMismatch);
        }
        let ts = now(e);
        if a.observed_at > ts.saturating_add(MAX_CLOCK_SKEW_SECONDS)
            || ts.saturating_sub(a.observed_at) > MAX_ATTESTATION_AGE_SECONDS
        {
            return Err(Error::StaleAttestation);
        }
        // Each attester's latest observation is the one that counts.
        let bit = 1u32 << index;
        let recorded = (p.live | p.blank) & bit != 0;
        if recorded && a.observed_at <= p.observed_at.get(index).unwrap_or(0) {
            return Err(Error::AlreadyAttested);
        }
        e.crypto()
            .ed25519_verify(&attester, &attestation, &signature);

        p.live &= !bit;
        p.blank &= !bit;
        if a.observed_live {
            p.live |= bit;
        } else {
            p.blank |= bit;
        }
        while p.observed_at.len() <= index {
            p.observed_at.push_back(0);
        }
        p.observed_at.set(index, a.observed_at);
        let counted = if p.kind == ProposalKind::Add {
            p.live
        } else {
            p.blank
        };
        // `attested_at` marks when the threshold was last reached; a newer
        // observation that drops the count below it clears it.
        if counted.count_ones() >= c.attest_threshold {
            if p.attested_at.is_none() {
                p.attested_at = Some(now(e));
            }
        } else {
            p.attested_at = None;
        }
        let mut resolvers = Vec::new(e);
        for r in a.resolvers() {
            resolvers.push_back(Bytes::from_slice(e, r));
        }
        DnsAttested {
            domain: p.domain.clone(),
            id,
            attester,
            selector: Bytes::from_slice(e, a.selector),
            key_hash: p.key_hash.clone(),
            observed_live: a.observed_live,
            observed_at: a.observed_at,
            resolvers,
        }
        .publish(e);
        put_persistent(e, &Key::Proposal(id), &p);
        Ok(())
    }

    /// Execute an approved addition once its timelock has passed, or an
    /// approved and attested retirement. Permissionless. Returns the new
    /// root.
    ///
    /// # Errors
    /// `UnknownProposal`, `ProposalClosed`, `ProposalExpired`, `NotApproved`,
    /// and for an addition `KeyRevoked`, `KeyAlreadyPresent`,
    /// `TimelockActive`, `TreeFull`; for a retirement `NotAttested`,
    /// `KeyNotPresent`.
    pub fn execute(e: &Env, id: u32) -> Result<BytesN<32>, Error> {
        let c = config(e);
        let mut p = load_proposal(e, id)?;
        check_open(e, &p)?;
        if p.approved_at.is_none() {
            return Err(Error::NotApproved);
        }
        let leaf_id = LeafId {
            domain: p.domain.clone(),
            key_hash: p.key_hash.clone(),
        };
        let rec = leaf_record(e, &leaf_id);
        let mut st = state(e);
        match p.kind {
            ProposalKind::Add => {
                if rec.as_ref().is_some_and(|r| r.revoked_by > id) {
                    return Err(Error::KeyRevoked);
                }
                if rec.as_ref().is_some_and(|r| r.present) {
                    return Err(Error::KeyAlreadyPresent);
                }
                let Some((eligible, attested)) = eligibility(&p, rec.as_ref()) else {
                    return Err(Error::NotApproved);
                };
                if now(e) < eligible {
                    return Err(Error::TimelockActive);
                }
                if st.next_index >= REGISTRY_CAPACITY {
                    return Err(Error::TreeFull);
                }
                let (index, previous_root) = insert(e, &c, &mut st, &leaf_id, rec);
                KeyActivated {
                    domain: p.domain.clone(),
                    id,
                    key_hash: p.key_hash.clone(),
                    index,
                    root: st.root.clone(),
                    previous_root,
                    attested,
                }
                .publish(e);
            }
            ProposalKind::Retire => {
                if p.attested_at.is_none() {
                    return Err(Error::NotAttested);
                }
                let mut rec = match rec {
                    Some(r) if r.present => r,
                    _ => return Err(Error::KeyNotPresent),
                };
                let previous_root = remove(e, &c, &mut st, &mut rec);
                put_persistent(e, &Key::Leaf(leaf_id), &rec);
                KeyRetired {
                    domain: p.domain.clone(),
                    id,
                    key_hash: p.key_hash.clone(),
                    index: rec.index,
                    root: st.root.clone(),
                    previous_root,
                    previous_accepted_until: now(e).saturating_add(c.grace_seconds),
                }
                .publish(e);
            }
            // A revocation executes with the approval that reaches its
            // threshold, so an approved one is always closed.
            ProposalKind::Revoke => return Err(Error::ProposalClosed),
        }
        p.executed = true;
        put_persistent(e, &Key::Proposal(id), &p);
        put_state(e, &st);
        Ok(st.root)
    }

    /// `DkimRegistryInterface::is_accepted_root` (spec §7.3): `root` is the
    /// current root, or a root superseded no more than `grace_seconds` ago,
    /// and no key it contains has been revoked. The empty tree's root is
    /// never accepted. Reads instance storage only.
    #[must_use]
    pub fn is_accepted_root(e: &Env, root: BytesN<32>) -> bool {
        let st = state(e);
        let grace = config(e).grace_seconds;
        let at = now(e);
        let accepted = root != empty_root(e)
            && st.live_roots.iter().any(|r| {
                r.root == root
                    && r.superseded_at
                        .is_none_or(|s| at <= s.saturating_add(grace))
            });
        // The check keeps the registry alive while guardians rely on it.
        let max = e.storage().max_ttl();
        e.storage().instance().extend_ttl(max / 2, max);
        accepted
    }

    /// The current root.
    #[must_use]
    pub fn root(e: &Env) -> BytesN<32> {
        state(e).root
    }

    /// The current root, its sequence number, the next leaf index and
    /// proposal id, and the roots that may still be acceptable.
    #[must_use]
    pub fn state(e: &Env) -> RegistryState {
        state(e)
    }

    /// The configuration fixed at construction.
    #[must_use]
    pub fn config(e: &Env) -> RegistryConfig {
        config(e)
    }

    #[must_use]
    pub fn proposal(e: &Env, id: u32) -> Option<Proposal> {
        e.storage().persistent().get(&Key::Proposal(id))
    }

    /// The earliest ledger close time at which an approved addition may
    /// execute; `None` for anything else.
    #[must_use]
    pub fn eligible_at(e: &Env, id: u32) -> Option<u64> {
        let p: Proposal = e.storage().persistent().get(&Key::Proposal(id))?;
        let rec = leaf_record(
            e,
            &LeafId {
                domain: p.domain.clone(),
                key_hash: p.key_hash.clone(),
            },
        );
        eligibility(&p, rec.as_ref()).map(|(at, _)| at)
    }

    #[must_use]
    pub fn leaf(e: &Env, domain: Bytes, key_hash: BytesN<32>) -> Option<LeafRecord> {
        leaf_record(e, &LeafId { domain, key_hash })
    }

    /// The key leaf at `index`, if the tree holds one there.
    #[must_use]
    pub fn leaf_at(e: &Env, index: u32) -> Option<LeafId> {
        e.storage().persistent().get(&Key::LeafAt(index))
    }

    /// Leaf `index`'s Merkle witness in the current tree.
    #[must_use]
    pub fn siblings(e: &Env, index: u32) -> Vec<BytesN<32>> {
        tree::siblings(e, index)
    }

    /// `key_hash` of an RSA-2048 modulus (spec §7.1), as an addition
    /// computes it.
    ///
    /// # Errors
    /// `KeyNotRsa2048`.
    pub fn key_hash(e: &Env, modulus: Bytes) -> Result<BytesN<32>, Error> {
        Ok(Hasher::new(e).key_hash(&modulus_array(&modulus)?))
    }

    /// See [`VERSION`].
    #[must_use]
    pub fn version(_e: &Env) -> u32 {
        VERSION
    }

    /// Extend the instance and its code to the network's maximum TTL.
    /// Permissionless; changes nothing else.
    pub fn renew(e: &Env) {
        extend_instance(e);
    }

    /// Extend leaf `index`'s tree path, its siblings, and its records to the
    /// network's maximum TTL. Permissionless; changes nothing else.
    pub fn renew_path(e: &Env, index: u32) {
        tree::renew_path(e, index);
        let max = e.storage().max_ttl();
        let storage = e.storage().persistent();
        let at = Key::LeafAt(index);
        if let Some(leaf_id) = storage.get::<_, LeafId>(&at) {
            storage.extend_ttl(&at, max, max);
            storage.extend_ttl(&Key::Leaf(leaf_id), max, max);
        }
    }
}
