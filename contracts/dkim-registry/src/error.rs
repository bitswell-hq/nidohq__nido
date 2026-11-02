use soroban_sdk::contracterror;

/// Why construction or a registry call refused. Codes are part of the ABI.
///
/// An attestation whose Ed25519 signature does not verify is not an error
/// code: the host's `ed25519_verify` traps, and the call fails.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum DkimRegistryError {
    // --- construction -------------------------------------------------------
    /// No members, more than `MAX_MEMBERS`, or a duplicate.
    InvalidMembers = 1,
    /// Not `1 ≤ revoke_threshold ≤ threshold ≤ members`.
    InvalidThreshold = 2,
    /// No attesters, more than `MAX_ATTESTERS`, or a duplicate.
    InvalidAttesters = 3,
    /// Not `1 ≤ attest_threshold ≤ attesters`.
    InvalidAttestThreshold = 4,
    /// `grace_seconds` above `MAX_GRACE_SECONDS`.
    InvalidGrace = 5,
    /// No domains, more than `MAX_DOMAINS`, a malformed one, or a duplicate.
    InvalidDomains = 6,

    // --- governance ---------------------------------------------------------
    /// The caller is not a multisig member.
    NotAMember = 10,
    /// The domain is not on the allowlist.
    DomainNotAllowed = 11,
    /// The modulus is not exactly 2048 bits (256 big-endian bytes, top bit
    /// set).
    KeyNotRsa2048 = 12,
    /// The leaf is already in the tree.
    KeyAlreadyPresent = 13,
    /// The leaf is not in the tree.
    KeyNotPresent = 14,
    /// No proposal has this id.
    UnknownProposal = 15,
    /// The proposal is older than `PROPOSAL_LIFETIME_SECONDS`.
    ProposalExpired = 16,
    /// The proposal was already executed.
    ProposalClosed = 17,
    /// This member already approved the proposal.
    AlreadyApproved = 18,
    /// The proposal lacks its threshold of approvals.
    NotApproved = 19,
    /// The addition's timelock has not passed.
    TimelockActive = 20,
    /// The leaf was revoked after this addition was proposed.
    KeyRevoked = 21,
    /// All `REGISTRY_CAPACITY` indices are used.
    TreeFull = 22,
    /// The retirement lacks `attest_threshold` attestations that the key is
    /// gone from DNS.
    NotAttested = 23,

    // --- attestations -------------------------------------------------------
    /// The key is not one of the attesters.
    NotAnAttester = 30,
    /// The bytes are not a well-formed attestation (spec §7.5).
    MalformedAttestation = 31,
    /// The attestation names another registry.
    WrongRegistry = 32,
    /// The attestation's domain or key hash is not the proposal's.
    AttestationMismatch = 33,
    /// The observation is older than `MAX_ATTESTATION_AGE_SECONDS`, or later
    /// than `MAX_CLOCK_SKEW_SECONDS` past the ledger's close time.
    StaleAttestation = 34,
    /// This attester already has an observation at least as recent recorded
    /// for the proposal.
    AlreadyAttested = 35,
    /// Revocations take no attestations.
    NotAttestable = 36,
}
