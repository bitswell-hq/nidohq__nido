use soroban_sdk::contracterror;

/// Why construction or `__check_auth` refused. Codes are part of the ABI.
///
/// `__check_auth` returns the first failure in the order the variants from
/// `UnexpectedContext` on are listed.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum EmailGuardianError {
    // --- construction -------------------------------------------------------
    /// `account` is not a contract address.
    AccountNotContract = 1,
    /// `controller` is not a contract address, or is the account itself.
    ControllerNotContract = 2,
    /// `registry` or `verifier` is not a contract address.
    DependencyNotContract = 3,
    /// `commitment` is zero or not a canonical BN254 field element.
    NonCanonicalCommitment = 4,
    /// More than one pin, a pin root that is not a canonical field element,
    /// or a pin that has already expired or outlives
    /// [`crate::MAX_PIN_LIFETIME_LEDGERS`].
    InvalidPin = 5,
    /// `allowed_actions` is empty or names a bit no action uses.
    InvalidAllowedActions = 6,
    /// The verifier's `circuit_id()` is not `circuit_id`, or the call failed.
    CircuitMismatch = 7,

    // --- __check_auth, in check order ---------------------------------------
    /// Not exactly one context, or it is not a call on the configured
    /// controller carrying one 32-byte digest.
    UnexpectedContext = 10,
    /// `sha256(statement)` is not the authorized digest.
    DigestMismatch = 11,
    /// The statement bytes are not a version-2 Perch statement encoding.
    MalformedStatement = 12,
    /// The statement names another network.
    WrongNetwork = 13,
    /// The statement names another account.
    WrongAccount = 14,
    /// The statement names another controller.
    WrongController = 15,
    /// The statement's action is not in `allowed_actions`.
    ActionNotAllowed = 16,
    /// The action reached the guardian through the wrong controller entry
    /// point (`submit_guardian` for lost-key, compromise, and cancel;
    /// `approve_change` for reconfigure and upgrade).
    WrongEntryPoint = 17,
    /// The current ledger is past the statement's `valid_until_ledger`.
    StatementExpired = 18,
    /// `key_root` is not a canonical field element.
    NonCanonicalRoot = 19,
    /// `key_root` is neither the unexpired pin nor a root the registry
    /// accepts.
    UnknownRoot = 20,
    /// The registry call failed.
    RegistryUnavailable = 21,
    /// The verifier refused the proof.
    ProofRejected = 22,
    /// The verifier could not run: its key did not parse, or the call failed.
    VerifierUnavailable = 23,
}
