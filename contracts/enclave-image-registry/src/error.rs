use soroban_sdk::contracterror;

/// Why a call refused. Codes are part of the ABI.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RegistryError {
    /// The signer set is empty, larger than [`crate::MAX_SIGNERS`], or names
    /// an address twice.
    InvalidSigners = 1,
    /// `threshold` is zero or larger than the signer set.
    InvalidThreshold = 2,
    /// The caller is not one of the registry's signers.
    NotASigner = 3,
    /// This signer already voted the same way on this measurement.
    AlreadyVoted = 4,
    /// Approval votes are accepted only while the measurement is pending.
    NotPending = 5,
    /// `activate` needs a queued measurement.
    NotQueued = 6,
    /// `activate` before `active_from`.
    TimelockNotElapsed = 7,
    /// The measurement was revoked; nothing more can happen to it.
    Revoked = 8,
    /// No proposal exists for this measurement.
    UnknownMeasurement = 9,
}
