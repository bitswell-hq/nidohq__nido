use soroban_sdk::contracterror;

/// Why a call or an authorization was refused. Codes are part of the ABI.
///
/// `__check_auth` returns the first failure: `NoSuchGrant` or `Revoked` for
/// the lineage; then, context by context, `ContractCreation`, `NotHolder`,
/// `AccountCall` or `UnmeteredCall`; then `NotAllowed`; then `Overdrawn`
/// (or `AllowanceTooLarge` for a lineage holding an amount above
/// `i128::MAX`, which no grant this contract stored does). A refused
/// authorization changes no state.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum GrantError {
    /// No grant has this id.
    NoSuchGrant = 1,
    /// The grant or one of its ancestors is revoked.
    Revoked = 2,
    /// A context calls this contract other than to delegate from the signing
    /// grant itself.
    NotHolder = 3,
    /// A context calls the account this contract serves.
    AccountCall = 4,
    /// A context calls the budget asset other than as `transfer(from, to,
    /// amount)` with a non-negative `i128` amount.
    UnmeteredCall = 5,
    /// The grant's caveats do not allow every context.
    NotAllowed = 6,
    /// A transfer would take the grant or one of its ancestors past its
    /// allowance.
    Overdrawn = 7,
    /// `issue`'s asset is not a Stellar Asset Contract.
    NotStellarAsset = 8,
    /// The grant ids are exhausted.
    Overflow = 9,
    /// A context creates a contract. No grant authorizes one.
    ContractCreation = 10,
    /// An allowance passed to `issue` or `delegate`, a refill's `extra`, or
    /// the allowance a refill would raise to is above `i128::MAX`, the most
    /// a Stellar Asset Contract transfer moves.
    AllowanceTooLarge = 11,
}
