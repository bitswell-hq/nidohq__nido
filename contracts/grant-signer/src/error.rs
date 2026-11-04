use soroban_sdk::contracterror;

/// Why a call or an authorization was refused. Codes are part of the ABI.
///
/// `__check_auth` returns the first failure: `NoSuchGrant` or `Revoked` for
/// the lineage; then, context by context, `ContractCreation`, `NotHolder`,
/// `AccountCall` or `UnmeteredCall`; then `NotAllowed`, `Expired` or
/// `CapExceeded` from the grant's rule set; then `Overdrawn` (or
/// `AllowanceTooLarge` for a lineage holding an amount above `i128::MAX`,
/// which no grant this contract stored does). A refused authorization
/// changes no state.
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
    /// No rule of the grant's rule set allows a context, or
    /// `rule_eval::authorize` refuses the authorization otherwise than
    /// `Expired` or `CapExceeded` say.
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
    /// The rule chosen for a context has passed its last ledger.
    Expired = 12,
    /// A rule's spending cap refuses a context's charge.
    CapExceeded = 13,
    /// `issue`'s rules hold a rule with more than one cap, a cap whose limit
    /// is not positive or whose period is 0, or rules of different
    /// generations.
    InvalidRules = 14,
    /// `rule_eval` refuses one of `delegate`'s attenuation steps on the
    /// parent's rule set, or a step names an address, symbol or signer with
    /// no `rule_eval` form.
    InvalidStep = 15,
}
