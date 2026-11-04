//! The one reading of a context that is the shell's own: what a call on the
//! budget asset spends. `soroban-facade` reads every context `rule_eval`
//! checks (`perch_rule_eval::convert::calls`).

use soroban_sdk::auth::ContractContext;
use soroban_sdk::{symbol_short, Env, TryFromVal};

/// The amount a call on the budget asset moves, if it is
/// `transfer(from, to, amount)` with a non-negative `i128` amount: the only
/// call on that asset a grant can authorize. A Stellar Asset Contract's
/// `transfer` requires `from`'s authorization, so the account's own
/// authorization of it names the account as `from`.
pub fn transfer_amount(e: &Env, c: &ContractContext) -> Option<u128> {
    if c.fn_name != symbol_short!("transfer") || c.args.len() != 3 {
        return None;
    }
    let amount = i128::try_from_val(e, &c.args.get_unchecked(2)).ok()?;
    u128::try_from(amount).ok()
}
