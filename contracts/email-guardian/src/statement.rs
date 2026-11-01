//! The fields of a Perch recovery statement the guardian checks, read from
//! its fixed-width encoding (`docs/recovery/statement.md` in Perch).

use perch_recovery_interface::statement::{
    STATEMENT_DOMAIN, STATEMENT_PREFIX_LEN, STATEMENT_VERSION,
};

/// The longest encoding: a lost-key or compromise statement.
pub const MAX_STATEMENT_LEN: usize = 278;

const PREFIX_LEN: usize = STATEMENT_PREFIX_LEN as usize;

/// The statement fields the guardian binds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatementView {
    /// Perch action code: 1 lost-key, 2 compromise, 3 cancel, 4 reconfigure,
    /// 5 upgrade.
    pub action: u8,
    pub network_id: [u8; 32],
    /// The account's contract id.
    pub account: [u8; 32],
    /// The controller's contract id.
    pub controller: [u8; 32],
    pub valid_until_ledger: u32,
}

/// Total encoded length for each action code, or `None` for an unknown code.
fn encoded_len(action: u8) -> Option<usize> {
    match action {
        1 | 2 => Some(278),
        3 | 5 => Some(214),
        4 => Some(207),
        _ => None,
    }
}

fn array32(bytes: &[u8], at: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[at..][..32]);
    out
}

/// Read a version-2 statement encoding. `None` unless the domain prefix,
/// version, action code, and the action's exact length all match.
#[must_use]
pub fn parse(bytes: &[u8]) -> Option<StatementView> {
    if bytes.len() < PREFIX_LEN
        || bytes[..STATEMENT_DOMAIN.len()] != STATEMENT_DOMAIN[..]
        || bytes[24] != STATEMENT_VERSION
    {
        return None;
    }
    let action = bytes[25];
    if encoded_len(action)? != bytes.len() {
        return None;
    }
    let mut until = [0u8; 4];
    until.copy_from_slice(&bytes[170..174]);
    Some(StatementView {
        action,
        network_id: array32(bytes, 26),
        account: array32(bytes, 58),
        controller: array32(bytes, 90),
        valid_until_ledger: u32::from_be_bytes(until),
    })
}
