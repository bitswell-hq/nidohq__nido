//! Files vocabulary: file system access by component path and mode.
//!
//! A path is a list of components, so `["home", "a"]` is a prefix of
//! `["home", "a", "x"]` but not of `["home", "ab"]`. Paths reach the
//! evaluator already canonical: resolving `..`, symlinks and
//! case-insensitive names is the host's job.

use alloc::vec::Vec;

use crate::bytes::bytes_eq;
use crate::Check;

/// An access mode.
pub enum Mode {
    Read,
    Write,
    Execute,
}

/// A file access.
pub struct Action {
    pub path: Vec<Vec<u8>>,
    pub mode: Mode,
}

/// A files caveat.
pub enum Caveat {
    /// This path is a component-wise prefix of the action's path.
    PathUnder(Vec<Vec<u8>>),
    /// The action's mode is one of these. Read-only is `ModeIn([Read])`.
    ModeIn(Vec<Mode>),
}

/// Whether `a` and `b` are the same mode.
#[must_use]
pub fn mode_eq(a: &Mode, b: &Mode) -> bool {
    matches!(
        (a, b),
        (Mode::Read, Mode::Read) | (Mode::Write, Mode::Write) | (Mode::Execute, Mode::Execute)
    )
}

/// Whether `mode` is one of the modes in `list`.
#[must_use]
pub fn mode_in(mode: &Mode, list: &[Mode]) -> bool {
    let mut i = 0;
    while i < list.len() {
        if mode_eq(mode, &list[i]) {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether `prefix` is a component-wise prefix of `path`.
#[must_use]
pub fn is_prefix(prefix: &[Vec<u8>], path: &[Vec<u8>]) -> bool {
    if prefix.len() > path.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if !bytes_eq(&prefix[i], &path[i]) {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `caveat` holds for `action`.
#[must_use]
pub fn holds(caveat: &Caveat, action: &Action) -> bool {
    match caveat {
        Caveat::PathUnder(prefix) => is_prefix(prefix, &action.path),
        Caveat::ModeIn(list) => mode_in(&action.mode, list),
    }
}

impl Check<Action> for Caveat {
    fn holds(&self, action: &Action) -> bool {
        holds(self, action)
    }
}

/// Whether `grant` allows `action`.
#[must_use]
pub fn allows(grant: &[Caveat], action: &Action) -> bool {
    crate::allows(grant, action)
}

/// Whether `grant` allows every action in `actions`.
#[must_use]
pub fn allows_all(grant: &[Caveat], actions: &[Action]) -> bool {
    crate::allows_all(grant, actions)
}
