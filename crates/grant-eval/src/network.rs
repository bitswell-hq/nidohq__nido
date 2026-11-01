//! Network vocabulary: outbound connections by host, port and scheme.
//!
//! The host is the name the agent requested, checked before resolution; the
//! runtime does the DNS lookup and the connecting. An HTTP redirect is a new
//! action and is checked again.

use alloc::vec::Vec;

use crate::bytes::bytes_in;
use crate::Check;

/// A URL scheme.
pub enum Scheme {
    Http,
    Https,
}

/// An outbound connection.
pub struct Action {
    pub host: Vec<u8>,
    pub port: u16,
    pub scheme: Scheme,
}

/// A network caveat.
pub enum Caveat {
    /// The action's host is one of these.
    HostIn(Vec<Vec<u8>>),
    /// The action's port is one of these.
    PortIn(Vec<u16>),
    /// The action's scheme is one of these. HTTPS only is `SchemeIn([Https])`.
    SchemeIn(Vec<Scheme>),
}

/// Whether `a` and `b` are the same scheme.
#[must_use]
pub fn scheme_eq(a: &Scheme, b: &Scheme) -> bool {
    matches!(
        (a, b),
        (Scheme::Http, Scheme::Http) | (Scheme::Https, Scheme::Https)
    )
}

/// Whether `scheme` is one of the schemes in `list`.
#[must_use]
pub fn scheme_in(scheme: &Scheme, list: &[Scheme]) -> bool {
    let mut i = 0;
    while i < list.len() {
        if scheme_eq(scheme, &list[i]) {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether `port` is one of the ports in `list`.
#[must_use]
pub fn port_in(port: u16, list: &[u16]) -> bool {
    let mut i = 0;
    while i < list.len() {
        if port == list[i] {
            return true;
        }
        i += 1;
    }
    false
}

/// Whether `caveat` holds for `action`.
#[must_use]
pub fn holds(caveat: &Caveat, action: &Action) -> bool {
    match caveat {
        Caveat::HostIn(list) => bytes_in(&action.host, list),
        Caveat::PortIn(list) => port_in(action.port, list),
        Caveat::SchemeIn(list) => scheme_in(&action.scheme, list),
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
