mod common;

use grant_eval::network::{allows, allows_all, holds, Action, Caveat, Scheme};

fn hosts(list: &[&str]) -> Vec<Vec<u8>> {
    list.iter().map(|h| h.as_bytes().to_vec()).collect()
}

fn connect(host: &str, port: u16, scheme: Scheme) -> Action {
    Action {
        host: host.as_bytes().to_vec(),
        port,
        scheme,
    }
}

#[test]
fn host_in() {
    let c = Caveat::HostIn(hosts(&["api.example.com", "cdn.example.com"]));
    assert!(holds(&c, &connect("api.example.com", 443, Scheme::Https)));
    assert!(holds(&c, &connect("cdn.example.com", 80, Scheme::Http)));
    assert!(!holds(&c, &connect("evil.example.com", 443, Scheme::Https)));
    assert!(!holds(
        &Caveat::HostIn(vec![]),
        &connect("api.example.com", 443, Scheme::Https)
    ));
}

#[test]
fn host_names_compare_exactly() {
    let c = Caveat::HostIn(hosts(&["api.example.com"]));
    assert!(!holds(
        &c,
        &connect("api.example.com.evil.net", 443, Scheme::Https)
    ));
    assert!(!holds(
        &c,
        &connect("x.api.example.com", 443, Scheme::Https)
    ));
    assert!(!holds(&c, &connect("example.com", 443, Scheme::Https)));
    assert!(!holds(&c, &connect("API.example.com", 443, Scheme::Https)));
}

#[test]
fn port_in() {
    let c = Caveat::PortIn(vec![443, 8443]);
    assert!(holds(&c, &connect("h", 443, Scheme::Https)));
    assert!(holds(&c, &connect("h", 8443, Scheme::Https)));
    assert!(!holds(&c, &connect("h", 80, Scheme::Https)));
    assert!(!holds(&c, &connect("h", 0, Scheme::Https)));
    assert!(holds(
        &Caveat::PortIn(vec![u16::MAX]),
        &connect("h", u16::MAX, Scheme::Http)
    ));
    assert!(!holds(
        &Caveat::PortIn(vec![]),
        &connect("h", 443, Scheme::Https)
    ));
}

#[test]
fn scheme_in() {
    let only_https = Caveat::SchemeIn(vec![Scheme::Https]);
    assert!(holds(&only_https, &connect("h", 443, Scheme::Https)));
    assert!(!holds(&only_https, &connect("h", 443, Scheme::Http)));
    let only_http = Caveat::SchemeIn(vec![Scheme::Http]);
    assert!(holds(&only_http, &connect("h", 80, Scheme::Http)));
    assert!(!holds(&only_http, &connect("h", 80, Scheme::Https)));
    assert!(!holds(
        &Caveat::SchemeIn(vec![]),
        &connect("h", 80, Scheme::Http)
    ));
}

#[test]
fn empty_grant_allows_everything() {
    assert!(allows(&[], &connect("anything", 1, Scheme::Http)));
    assert!(allows_all(
        &[],
        &[
            connect("a", 1, Scheme::Http),
            connect("b", 2, Scheme::Https)
        ]
    ));
}

#[test]
fn redirect_is_checked_as_a_new_action() {
    let grant = [
        Caveat::HostIn(hosts(&["api.example.com"])),
        Caveat::SchemeIn(vec![Scheme::Https]),
        Caveat::PortIn(vec![443]),
    ];
    let request = connect("api.example.com", 443, Scheme::Https);
    let redirect = connect("evil.example.net", 443, Scheme::Https);
    assert!(allows(&grant, &request));
    assert!(!allows(&grant, &redirect));
    assert!(!allows_all(&grant, &[request, redirect]));
}

const N_CAVEATS: usize = 8;

fn caveat(i: usize) -> Caveat {
    match i {
        0 => Caveat::HostIn(hosts(&["api.example.com"])),
        1 => Caveat::HostIn(hosts(&["api.example.com", "cdn.example.com"])),
        2 => Caveat::HostIn(vec![]),
        3 => Caveat::PortIn(vec![443]),
        4 => Caveat::PortIn(vec![80, 443]),
        5 => Caveat::SchemeIn(vec![Scheme::Https]),
        6 => Caveat::SchemeIn(vec![Scheme::Http, Scheme::Https]),
        7 => Caveat::SchemeIn(vec![Scheme::Http]),
        _ => unreachable!(),
    }
}

const N_ACTIONS: usize = 8;

fn action(i: usize) -> Action {
    match i {
        0 => connect("api.example.com", 443, Scheme::Https),
        1 => connect("api.example.com", 80, Scheme::Http),
        2 => connect("cdn.example.com", 443, Scheme::Https),
        3 => connect("cdn.example.com", 8080, Scheme::Http),
        4 => connect("evil.example.net", 443, Scheme::Https),
        5 => connect("api.example.co", 443, Scheme::Https),
        6 => connect("", 0, Scheme::Http),
        7 => connect("api.example.com", 443, Scheme::Http),
        _ => unreachable!(),
    }
}

fn is_https(s: &Scheme) -> bool {
    matches!(s, Scheme::Https)
}

/// The network semantics in plain Rust.
fn reference(c: &Caveat, a: &Action) -> bool {
    match c {
        Caveat::HostIn(list) => list.contains(&a.host),
        Caveat::PortIn(list) => list.contains(&a.port),
        Caveat::SchemeIn(list) => list.iter().any(|s| is_https(s) == is_https(&a.scheme)),
    }
}

#[test]
fn exhaustive_attenuation_and_reference_agreement() {
    let seen = common::check_exhaustive(caveat, N_CAVEATS, action, N_ACTIONS, reference);
    assert!(seen.checks > 50_000, "{seen:?}");
}
