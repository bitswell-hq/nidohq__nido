//! Network wiring through the host, against local HTTP servers: host, port
//! and scheme checks before any connection, and every redirect checked as a
//! new action.

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use agent_host::grant::{Grants, NetworkCaveat, Scheme};
use agent_host::net::{Method, Request};
use agent_host::{CallError, Output, ToolCall, Vocabulary};
use common::host_with;

/// A local server that answers every request with `answer(path)` and counts
/// the requests it receives.
struct Server {
    port: u16,
    hits: Arc<AtomicUsize>,
}

impl Server {
    fn start(answer: impl Fn(&str) -> (u16, Option<String>) + Send + 'static) -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        thread::spawn(move || {
            for request in server.incoming_requests() {
                counter.fetch_add(1, Ordering::SeqCst);
                let (status, location) = answer(request.url());
                let mut response =
                    tiny_http::Response::from_string(format!("hello from {}", request.url()))
                        .with_status_code(status);
                if let Some(location) = location {
                    response = response
                        .with_header(tiny_http::Header::from_bytes("Location", location).unwrap());
                }
                let _ = request.respond(response);
            }
        });
        Self { port, hits }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

fn network(caveats: Vec<NetworkCaveat>) -> Grants {
    Grants {
        network: caveats,
        ..Grants::default()
    }
}

fn fetch(url: &str) -> ToolCall {
    ToolCall::Fetch(Request {
        url: url.into(),
        method: Method::Get,
        body: None,
    })
}

fn assert_denied(result: Result<Output, CallError>) -> String {
    match result {
        Err(CallError::Denied {
            vocabulary: Vocabulary::Network,
            action,
        }) => action,
        other => panic!("expected a network denial, got {other:?}"),
    }
}

fn hosts(list: &[&str]) -> NetworkCaveat {
    NetworkCaveat::HostIn(list.iter().map(|s| (*s).to_owned()).collect())
}

#[test]
fn allowed_host_port_and_scheme() {
    let server = Server::start(|_| (200, None));
    let (mut host, agent) = host_with(&network(vec![
        hosts(&["127.0.0.1"]),
        NetworkCaveat::PortIn(vec![server.port]),
        NetworkCaveat::SchemeIn(vec![Scheme::Http]),
    ]));
    match host.call(
        agent,
        &fetch(&format!("http://127.0.0.1:{}/ok", server.port)),
    ) {
        Ok(Output::Response(r)) => {
            assert_eq!(r.status, 200);
            assert_eq!(r.body, b"hello from /ok");
        }
        other => panic!("expected a response, got {other:?}"),
    }
    assert_eq!(server.hits(), 1);
}

#[test]
fn denied_host_port_or_scheme_never_connects() {
    let server = Server::start(|_| (200, None));
    let port = server.port;
    let (mut host, agent) = host_with(&network(vec![
        hosts(&["127.0.0.1"]),
        NetworkCaveat::PortIn(vec![port]),
        NetworkCaveat::SchemeIn(vec![Scheme::Https]),
    ]));
    // Scheme: only HTTPS is allowed, so the HTTP request is never made.
    assert_denied(host.call(agent, &fetch(&format!("http://127.0.0.1:{port}/"))));
    // Host: `localhost` resolves to the same server, but the grant names
    // `127.0.0.1`; names are checked as requested, before resolution.
    assert_denied(host.call(agent, &fetch(&format!("http://localhost:{port}/"))));
    // Port.
    assert_denied(host.call(agent, &fetch("https://127.0.0.1:1/")));
    assert_eq!(server.hits(), 0);
}

#[test]
fn host_names_are_checked_as_the_url_parser_normalizes_them() {
    let server = Server::start(|_| (200, None));
    let (mut host, agent) = host_with(&network(vec![hosts(&["example.com", "localhost"])]));
    // ASCII case is folded before the check.
    assert!(matches!(
        host.call(agent, &fetch(&format!("http://LocalHost:{}/", server.port))),
        Ok(Output::Response(_))
    ));
    assert_eq!(server.hits(), 1);
    // The trailing dot is kept, so it is another host.
    assert_denied(host.call(agent, &fetch("http://example.com.:9/")));
    assert_denied(host.call(agent, &fetch("http://example.com@127.0.0.1:9/")));
    assert_denied(host.call(agent, &fetch("http://[::1]:9/")));
    match host.call(agent, &fetch("ftp://example.com/")) {
        Err(CallError::Failed(why)) => assert!(why.contains("scheme")),
        other => panic!("expected an unsupported scheme, got {other:?}"),
    }
}

#[test]
fn a_redirect_to_a_disallowed_host_is_denied() {
    let target = Server::start(|_| (200, None));
    let target_port = target.port;
    let first =
        Server::start(move |_| (302, Some(format!("http://localhost:{target_port}/landing"))));
    let (mut host, agent) = host_with(&network(vec![hosts(&["127.0.0.1"])]));
    let action = assert_denied(host.call(
        agent,
        &fetch(&format!("http://127.0.0.1:{}/start", first.port)),
    ));
    assert!(
        action.contains("localhost") && action.contains("redirect 1"),
        "{action}"
    );
    assert_eq!(first.hits(), 1);
    assert_eq!(target.hits(), 0);
}

#[test]
fn a_redirect_to_a_disallowed_port_is_denied() {
    let target = Server::start(|_| (200, None));
    let target_port = target.port;
    let first =
        Server::start(move |_| (307, Some(format!("http://127.0.0.1:{target_port}/landing"))));
    let (mut host, agent) = host_with(&network(vec![
        hosts(&["127.0.0.1"]),
        NetworkCaveat::PortIn(vec![first.port]),
    ]));
    assert_denied(host.call(agent, &fetch(&format!("http://127.0.0.1:{}/", first.port))));
    assert_eq!(target.hits(), 0);
}

#[test]
fn an_allowed_redirect_is_followed() {
    let server = Server::start(|path| {
        if path == "/start" {
            (301, Some("/landing".into()))
        } else {
            (200, None)
        }
    });
    let (mut host, agent) = host_with(&network(vec![hosts(&["127.0.0.1"])]));
    match host.call(
        agent,
        &fetch(&format!("http://127.0.0.1:{}/start", server.port)),
    ) {
        Ok(Output::Response(r)) => {
            assert_eq!(r.status, 200);
            assert!(r.url.ends_with("/landing"));
            assert_eq!(r.body, b"hello from /landing");
        }
        other => panic!("expected a response, got {other:?}"),
    }
    assert_eq!(server.hits(), 2);
}

#[test]
fn a_redirect_loop_stops() {
    let server = Server::start(|_| (302, Some("/again".into())));
    let (mut host, agent) = host_with(&network(vec![hosts(&["127.0.0.1"])]));
    assert!(matches!(
        host.call(agent, &fetch(&format!("http://127.0.0.1:{}/", server.port))),
        Err(CallError::Failed(_))
    ));
    assert_eq!(server.hits(), 6);
}
