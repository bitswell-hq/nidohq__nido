//! Delegation: a sub-agent's grant is its parent's caveats plus the ones the
//! parent adds, so it narrows and cannot widen. Revoking an agent revokes
//! everything under it. Agents have no call that reads or edits a grant.

mod common;

use agent_host::grant::{FileCaveat, Grants, Mode, NetworkCaveat};
use agent_host::{CallError, Output, ToolCall};
use common::{files, host_with, modes, under, write, TempDir};

fn delegate(add: Grants) -> ToolCall {
    ToolCall::Delegate { add }
}

fn child(result: Result<Output, CallError>) -> agent_host::AgentId {
    match result {
        Ok(Output::Agent(id)) => id,
        other => panic!("expected a new agent, got {other:?}"),
    }
}

fn read(path: &std::path::Path) -> ToolCall {
    ToolCall::ReadFile {
        path: path.to_path_buf(),
    }
}

fn write_call(path: &std::path::Path) -> ToolCall {
    ToolCall::WriteFile {
        path: path.to_path_buf(),
        contents: "x".into(),
    }
}

#[test]
fn delegation_narrows() {
    let t = TempDir::new("narrows");
    write(&t.path("work/a/x"), "ax");
    write(&t.path("work/b/x"), "bx");
    let (mut host, root) = host_with(&files(vec![under(&t.path("work"))]));
    let reader = child(host.call(
        root,
        &delegate(files(vec![under(&t.path("work/a")), modes(&[Mode::Read])])),
    ));
    assert!(host.call(reader, &read(&t.path("work/a/x"))).is_ok());
    assert!(host.call(reader, &read(&t.path("work/b/x"))).is_err());
    assert!(host.call(reader, &write_call(&t.path("work/a/y"))).is_err());
    // The parent keeps its own grant.
    assert!(host.call(root, &write_call(&t.path("work/b/y"))).is_ok());
}

#[test]
fn delegation_cannot_widen() {
    let t = TempDir::new("widen");
    write(&t.path("work/a/x"), "ax");
    write(&t.path("work/b/x"), "bx");
    write(&t.path("outside/x"), "o");
    let (mut host, root) = host_with(&Grants {
        files: vec![under(&t.path("work/a")), modes(&[Mode::Read])],
        network: vec![NetworkCaveat::HostIn(vec!["127.0.0.1".into()])],
        ..Grants::default()
    });
    // The child asks for everything: `/`, every mode, and any host. Its grant
    // still carries the parent's caveats, so nothing new is allowed.
    let greedy = child(host.call(
        root,
        &delegate(Grants {
            files: vec![
                FileCaveat::PathUnder("/".into()),
                modes(&[Mode::Read, Mode::Write, Mode::Execute]),
            ],
            network: vec![NetworkCaveat::HostIn(vec![
                "127.0.0.1".into(),
                "example.com".into(),
            ])],
            ..Grants::default()
        }),
    ));
    let grandchild = child(host.call(greedy, &delegate(Grants::default())));
    for agent in [greedy, grandchild] {
        assert!(host.call(agent, &read(&t.path("work/a/x"))).is_ok());
        for denied in [
            read(&t.path("work/b/x")),
            read(&t.path("outside/x")),
            write_call(&t.path("work/a/y")),
            ToolCall::Fetch(agent_host::net::Request {
                url: "http://example.com:9/".into(),
                method: agent_host::net::Method::Get,
                body: None,
            }),
        ] {
            assert!(
                matches!(host.call(agent, &denied), Err(CallError::Denied { .. })),
                "{denied:?}"
            );
        }
    }
}

/// A sub-agent inherits the parent's `path_under` prefixes as they were
/// resolved when the parent's grant was issued. If the granted directory is
/// later replaced by a symlink, delegating does not re-resolve the parent's
/// prefix to the symlink's target.
#[test]
fn delegation_keeps_the_parents_resolved_paths() {
    let t = TempDir::new("resolved");
    write(&t.path("work/x"), "work");
    write(&t.path("outside/x"), "outside");
    let (mut host, root) = host_with(&files(vec![under(&t.path("work"))]));
    std::fs::rename(t.path("work"), t.path("work.old")).unwrap();
    std::os::unix::fs::symlink(t.path("outside"), t.path("work")).unwrap();
    let kid = child(host.call(root, &delegate(Grants::default())));
    for agent in [root, kid] {
        assert!(
            matches!(
                host.call(agent, &read(&t.path("work/x"))),
                Err(CallError::Denied { .. })
            ),
            "the path now leads outside the grant"
        );
        assert!(matches!(
            host.call(agent, &read(&t.path("outside/x"))),
            Err(CallError::Denied { .. })
        ));
    }
}

/// For every pair of caveat lists from a small universe, a child allows only
/// what its parent allows, on every action in a set of paths and modes.
#[test]
fn every_child_allows_a_subset_of_its_parent() {
    let t = TempDir::new("subset");
    let paths = ["work/a/x", "work/b/x", "work/ab/x", "outside/x"];
    for p in paths {
        write(&t.path(p), "x");
    }
    let universe = [
        under(&t.path("work")),
        under(&t.path("work/a")),
        under(&t.path("outside")),
        modes(&[Mode::Read]),
        modes(&[Mode::Write]),
    ];
    let mut lists: Vec<Vec<FileCaveat>> = vec![vec![]];
    lists.extend(universe.iter().map(|c| vec![c.clone()]));
    for x in &universe {
        for y in &universe {
            lists.push(vec![x.clone(), y.clone()]);
        }
    }
    let (mut host, _) = host_with(&Grants::default());
    for parent_caveats in &lists {
        let parent = host.issue(&files(parent_caveats.clone())).unwrap();
        for added in &lists {
            let kid = child(host.call(parent, &delegate(files(added.clone()))));
            for p in paths {
                for call in [read(&t.path(p)), write_call(&t.path(p))] {
                    let parent_ok =
                        !matches!(host.call(parent, &call), Err(CallError::Denied { .. }));
                    let child_ok = !matches!(host.call(kid, &call), Err(CallError::Denied { .. }));
                    assert!(
                        !child_ok || parent_ok,
                        "{parent_caveats:?} + {added:?} widened {call:?}"
                    );
                }
            }
        }
    }
}

#[test]
fn revoking_an_agent_revokes_its_sub_agents() {
    let t = TempDir::new("revoke");
    write(&t.path("work/x"), "x");
    let (mut host, root) = host_with(&files(vec![under(&t.path("work"))]));
    let kid = child(host.call(root, &delegate(Grants::default())));
    let grandkid = child(host.call(kid, &delegate(Grants::default())));
    host.revoke(kid);
    assert!(host.call(root, &read(&t.path("work/x"))).is_ok());
    for agent in [kid, grandkid] {
        assert!(matches!(
            host.call(agent, &read(&t.path("work/x"))),
            Err(CallError::Revoked)
        ));
        assert!(matches!(
            host.call(agent, &delegate(Grants::default())),
            Err(CallError::Revoked)
        ));
    }
}

/// The agent interface is the `ToolCall` enum; a call that would read, set
/// or widen a grant does not parse.
#[test]
fn there_is_no_tool_call_for_grants() {
    for call in [
        r#"{"set_grant": {"files": []}}"#,
        r#"{"read_grant": null}"#,
        r#"{"issue": {"grants": {}}}"#,
        r#"{"revoke": 0}"#,
        r#"{"delegate": {"add": {}, "replace": true}}"#,
    ] {
        assert!(
            serde_json::from_str::<ToolCall>(call).is_err(),
            "{call} parsed"
        );
    }
    assert!(serde_json::from_str::<ToolCall>(r#"{"delegate": {"add": {}}}"#).is_ok());
}
