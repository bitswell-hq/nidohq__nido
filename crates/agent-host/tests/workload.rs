//! A scripted workload replayed through the `agent-host` binary.

mod common;

use std::process::Command;

use common::{write, TempDir};

#[test]
fn the_cli_replays_a_workload() {
    let t = TempDir::new("workload");
    write(&t.path("work/notes.txt"), "notes");
    write(&t.path("secret.txt"), "s");
    let work = t.path("work");
    let workload = serde_json::json!({
        "keys": {"key-a": "01".repeat(32)},
        "steps": [
            {"admin": {"issue": {"name": "root", "grants": {
                "files": [{"path_under": work}],
                "signing": [{"key_in": ["key-a"]}, {"payload_in": ["message"]}]
            }}}},
            {"agent": {"name": "root", "call": {"read_file": {"path": work.join("notes.txt")}}}},
            {"agent": {"name": "root", "call": {"read_file": {"path": work.join("../secret.txt")}}}},
            {"agent": {"name": "root", "call": {"delegate": {"add": {"files": [{"mode_in": ["read"]}]}}}, "as": "reader"}},
            {"agent": {"name": "reader", "call": {"write_file": {"path": work.join("out.txt"), "contents": "x"}}}},
            {"agent": {"name": "root", "call": {"sign": {"key": "key-a", "network": "Test SDF Network ; September 2015", "message": "hi"}}}},
            {"agent": {"name": "root", "call": {"sign": {"key": "key-b", "network": "Test SDF Network ; September 2015", "message": "hi"}}}},
            {"admin": {"revoke": "root"}},
            {"agent": {"name": "reader", "call": {"read_file": {"path": work.join("notes.txt")}}}}
        ]
    });
    let path = t.path("workload.json");
    std::fs::write(&path, workload.to_string()).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_agent-host"))
        .arg("run")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let outcomes: Vec<String> = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            v["outcome"].as_str().unwrap().to_owned()
        })
        .collect();
    assert_eq!(
        outcomes,
        [
            "allowed", "allowed", "denied", "allowed", "denied", "allowed", "denied", "allowed",
            "denied"
        ]
    );
    assert!(!t.path("work/out.txt").exists());
}
