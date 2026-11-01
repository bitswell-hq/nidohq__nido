//! The evaluation at the agent host (`crates/agent-host`): a research agent
//! that reads and writes files, calls an API and signs, with a sub-agent; the
//! attack suite, each attempt checked for clean failure; the per-check cost
//! through the evaluator component against native `grant-eval`; and tool-call
//! throughput.
//!
//! ```sh
//! cargo run --release --manifest-path evaluation/agent-host/Cargo.toml -- --out <dir>
//! ```
//!
//! Writes `agent-host-workload.json`, `agent-host-attacks.json`,
//! `agent-host-bench.json` and `agent-host-throughput.json` to `<dir>`. Files
//! live in a fresh directory under the system temporary directory, and the
//! network is two HTTP servers on 127.0.0.1: the API the grant allows and a
//! second one on a port it does not.

mod timing;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use agent_host::grant::{FileCaveat, Grants, Mode, NetworkCaveat, Payload, Scheme, SigningCaveat};
use agent_host::net::{Method, Request};
use agent_host::sign::{Request as SignRequest, RequestPayload};
use agent_host::{bench, workload, AgentId, CallError, Host, Output, ToolCall};
use base64::Engine as _;
use nido_key_keeper::{KeyId, MemoryKeyKeeper};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use stellar_xdr::{
    ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorizationWithAddress,
    InvokeContractArgs, Limits, ScAddress, ScSymbol, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, VecM, WriteXdr,
};

/// The local network's passphrase, which the research agent may sign for.
const STANDALONE: &str = "Standalone Network ; February 2017";
const TESTNET: &str = "Test SDF Network ; September 2015";
const KEY: &str = "research-key";
const OTHER_KEY: &str = "other-key";

// --- the environment ---------------------------------------------------------

/// A local HTTP server that counts requests. `/redirect-port` redirects to
/// `redirect_port`, `/redirect-ip` to this server by its address literal,
/// `/redirect-ok` to `/v1`.
struct Server {
    port: u16,
    hits: Arc<AtomicUsize>,
}

impl Server {
    fn start(redirect_port: u16) -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").expect("a local port");
        let port = server.server_addr().to_ip().expect("an IP address").port();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&hits);
        std::thread::spawn(move || {
            for request in server.incoming_requests() {
                counter.fetch_add(1, Ordering::SeqCst);
                let location = match request.url() {
                    "/redirect-port" => Some(format!("http://localhost:{redirect_port}/v1")),
                    "/redirect-ip" => Some(format!("http://127.0.0.1:{port}/v1")),
                    "/redirect-ok" => Some("/v1".to_owned()),
                    _ => None,
                };
                let mut response = tiny_http::Response::from_string(r#"{"ok":true}"#)
                    .with_status_code(if location.is_some() { 302 } else { 200 });
                if let Some(l) = location {
                    response = response.with_header(
                        tiny_http::Header::from_bytes("Location", l).expect("a header"),
                    );
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

/// The agents' file tree: `work/` (the grant's), `secret/`, `workshop/` (a
/// name with `work` as a string prefix) and `work/link`, a symlink to
/// `secret/`.
struct Sandbox {
    root: PathBuf,
}

impl Sandbox {
    fn create() -> std::io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("nido-eval-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(dir.join("work/data"))?;
        std::fs::create_dir_all(dir.join("work/out"))?;
        std::fs::create_dir_all(dir.join("secret"))?;
        std::fs::create_dir_all(dir.join("workshop"))?;
        std::fs::write(dir.join("work/notes.txt"), "research notes\n")?;
        std::fs::write(dir.join("work/data/input.csv"), "a,b\n1,2\n")?;
        std::fs::write(dir.join("secret/key.txt"), "not for agents\n")?;
        std::fs::write(dir.join("workshop/plan.txt"), "a sibling directory\n")?;
        std::os::unix::fs::symlink("../secret", dir.join("work/link"))?;
        Ok(Self {
            root: std::fs::canonicalize(&dir)?,
        })
    }

    /// `text` with this run's sandbox root and server ports replaced by
    /// names, so results compare across runs.
    fn redact(&self, text: &str, ports: &[(u16, &str)]) -> String {
        let mut out = text.replace(&self.root.display().to_string(), "$SANDBOX");
        for (port, name) in ports {
            out = out.replace(&format!(":{port}"), &format!(":${name}"));
        }
        out
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn at(&self, rel: &str) -> String {
        self.path(rel).display().to_string()
    }

    /// Every entry under the root: a file's SHA-256, a symlink's target.
    fn digest(&self) -> BTreeMap<String, String> {
        fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, String>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let rel = path
                    .strip_prefix(base)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                let Ok(meta) = std::fs::symlink_metadata(&path) else {
                    continue;
                };
                if meta.file_type().is_symlink() {
                    let target = std::fs::read_link(&path).unwrap_or_default();
                    out.insert(rel, format!("link:{}", target.display()));
                } else if meta.is_dir() {
                    out.insert(rel, "dir".into());
                    walk(base, &path, out);
                } else {
                    let data = std::fs::read(&path).unwrap_or_default();
                    out.insert(rel, format!("file:{}", hex::encode(Sha256::digest(&data))));
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(&self.root, &self.root, &mut out);
        out
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn keeper() -> MemoryKeyKeeper {
    let mut k = MemoryKeyKeeper::new();
    k.insert(KeyId::new(KEY), [0x11; 32]);
    k.insert(KeyId::new(OTHER_KEY), [0x22; 32]);
    k
}

/// The research agent's grant: its work directory, the API by name over
/// HTTP on one port, and messages and authorization entries on the local
/// network with its own key.
fn research_grant(sb: &Sandbox, api: &Server) -> Grants {
    Grants {
        files: vec![FileCaveat::PathUnder(sb.at("work"))],
        network: vec![
            NetworkCaveat::HostIn(vec!["localhost".into()]),
            NetworkCaveat::PortIn(vec![api.port]),
            NetworkCaveat::SchemeIn(vec![Scheme::Http]),
        ],
        signing: vec![
            SigningCaveat::KeyIn(vec![KEY.into()]),
            SigningCaveat::NetworkIn(vec![STANDALONE.into()]),
            SigningCaveat::PayloadIn(vec![Payload::Message, Payload::AuthEntry]),
        ],
    }
}

/// What the summarizer adds: read only, no host, messages only.
fn summarizer_add() -> Grants {
    Grants {
        files: vec![FileCaveat::ModeIn(vec![Mode::Read])],
        network: vec![NetworkCaveat::HostIn(vec![])],
        signing: vec![SigningCaveat::PayloadIn(vec![Payload::Message])],
    }
}

/// A delegated signer's authorization preimage (what a grant signer holder
/// signs) on `passphrase`'s network.
fn delegated_preimage(passphrase: &str) -> String {
    let xdr = HashIdPreimage::SorobanAuthorizationWithAddress(
        HashIdPreimageSorobanAuthorizationWithAddress {
            network_id: Hash(Sha256::digest(passphrase.as_bytes()).into()),
            address: ScAddress::Contract(ContractId(Hash([9; 32]))),
            nonce: 7,
            signature_expiration_ledger: 1_000,
            invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([1; 32]))),
                    function_name: ScSymbol("transfer".try_into().expect("a symbol")),
                    args: VecM::default(),
                }),
                sub_invocations: VecM::default(),
            },
        },
    )
    .to_xdr(Limits::none())
    .expect("XDR");
    base64::engine::general_purpose::STANDARD.encode(xdr)
}

fn fetch(url: &str) -> ToolCall {
    ToolCall::Fetch(Request {
        url: url.into(),
        method: Method::Get,
        body: None,
    })
}

fn sign(key: &str, network: &str, payload: RequestPayload) -> ToolCall {
    ToolCall::Sign(SignRequest {
        key: key.into(),
        network: network.into(),
        payload,
    })
}

fn read(path: String) -> ToolCall {
    ToolCall::ReadFile { path: path.into() }
}

fn write(path: String) -> ToolCall {
    ToolCall::WriteFile {
        path: path.into(),
        contents: "x".into(),
    }
}

// --- the workload --------------------------------------------------------------

#[derive(Serialize)]
struct WorkloadRow {
    step: usize,
    expected: &'static str,
    outcome: &'static str,
    as_expected: bool,
    detail: String,
    micros: u128,
}

fn run_workload(sb: &Sandbox, api: &Server) -> Result<Vec<WorkloadRow>, String> {
    let at = |rel: &str| sb.at(rel);
    let grants = serde_json::to_value(json!({
        "files": [{"path_under": at("work")}],
        "network": [{"host_in": ["localhost"]}, {"port_in": [api.port]}, {"scheme_in": ["http"]}],
        "signing": [{"key_in": [KEY]}, {"network_in": [STANDALONE]}, {"payload_in": ["message", "auth_entry"]}],
    }))
    .map_err(|e| e.to_string())?;
    let base = format!("http://localhost:{}", api.port);
    let steps = json!([
        {"admin": {"issue": {"name": "research", "grants": grants}}},
        {"agent": {"name": "research", "call": {"read_file": {"path": at("work/notes.txt")}}}},
        {"agent": {"name": "research", "call": {"fetch": {"url": format!("{base}/v1")}}}},
        {"agent": {"name": "research", "call": {"fetch": {"url": format!("{base}/redirect-ok")}}}},
        {"agent": {"name": "research", "call": {"write_file": {"path": at("work/out/report.md"), "contents": "findings"}}}},
        {"agent": {"name": "research", "call": {"sign": {"key": KEY, "network": STANDALONE, "message": "report sha256 0f3c"}}}},
        {"agent": {"name": "research", "call": {"sign": {"key": KEY, "network": STANDALONE, "auth_entry": delegated_preimage(STANDALONE)}}}},
        {"agent": {"name": "research", "call": {"delegate": {"add": {
            "files": [{"mode_in": ["read"]}],
            "network": [{"host_in": []}],
            "signing": [{"payload_in": ["message"]}]
        }}}, "as": "summarizer"}},
        {"agent": {"name": "summarizer", "call": {"read_file": {"path": at("work/data/input.csv")}}}},
        {"agent": {"name": "summarizer", "call": {"write_file": {"path": at("work/out/summary.md"), "contents": "s"}}}},
        {"agent": {"name": "summarizer", "call": {"fetch": {"url": format!("{base}/v1")}}}},
        {"agent": {"name": "summarizer", "call": {"sign": {"key": KEY, "network": STANDALONE, "message": "summary"}}}},
        {"agent": {"name": "summarizer", "call": {"sign": {"key": KEY, "network": STANDALONE, "auth_entry": delegated_preimage(STANDALONE)}}}},
        {"admin": {"revoke": "research"}},
        {"agent": {"name": "summarizer", "call": {"read_file": {"path": at("work/data/input.csv")}}}},
    ]);
    let expected = [
        "allowed", "allowed", "allowed", "allowed", "allowed", "allowed", "allowed", "allowed",
        "allowed", "denied", "denied", "allowed", "denied", "allowed", "denied",
    ];
    let w: workload::Workload = serde_json::from_value(json!({
        "keys": {KEY: hex::encode([0x11; 32])},
        "steps": steps,
    }))
    .map_err(|e| format!("workload: {e}"))?;
    let keeper = workload::keeper(&w)?;
    let mut host = Host::new(keeper).map_err(|e| e.to_string())?;
    Ok(workload::run(&mut host, &w)
        .into_iter()
        .zip(expected)
        .map(|(r, want)| WorkloadRow {
            step: r.step,
            expected: want,
            outcome: r.outcome,
            as_expected: r.outcome == want,
            detail: sb.redact(&r.detail, &[(api.port, "API_PORT")]),
            micros: r.micros,
        })
        .collect())
}

// --- the attack suite ----------------------------------------------------------

#[derive(Serialize)]
struct AttackRow {
    id: &'static str,
    category: &'static str,
    attempt: String,
    boundary: &'static str,
    control: bool,
    outcome: &'static str,
    component: &'static str,
    error: String,
    state_unchanged: bool,
    changes: Vec<String>,
}

/// What an attempt must leave unchanged: the file tree, the requests the
/// disallowed server received, the keeper's signatures, and every agent's
/// verdicts on reading two probe files.
#[derive(PartialEq)]
struct State {
    files: BTreeMap<String, String>,
    other_hits: usize,
    signatures: usize,
    probes: Vec<bool>,
}

struct Attacks<'a> {
    sb: &'a Sandbox,
    other: &'a Server,
    ports: [(u16, &'static str); 2],
    host: Host<MemoryKeyKeeper>,
    agents: Vec<AgentId>,
    rows: Vec<AttackRow>,
}

impl Attacks<'_> {
    fn state(&mut self) -> State {
        let mut probes = Vec::new();
        for agent in self.agents.clone() {
            for rel in ["work/notes.txt", "secret/key.txt"] {
                probes.push(self.host.call(agent, &read(self.sb.at(rel))).is_ok());
            }
        }
        State {
            files: self.sb.digest(),
            other_hits: self.other.hits(),
            signatures: self.host.keeper().requests().len(),
            probes,
        }
    }

    fn attempt(
        &mut self,
        id: &'static str,
        category: &'static str,
        attempt: &str,
        control: bool,
        run: impl FnOnce(&mut Host<MemoryKeyKeeper>) -> Result<Output, CallError>,
    ) {
        let before = self.state();
        let result = run(&mut self.host);
        let after = self.state();
        let mut changes = Vec::new();
        if before.files != after.files {
            changes.push("files".to_owned());
        }
        if before.other_hits != after.other_hits {
            changes.push(format!(
                "disallowed server requests {} -> {}",
                before.other_hits, after.other_hits
            ));
        }
        if before.signatures != after.signatures {
            changes.push(format!(
                "keeper signatures {} -> {}",
                before.signatures, after.signatures
            ));
        }
        if before.probes != after.probes {
            changes.push("agents' probe verdicts".to_owned());
        }
        let (outcome, error) = match &result {
            Ok(_) => ("allowed", String::new()),
            Err(e @ (CallError::Denied { .. } | CallError::Revoked)) => ("refused", e.to_string()),
            Err(e) => ("refused", format!("failed: {e}")),
        };
        self.rows.push(AttackRow {
            id,
            category,
            attempt: attempt.to_owned(),
            boundary: "agent-host",
            control,
            outcome,
            component: if result.is_ok() { "" } else { "agent-host" },
            error: self.sb.redact(&error, &self.ports),
            state_unchanged: changes.is_empty(),
            changes,
        });
    }

    /// An agent message the tool interface must not accept.
    fn parse(&mut self, id: &'static str, attempt: &str, message: &Value) {
        let before = self.state();
        let parsed = serde_json::from_value::<ToolCall>(message.clone());
        let after = self.state();
        self.rows.push(AttackRow {
            id,
            category: "self-escalation",
            attempt: attempt.to_owned(),
            boundary: "agent-host",
            control: false,
            outcome: if parsed.is_ok() { "allowed" } else { "refused" },
            component: "agent-host tool interface",
            error: parsed.err().map(|e| e.to_string()).unwrap_or_default(),
            state_unchanged: before == after,
            changes: Vec::new(),
        });
    }
}

#[allow(clippy::too_many_lines)]
fn run_attacks(sb: &Sandbox, api: &Server, other: &Server) -> Result<Vec<AttackRow>, String> {
    let mut host = Host::new(keeper()).map_err(|e| e.to_string())?;
    let research = host.issue(&research_grant(sb, api))?;
    let reader = match host
        .call(
            research,
            &ToolCall::Delegate {
                add: summarizer_add(),
            },
        )
        .map_err(|e| e.to_string())?
    {
        Output::Agent(id) => id,
        other => return Err(format!("delegation gave {other:?}")),
    };
    let doomed = host.issue(&research_grant(sb, api))?;
    let doomed_child = match host
        .call(
            doomed,
            &ToolCall::Delegate {
                add: Grants::default(),
            },
        )
        .map_err(|e| e.to_string())?
    {
        Output::Agent(id) => id,
        other => return Err(format!("delegation gave {other:?}")),
    };
    host.revoke(doomed);
    let mut a = Attacks {
        sb,
        other,
        ports: [(api.port, "API_PORT"), (other.port, "OTHER_PORT")],
        agents: vec![research, reader, doomed, doomed_child],
        host,
        rows: Vec::new(),
    };
    let at = |rel: &str| sb.at(rel);
    let api_url = |path: &str| format!("http://localhost:{}{path}", api.port);

    // --- self-escalation
    let se = "self-escalation";
    a.parse(
        "ah-se-tool-call-issue",
        "an agent sends a tool call that issues a grant",
        &json!({"issue": {"grants": {}}}),
    );
    a.parse(
        "ah-se-tool-call-revoke",
        "an agent sends a tool call that revokes another agent",
        &json!({"revoke": 0}),
    );
    a.parse(
        "ah-se-tool-call-edit-grant",
        "an agent sends a tool call that replaces its own grant",
        &json!({"set_grant": {"files": []}}),
    );
    let widened = Grants {
        files: vec![
            FileCaveat::PathUnder("/".into()),
            FileCaveat::ModeIn(vec![Mode::Read, Mode::Write]),
        ],
        network: vec![NetworkCaveat::HostIn(vec![
            "localhost".into(),
            "127.0.0.1".into(),
        ])],
        signing: vec![SigningCaveat::PayloadIn(vec![
            Payload::Transaction,
            Payload::AuthEntry,
            Payload::Message,
        ])],
    };
    let wide_child = match a
        .host
        .call(reader, &ToolCall::Delegate { add: widened })
        .map_err(|e| e.to_string())?
    {
        Output::Agent(id) => id,
        other => return Err(format!("delegation gave {other:?}")),
    };
    a.agents.push(wide_child);
    a.attempt(
        "ah-se-sub-agent-wider-files",
        se,
        "a sub-agent of the read-only summarizer, delegated a grant naming `/` with read and write, reads a file outside the work directory",
        false,
        |h| h.call(wide_child, &read(at("secret/key.txt"))),
    );
    a.attempt(
        "ah-se-sub-agent-wider-mode",
        se,
        "the same sub-agent writes inside the work directory",
        false,
        |h| h.call(wide_child, &write(at("work/out/wide.txt"))),
    );
    a.attempt(
        "ah-se-sub-agent-wider-network",
        se,
        "the same sub-agent, delegated `localhost` after its parent was given no host, fetches the API",
        false,
        |h| h.call(wide_child, &fetch(&api_url("/v1"))),
    );
    a.attempt(
        "ah-se-sub-agent-wider-signing",
        se,
        "the same sub-agent, delegated every payload kind, signs an authorization entry",
        false,
        |h| {
            h.call(
                wide_child,
                &sign(
                    KEY,
                    STANDALONE,
                    RequestPayload::AuthEntry(delegated_preimage(STANDALONE)),
                ),
            )
        },
    );
    a.attempt(
        "ah-se-revoked-agent",
        se,
        "a revoked agent reads its own work file",
        false,
        |h| h.call(doomed, &read(at("work/notes.txt"))),
    );
    a.attempt(
        "ah-se-revoked-agent-delegates",
        se,
        "a revoked agent starts a sub-agent",
        false,
        |h| {
            h.call(
                doomed,
                &ToolCall::Delegate {
                    add: Grants::default(),
                },
            )
        },
    );
    a.attempt(
        "ah-se-sub-agent-of-revoked",
        se,
        "a sub-agent of a revoked agent reads a work file",
        false,
        |h| h.call(doomed_child, &read(at("work/notes.txt"))),
    );

    // --- delegation workarounds: arguments that name one thing and reach another
    let dw = "delegation workarounds";
    let files: [(&'static str, &str, String, bool); 7] = [
        (
            "ah-dw-path-dotdot",
            "read `work/../secret/key.txt`",
            at("work/../secret/key.txt"),
            false,
        ),
        (
            "ah-dw-path-symlink",
            "read through `work/link`, a symlink to `secret/`",
            at("work/link/key.txt"),
            false,
        ),
        (
            "ah-dw-path-symlink-dotdot",
            "read `work/link/../secret/key.txt` (`..` after a symlink)",
            at("work/link/../secret/key.txt"),
            false,
        ),
        (
            "ah-dw-path-string-prefix",
            "read `workshop/plan.txt`, whose path has the grant's as a string prefix",
            at("workshop/plan.txt"),
            false,
        ),
        (
            "ah-dw-path-case",
            "read `Secret/key.txt`, another case of a path outside the grant",
            at("Secret/key.txt"),
            false,
        ),
        (
            "ah-dw-path-relative",
            "read a relative path",
            "secret/key.txt".to_owned(),
            false,
        ),
        (
            "ah-dw-path-control",
            "control: read a work file",
            at("work/notes.txt"),
            true,
        ),
    ];
    for (id, what, path, control) in files {
        a.attempt(id, dw, what, control, |h| h.call(research, &read(path)));
    }
    a.attempt(
        "ah-dw-write-through-symlink",
        dw,
        "create a file through `work/link`",
        false,
        |h| h.call(research, &write(at("work/link/planted.txt"))),
    );
    a.attempt(
        "ah-dw-write-read-only",
        dw,
        "the read-only summarizer overwrites a work file",
        false,
        |h| h.call(reader, &write(at("work/notes.txt"))),
    );
    let urls: [(&'static str, &str, String, bool); 9] = [
        (
            "ah-dw-url-port",
            "fetch the allowed name on a port the grant leaves out",
            format!("http://localhost:{}/v1", other.port),
            false,
        ),
        (
            "ah-dw-url-scheme",
            "fetch the API over HTTPS, a scheme the grant leaves out",
            format!("https://localhost:{}/v1", api.port),
            false,
        ),
        (
            "ah-dw-url-address-literal",
            "fetch the API by the address its name resolves to",
            format!("http://127.0.0.1:{}/v1", api.port),
            false,
        ),
        (
            "ah-dw-url-decimal-address",
            "fetch the API by a decimal IPv4 literal",
            format!("http://2130706433:{}/v1", api.port),
            false,
        ),
        (
            "ah-dw-url-trailing-dot",
            "fetch the allowed name with a trailing dot",
            format!("http://localhost.:{}/v1", api.port),
            false,
        ),
        (
            "ah-dw-url-userinfo",
            "fetch a URL whose userinfo is the allowed name",
            format!("http://localhost:{}@127.0.0.1:{}/v1", api.port, other.port),
            false,
        ),
        (
            "ah-dw-url-redirect-port",
            "an allowed request whose redirect goes to a port the grant leaves out",
            api_url("/redirect-port"),
            false,
        ),
        (
            "ah-dw-url-redirect-address",
            "an allowed request whose redirect goes to the API's address literal",
            api_url("/redirect-ip"),
            false,
        ),
        (
            "ah-dw-url-control",
            "control: an allowed request with an allowed redirect",
            api_url("/redirect-ok"),
            true,
        ),
    ];
    for (id, what, url, control) in urls {
        a.attempt(id, dw, what, control, |h| h.call(research, &fetch(&url)));
    }
    let signs: [(&'static str, &str, ToolCall, AgentId, bool); 6] = [
        (
            "ah-dw-sign-other-key",
            "sign with a key the keeper holds and the grant does not name",
            sign(OTHER_KEY, STANDALONE, RequestPayload::Message("m".into())),
            research,
            false,
        ),
        (
            "ah-dw-sign-other-network",
            "sign an authorization entry for testnet",
            sign(
                KEY,
                TESTNET,
                RequestPayload::AuthEntry(delegated_preimage(TESTNET)),
            ),
            research,
            false,
        ),
        (
            "ah-dw-sign-preimage-network",
            "name the allowed network for an authorization entry built for testnet",
            sign(
                KEY,
                STANDALONE,
                RequestPayload::AuthEntry(delegated_preimage(TESTNET)),
            ),
            research,
            false,
        ),
        (
            "ah-dw-sign-testnet-transaction",
            "sign a testnet transaction (a network and a payload kind the grant leaves out)",
            sign(KEY, TESTNET, RequestPayload::Transaction(String::new())),
            research,
            false,
        ),
        (
            "ah-dw-sign-summarizer-auth-entry",
            "the summarizer signs an authorization entry",
            sign(
                KEY,
                STANDALONE,
                RequestPayload::AuthEntry(delegated_preimage(STANDALONE)),
            ),
            reader,
            false,
        ),
        (
            "ah-dw-sign-control",
            "control: sign an authorization entry for the local network",
            sign(
                KEY,
                STANDALONE,
                RequestPayload::AuthEntry(delegated_preimage(STANDALONE)),
            ),
            research,
            true,
        ),
    ];
    for (id, what, call, agent, control) in signs {
        a.attempt(id, dw, what, control, |h| h.call(agent, &call));
    }
    Ok(a.rows)
}

// --- cost and throughput -------------------------------------------------------

#[derive(Serialize)]
struct Throughput {
    case: &'static str,
    calls_per_batch: u32,
    micros_per_call: bench::Stats,
}

fn throughput(sb: &Sandbox, api: &Server) -> Result<Vec<Throughput>, String> {
    let mut host = Host::new(keeper()).map_err(|e| e.to_string())?;
    let agent = host.issue(&research_grant(sb, api))?;
    let other_port = format!("http://localhost:{}/v1", api.port.wrapping_add(1));
    let cases: [(&'static str, ToolCall, bool); 6] = [
        ("denied fetch (check only)", fetch(&other_port), false),
        (
            "denied read outside the grant (resolve and check)",
            read(sb.at("secret/key.txt")),
            false,
        ),
        (
            "allowed read of a 15-byte file",
            read(sb.at("work/notes.txt")),
            true,
        ),
        (
            "allowed message signature",
            sign(KEY, STANDALONE, RequestPayload::Message("m".into())),
            true,
        ),
        (
            "allowed authorization-entry signature",
            sign(
                KEY,
                STANDALONE,
                RequestPayload::AuthEntry(delegated_preimage(STANDALONE)),
            ),
            true,
        ),
        (
            "allowed fetch from the local API",
            fetch(&format!("http://localhost:{}/v1", api.port)),
            true,
        ),
    ];
    let mut out = Vec::new();
    for (case, call, allowed) in cases {
        let (micros_per_call, calls_per_batch) = bench::calls(|| {
            let r = host.call(agent, &call);
            if r.is_ok() == allowed {
                Ok(true)
            } else {
                Err(agent_host::evaluator::EvalError(format!("{case}: {r:?}")))
            }
        })
        .map_err(|e| e.to_string())?;
        out.push(Throughput {
            case,
            calls_per_batch,
            micros_per_call,
        });
    }
    Ok(out)
}

fn write_json(dir: &Path, name: &str, value: &impl Serialize) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut text = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    text.push('\n');
    std::fs::write(dir.join(name), text).map_err(|e| format!("{name}: {e}"))
}

fn run(args: &[String]) -> Result<(), String> {
    let flag = |name: &str| {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let out = PathBuf::from(flag("--out").ok_or("--out <dir> is required")?);
    let sb = Sandbox::create().map_err(|e| format!("sandbox: {e}"))?;
    let other = Server::start(0);
    let api = Server::start(other.port);

    let workload = run_workload(&sb, &api)?;
    eprintln!("agent-host: workload of {} steps", workload.len());
    write_json(&out, "agent-host-workload.json", &workload)?;

    let attacks = run_attacks(&sb, &api, &other)?;
    eprintln!("agent-host: {} attack rows", attacks.len());
    write_json(&out, "agent-host-attacks.json", &attacks)?;

    // Timing: one recorded run, its method in `timing`, with the machine's
    // state before and after.
    let before = timing::machine();
    let scheduling = timing::prefer_fast_cores();
    let report = bench::run().map_err(|e| e.to_string())?;
    let calls = throughput(&sb, &api)?;
    let after = timing::machine();
    write_json(
        &out,
        "agent-host-bench.json",
        &json!({
            "method": {
                "warm_up_ms": report.warm_up_ms,
                "min_batch_ms": report.min_batch_ms,
                "check_rounds": report.check_rounds,
                "instantiations": report.instantiations,
                "call_rounds": bench::CALL_ROUNDS,
                "interval": "distribution-free 95% confidence interval of the median",
            },
            "build": timing::build(),
            "scheduling": scheduling,
            "machine_before": before,
            "machine_after": after,
            "instantiate_ms": report.instantiate_ms,
            "checks": report.checks,
        }),
    )?;
    write_json(&out, "agent-host-throughput.json", &calls)?;
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("nido-eval-agent-host: {e}");
            ExitCode::FAILURE
        }
    }
}
