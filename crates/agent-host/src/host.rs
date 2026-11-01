//! The host: holds every agent's grant and is the only path from an agent's
//! tool calls to the file system, the network and the key keeper.
//!
//! Two interfaces, kept apart:
//!
//! - The admin interface ([`Host::issue`], [`Host::revoke`]) creates root
//!   agents with a grant and revokes agents. Agents never hold it.
//! - The agent interface is [`Host::call`] with a [`ToolCall`]. An agent is
//!   named by its [`AgentId`] and has no call that reads or edits a grant.
//!   [`ToolCall::Delegate`] starts a sub-agent whose grant is the caller's
//!   caveats followed by the ones it adds, so it allows at most what the
//!   caller's does.
//!
//! Every file, fetch and signing call is checked through the evaluator
//! component before it acts, against the caller's grant; a signature over a
//! transaction or an authorization entry is also checked against the chain
//! grant, context by context. A revoked agent, or one under a revoked
//! ancestor, is denied everything.

use std::path::{Path, PathBuf};

use nido_key_keeper::KeyKeeper;

use crate::evaluator::{wit, EvalError, Evaluator};
use crate::fs::{self, FileError};
use crate::grant::{self, Grants, Lowered, Mode};
use crate::net::{self, NetError};
use crate::sign;

/// An agent, as the host names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AgentId(pub usize);

/// A tool call an agent makes.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ToolCall {
    /// Read a regular file (mode `read`).
    ReadFile { path: PathBuf },
    /// Replace or create a regular file (mode `write`).
    WriteFile { path: PathBuf, contents: String },
    /// An HTTP request; every redirect hop is checked.
    Fetch(net::Request),
    /// A signature from the key keeper.
    Sign(sign::Request),
    /// Start a sub-agent whose grant is the caller's narrowed by `add`.
    Delegate { add: Grants },
}

/// What a tool call produced.
#[derive(Debug)]
pub enum Output {
    File(Vec<u8>),
    Written,
    Response(net::Response),
    Signature(Vec<u8>),
    Agent(AgentId),
}

/// Which grant denied a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Vocabulary {
    Files,
    Network,
    Signing,
    Chain,
}

/// Why a tool call did not act.
#[derive(Debug)]
pub enum CallError {
    /// A grant denied the call. `action` describes the action denied.
    Denied {
        vocabulary: Vocabulary,
        action: String,
    },
    /// The agent, or an ancestor, is revoked.
    Revoked,
    /// No such agent.
    UnknownAgent,
    /// The call was allowed (or never reached a check) and then failed.
    Failed(String),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied { vocabulary, action } => {
                write!(f, "{vocabulary:?} grant denies {action}")
            }
            Self::Revoked => f.write_str("agent revoked"),
            Self::UnknownAgent => f.write_str("unknown agent"),
            Self::Failed(why) => f.write_str(why),
        }
    }
}

struct Agent {
    parent: Option<AgentId>,
    grant: Lowered,
    revoked: bool,
}

/// The agent host. `K` is the key keeper signatures go to.
pub struct Host<K> {
    evaluator: Evaluator,
    keeper: K,
    agents: Vec<Agent>,
    http: ureq::Agent,
    limits: Limits,
}

/// Size and redirect limits for the host's tools.
#[derive(Clone, Copy, Debug, Default)]
pub struct Limits {
    pub net: net::Limits,
    /// The most bytes `read_file` returns.
    pub max_read: Option<u64>,
}

const DEFAULT_MAX_READ: u64 = 16 << 20;

impl<K: KeyKeeper> Host<K> {
    /// A host with no agents, signing through `keeper`.
    ///
    /// # Errors
    ///
    /// If the evaluator component does not load.
    pub fn new(keeper: K) -> Result<Self, EvalError> {
        Self::with_limits(keeper, Limits::default())
    }

    /// [`Host::new`] with explicit limits.
    ///
    /// # Errors
    ///
    /// If the evaluator component does not load.
    pub fn with_limits(keeper: K, limits: Limits) -> Result<Self, EvalError> {
        Ok(Self {
            evaluator: Evaluator::new()?,
            keeper,
            agents: Vec::new(),
            http: net::client(&limits.net),
            limits,
        })
    }

    /// The key keeper, for tests that inspect what reached it.
    pub fn keeper(&self) -> &K {
        &self.keeper
    }

    /// Admin: start a root agent holding `grants`.
    ///
    /// # Errors
    ///
    /// If a `path_under` prefix does not resolve.
    pub fn issue(&mut self, grants: &Grants) -> Result<AgentId, String> {
        let grant = lower(grants)?;
        Ok(self.add(None, grant))
    }

    /// Admin: revoke `agent` and, through it, every agent it delegated to.
    pub fn revoke(&mut self, agent: AgentId) {
        if let Some(a) = self.agents.get_mut(agent.0) {
            a.revoked = true;
        }
    }

    fn add(&mut self, parent: Option<AgentId>, grant: Lowered) -> AgentId {
        self.agents.push(Agent {
            parent,
            grant,
            revoked: false,
        });
        AgentId(self.agents.len() - 1)
    }

    /// The grant of a live agent.
    fn live(&self, agent: AgentId) -> Result<&Agent, CallError> {
        let found = self.agents.get(agent.0).ok_or(CallError::UnknownAgent)?;
        let mut at = Some(agent);
        while let Some(id) = at {
            let a = &self.agents[id.0];
            if a.revoked {
                return Err(CallError::Revoked);
            }
            at = a.parent;
        }
        Ok(found)
    }

    /// Agent: make `call` as `agent`.
    ///
    /// # Errors
    ///
    /// [`CallError::Denied`] when a grant denies the call; otherwise why it
    /// did not complete.
    pub fn call(&mut self, agent: AgentId, call: &ToolCall) -> Result<Output, CallError> {
        let grant = self.live(agent)?.grant.clone();
        match call {
            ToolCall::ReadFile { path } => self.read_file(&grant, path),
            ToolCall::WriteFile { path, contents } => {
                self.write_file(&grant, path, contents.as_bytes())
            }
            ToolCall::Fetch(request) => self.fetch(&grant, request),
            ToolCall::Sign(request) => self.sign(&grant, request),
            ToolCall::Delegate { add } => {
                let narrowed = grant.narrowed_by(lower(add).map_err(CallError::Failed)?);
                Ok(Output::Agent(self.add(Some(agent), narrowed)))
            }
        }
    }

    fn read_file(&mut self, grant: &Lowered, path: &Path) -> Result<Output, CallError> {
        let mut check = FileCheck {
            evaluator: &mut self.evaluator,
            grant: &grant.files,
            mode: Mode::Read,
        };
        let limit = self.limits.max_read.unwrap_or(DEFAULT_MAX_READ);
        fs::read(path, limit, &mut check)
            .map(Output::File)
            .map_err(file_error)
    }

    fn write_file(
        &mut self,
        grant: &Lowered,
        path: &Path,
        data: &[u8],
    ) -> Result<Output, CallError> {
        let mut check = FileCheck {
            evaluator: &mut self.evaluator,
            grant: &grant.files,
            mode: Mode::Write,
        };
        fs::write(path, data, &mut check)
            .map(|()| Output::Written)
            .map_err(file_error)
    }

    fn fetch(&mut self, grant: &Lowered, request: &net::Request) -> Result<Output, CallError> {
        let mut check = NetCheck {
            evaluator: &mut self.evaluator,
            grant: &grant.network,
        };
        net::fetch(&self.http, &self.limits.net, request, &mut check)
            .map(Output::Response)
            .map_err(|e| match e {
                NetError::Denied { url, hop } => CallError::Denied {
                    vocabulary: Vocabulary::Network,
                    action: if hop == 0 {
                        url
                    } else {
                        format!("{url} (redirect {hop})")
                    },
                },
                NetError::Unsupported(why) => CallError::Failed(format!("unsupported: {why}")),
                NetError::TooManyRedirects => CallError::Failed("too many redirects".into()),
                NetError::Check(why) | NetError::Transport(why) => CallError::Failed(why),
            })
    }

    fn sign(&mut self, grant: &Lowered, request: &sign::Request) -> Result<Output, CallError> {
        // The signing action is the request's key, network and payload kind,
        // checked before the payload is decoded.
        let kind = request.payload.kind();
        let action = wit::signing::Action {
            key: request.key.as_bytes().to_vec(),
            network: request.network.as_bytes().to_vec(),
            payload: grant::lower_payload(kind),
        };
        let allowed = self
            .evaluator
            .signing(&grant.signing, &action)
            .map_err(|e| CallError::Failed(e.to_string()))?;
        if !allowed {
            return Err(CallError::Denied {
                vocabulary: Vocabulary::Signing,
                action: format!(
                    "{kind:?} signature by {} on {:?}",
                    request.key, request.network
                ),
            });
        }
        let prepared = sign::prepare(request).map_err(CallError::Failed)?;
        let chain = |evaluator: &mut Evaluator, actions: &[wit::chain::Action]| {
            evaluator
                .chain_all(&grant.chain, actions)
                .map_err(|e| CallError::Failed(e.to_string()))
        };
        if !chain(&mut self.evaluator, &prepared.chain)? {
            // The batch check denied; name the first context that fails alone.
            let mut action = format!("{:?} signature's authorization", prepared.kind);
            for (i, context) in prepared.chain.iter().enumerate() {
                if !chain(&mut self.evaluator, std::slice::from_ref(context))? {
                    action = format!(
                        "{} (context {i} of the {:?} signature's {})",
                        describe(context),
                        prepared.kind,
                        prepared.chain.len()
                    );
                    break;
                }
            }
            return Err(CallError::Denied {
                vocabulary: Vocabulary::Chain,
                action,
            });
        }
        self.keeper
            .sign(&prepared.key, &prepared.payload)
            .map(|s| Output::Signature(s.0))
            .map_err(|e| CallError::Failed(format!("keeper: {e}")))
    }
}

fn describe(action: &wit::chain::Action) -> String {
    match action {
        wit::chain::Action::Invoke(call) => format!(
            "{}.{}",
            String::from_utf8_lossy(&call.contract),
            String::from_utf8_lossy(&call.function)
        ),
        wit::chain::Action::CreateContract(_) => "a contract deployment".into(),
    }
}

fn lower(grants: &Grants) -> Result<Lowered, String> {
    grants.lower().map_err(|e| format!("grant: {e}"))
}

fn file_error(e: FileError) -> CallError {
    match e {
        FileError::Denied { path, opened } => CallError::Denied {
            vocabulary: Vocabulary::Files,
            action: if opened {
                format!("{} (as opened)", path.display())
            } else {
                path.display().to_string()
            },
        },
        FileError::Io(e) => CallError::Failed(e.to_string()),
    }
}

struct FileCheck<'a> {
    evaluator: &'a mut Evaluator,
    grant: &'a [wit::files::Caveat],
    mode: Mode,
}

impl fs::Check for FileCheck<'_> {
    fn allows(&mut self, path: &Path) -> std::io::Result<bool> {
        let action = wit::files::Action {
            path: fs::components(path),
            mode: grant::lower_mode(self.mode),
        };
        self.evaluator
            .files(self.grant, &action)
            .map_err(std::io::Error::other)
    }
}

struct NetCheck<'a> {
    evaluator: &'a mut Evaluator,
    grant: &'a [wit::network::Caveat],
}

impl net::Check for NetCheck<'_> {
    fn allows(&mut self, target: &net::Target) -> Result<bool, String> {
        let action = wit::network::Action {
            host: target.host.as_bytes().to_vec(),
            port: target.port,
            scheme: grant::lower_scheme(if target.https {
                grant::Scheme::Https
            } else {
                grant::Scheme::Http
            }),
        };
        self.evaluator
            .network(self.grant, &action)
            .map_err(|e| e.to_string())
    }
}
