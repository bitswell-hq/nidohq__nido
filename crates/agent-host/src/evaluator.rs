//! The grant evaluator component, loaded into Wasmtime.
//!
//! `build.rs` compiles `crates/grant-component` (the `grant-eval` crate behind
//! the WIT interface in `crates/grant-component/wit/`) for `wasm32v1-none` and
//! wraps it as a component; the bytes are embedded here. The component
//! imports nothing, so it runs with an empty linker: it can compute a verdict
//! and nothing else.

use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

mod bindings {
    wasmtime::component::bindgen!({
        world: "evaluator",
        path: "../grant-component/wit",
    });
}

/// The component's value types, one module per vocabulary.
pub mod wit {
    pub use super::bindings::exports::nido::grant_eval::{chain, files, network, signing};
}

/// The evaluator component, as compiled by `build.rs`.
pub const COMPONENT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/grant_eval.wasm"));

/// An instance of the evaluator component.
pub struct Evaluator {
    store: Store<()>,
    instance: bindings::Evaluator,
}

/// The component trapped or could not be called. The evaluator returns a
/// verdict for every input, so this means the component itself is broken
/// (or out of memory); the host refuses the call.
#[derive(Debug)]
pub struct EvalError(pub String);

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "evaluator component failed: {}", self.0)
    }
}

impl std::error::Error for EvalError {}

fn eval_error(e: impl std::fmt::Display) -> EvalError {
    EvalError(e.to_string())
}

impl Evaluator {
    /// Compile and instantiate the embedded component.
    ///
    /// # Errors
    ///
    /// If Wasmtime rejects the component.
    pub fn new() -> Result<Self, EvalError> {
        let engine = Engine::new(&Config::new()).map_err(eval_error)?;
        let component = Component::new(&engine, COMPONENT).map_err(eval_error)?;
        let linker = Linker::new(&engine);
        let mut store = Store::new(&engine, ());
        let instance = bindings::Evaluator::instantiate(&mut store, &component, &linker)
            .map_err(eval_error)?;
        Ok(Self { store, instance })
    }

    /// `grant_eval::files::allows`, through the component.
    ///
    /// # Errors
    ///
    /// If the component traps.
    pub fn files(
        &mut self,
        grant: &[wit::files::Caveat],
        action: &wit::files::Action,
    ) -> Result<bool, EvalError> {
        self.instance
            .nido_grant_eval_files()
            .call_allows(&mut self.store, grant, action)
            .map_err(eval_error)
    }

    /// `grant_eval::network::allows`, through the component.
    ///
    /// # Errors
    ///
    /// If the component traps.
    pub fn network(
        &mut self,
        grant: &[wit::network::Caveat],
        action: &wit::network::Action,
    ) -> Result<bool, EvalError> {
        self.instance
            .nido_grant_eval_network()
            .call_allows(&mut self.store, grant, action)
            .map_err(eval_error)
    }

    /// `grant_eval::signing::allows`, through the component.
    ///
    /// # Errors
    ///
    /// If the component traps.
    pub fn signing(
        &mut self,
        grant: &[wit::signing::Caveat],
        action: &wit::signing::Action,
    ) -> Result<bool, EvalError> {
        self.instance
            .nido_grant_eval_signing()
            .call_allows(&mut self.store, grant, action)
            .map_err(eval_error)
    }

    /// `grant_eval::chain::allows_all`, through the component: every context
    /// of an authorization tree.
    ///
    /// # Errors
    ///
    /// If the component traps.
    pub fn chain_all(
        &mut self,
        grant: &[wit::chain::Caveat],
        actions: &[wit::chain::Action],
    ) -> Result<bool, EvalError> {
        self.instance
            .nido_grant_eval_chain()
            .call_allows_all(&mut self.store, grant, actions)
            .map_err(eval_error)
    }
}
