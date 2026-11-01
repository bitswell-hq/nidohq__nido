# grant-component

`grant-eval` as a WebAssembly component: the evaluator behind the WIT
interface in `wit/grant-eval.wit`, one interface per vocabulary (`files`,
`network`, `signing`, `chain`), each exporting `allows(grant, action)` and
`allows-all(grant, actions)`. Each export converts its arguments to
`grant-eval` values and calls that vocabulary's function; nothing else runs.
The component imports nothing and keeps no state.

It builds for `wasm32v1-none`, the target the Soroban smart account compiles
`grant-eval` for, as a `no_std` crate with `dlmalloc` as its allocator. A
Soroban `i128` crosses the boundary as `int128 { hi: s64, lo: u64 }`
(`hi * 2^64 + lo`), since WIT has no 128-bit integer.

```sh
cargo build -p grant-component --target wasm32v1-none --release
wasm-tools component new target/wasm32v1-none/release/grant_component.wasm -o grant_eval.wasm
```

`crates/agent-host` does both steps in its build script and embeds the
result; its README describes the host and what is trusted.
