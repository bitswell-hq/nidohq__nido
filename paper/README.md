# One Policy, Two Boundaries: paper and slides

The paper (ACM `acmart`, `sigconf`, BibTeX with `ACM-Reference-Format`) and the
Beamer slide deck for attenuating grants: verified capability enforcement for
AI agents at the WebAssembly host and the Soroban smart account. The system
they describe is in `formal/`, `crates/grant-eval`, `contracts/grant-signer`,
`crates/agent-host`, `crates/grant-component`, `crates/grant-relay`,
`crates/key-keeper` and `evaluation/`; each component's README is the
authoritative description.

## Build

```sh
make -C paper            # or: just paper
make -C paper REVIEW=0   # without acmart's anonymous and review options
```

The only host requirements are Docker and make. The Makefile runs the build
inside `texlive/texlive:TL2025-historic`, pinned by its manifest digest, and
writes:

- `build/paper.pdf`
- `build/slides.pdf`

`build/` is gitignored. The image is published for `linux/amd64` only; on
Apple silicon Docker runs it under emulation. `make -C paper pdfs` runs the
same steps without Docker on a host with TeX Live 2025 and Perl's
`YAML::Tiny`; after changing the bibliography, `make -C paper clean` first, so
latexmk does not stop on a stale `.bbl`.

Each build, in order (`tools/build.sh`):

1. checks the claim ledger, `claims.yaml`, against the repository and the
   documents;
2. generates `build/gen/claims.tex` from the ledger, and
   `build/gen/loc.tex`, the line counts the paper's tables print, from the
   sources they count;
3. builds the paper, then the slides, with `latexmk -Werror` (settings in
   `latexmkrc`), and scans the logs, so an undefined reference or citation, or
   a missing bibliography entry, fails the build.

The CI workflow `.github/workflows/paper.yml` runs `make -C paper` on pull
requests that touch the paper or any file the ledger points into, and on
pushes to `main`, and uploads both PDFs as the `attenuating-grants-pdfs`
artifact. On a push to `main` its `publish` job also attaches them to the
rolling prerelease `paper-latest`, moving its tag to the commit they were built
from and replacing the previous assets; that job alone has `contents: write`.

## Layout

| Path | Contents |
| --- | --- |
| `main.tex`, `sections/` | The paper, one file per section |
| `slides/main.tex` | The slide deck |
| `references.bib` | Bibliography, shared with the slides |
| `grants.sty` | Notation, listings and figure styles used by both documents |
| `figures/` | TikZ figures used by both documents |
| `claims.yaml` | The claim ledger |
| `tools/build.sh` | The build steps the Makefile runs in the container |

## The claim ledger

Every claim the paper or the slides make has one entry in `claims.yaml`, with
a status of `proven` (a Lean theorem), `tested` (a named test), `measured` (a
file recording the measurement), `assumed` (a stated assumption) or
`unproven`. `\claim{id}` prints the status as a coloured tag and
`\claimstatement{id}` the statement; the paper's appendix prints every claim
with its evidence.

The ledger format, the checker (`research/email-recovery/check-claims.pl`),
the LaTeX generator (`research/email-recovery/claims-to-tex.pl`) and the style
file (`research/email-recovery/shared/claims.sty`) are shared with the
email-recovery paper; `research/email-recovery/README.md` describes them. The
checker verifies that each `proven` claim's file declares its theorem, each
`tested` claim's file contains its test name, and each `measured` claim's file
exists, that every `\claim` names a ledger entry, and that every entry is used.

Changing a claim's status means changing its ledger entry and pointing it at
the evidence; the tags in both documents follow on the next build.

## Reproducing the cited results

One claim's evidence lives in `vendor/perch`, so a checkout needs
`git submodule update --init` before the build. The claims point at the
artifacts that produce them: the Lean package (`cd formal && lake build`), the
crates' tests (`cargo test --workspace`; `crates/agent-host` is its own Cargo
workspace, so `cargo test --manifest-path crates/agent-host/Cargo.toml` runs
its suites, and `just test` runs both), the grant signer's integration tests
(`just build-contracts`, then `cargo test -p nido-integration-tests --test it
grant_signer`), and the evaluation (`just eval`, which writes
`evaluation/results/` but the local network's files, and `just eval-network`,
which needs Docker and the Stellar CLI and writes `results/network*.json`; see
`evaluation/README.md`).

## Current state

The documents report the proofs, tests and the evaluation in
`evaluation/results/` and ran no experiments of their own. The attack suite
ran in Soroban simulation, at the agent host and, through the relay, on a
local Stellar network; the cost-bound cross-check in Soroban simulation; the
relay's throughput, a race of sibling spends and on-chain costs on the local
network. What the evaluation leaves out (public networks, real Dfns, more than
eight channels, the cost sweeps on chain) the paper lists as not measured.

Line counts in the paper's tables are non-blank lines that do not start with
`//` for Rust, and non-blank lines for Lean; `tools/build.sh` computes them.

Bibliography entries were checked against their primary sources on
2026-11-01: Crossref and the publishers' or authors' PDFs for papers, the
arXiv records for preprints, and the specification, documentation or
repository pages for standards, documentation and software. A page that states
no date carries the year it was accessed.
