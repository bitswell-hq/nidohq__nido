# Email Recovery Without Plaintext: paper and slides

The paper (ACM `acmart`, `sigconf`, BibTeX with `ACM-Reference-Format`) and
the Beamer slide deck for zero-knowledge email as a recovery factor for
smart accounts.

## Build

```sh
just email-recovery-docs        # or: bash research/email-recovery/build.sh
```

The only host requirement is Docker. `build.sh` runs everything inside
`texlive/texlive:TL2025-historic`, pinned by its manifest digest (recorded in
the script), and writes:

- `build/email-recovery-paper.pdf`
- `build/email-recovery-slides.pdf`

`build/` is gitignored. The image is published for `linux/amd64` only; on
Apple silicon Docker runs it under emulation.

Each build, in order:

1. runs the checker's self-tests (`tests/check-claims/run.sh`);
2. checks the claim ledger (`check-claims.pl`);
3. generates `build/gen/claims.tex` from `claims.yaml` (`claims-to-tex.pl`);
4. generates `build/gen/attacks.tex`, the paper's attack tables, from the
   evaluation's results in `eval/results/` (`attacks-to-tex.pl`), and fails
   if any scenario's observed outcome differs from its expected one;
5. builds both documents with `latexmk -Werror` (settings in `latexmkrc`),
   then scans the logs, so an undefined reference or citation, or a missing
   bibliography entry, fails the build.

The CI workflow `.github/workflows/email-recovery-docs.yml` runs the same
`build.sh` on every pull request and every push to `main` (with no path
filter, since claim evidence lives anywhere in the repository). The check
fails if either PDF fails to build. Each run uploads the PDFs as two workflow
artifacts, `email-recovery-paper` and `email-recovery-slides`. On a push to
`main` it also publishes both PDFs to the rolling prerelease
`email-recovery-latest`, whose tag points at the commit they were built from.

## Layout

| Path | Contents |
| --- | --- |
| `paper/main.tex`, `paper/sections/` | The paper, one file per section |
| `paper/references.bib` | Bibliography, shared with the slides |
| `slides/main.tex` | The slide deck |
| `shared/macros.tex` | Notation used by both documents |
| `shared/claims.sty` | `\claim`, `\claimstatement`, `\ClaimTable`, `\ClaimList` |
| `shared/figures/` | TikZ figures used by both documents |
| `formal/` | The Lean model and proofs of the four properties (`formal/README.md`) |
| `claims.yaml` | The claim ledger |
| `check-claims.pl`, `claims-to-tex.pl` | Ledger checker and LaTeX generator |
| `attacks-to-tex.pl` | The paper's attack tables, from `eval/results/` |
| `tests/check-claims/` | Checker self-tests |
| `tools/build-in-container.sh` | The build steps `build.sh` runs in the container |

## The claim ledger

Every claim the paper or the slides make has one entry in `claims.yaml`:

```yaml
- id: replay-resistance            # [a-z][a-z0-9-]*, unique
  statement: >-                    # the claim, as both documents word it
    An accepted proof is bound to one account, ...
  status: unproven                 # proven | tested | measured | assumed | unproven
  evidence: ...                    # by status, below
```

| Status | Evidence | What the checker verifies |
| --- | --- | --- |
| `proven` | `{ lean: <theorem>, file: <.lean path> }` | the file exists and declares `theorem` or `lemma` with that name or a dotted suffix of it (its last component, or `Ns.thm` inside namespaces) |
| `tested` | `{ test: <test name>, file: <path> }` | the file exists and contains the test name as a whole word |
| `measured` | `{ file: <path> }` | the measurement file exists |
| `assumed` | `{ assumption: <text> }` | the assumption is stated |
| `unproven` | none | no evidence is given |

Paths are relative to the repository root and may not leave it. A claim
resting on several artifacts (one theorem per vocabulary, say) gives a list of
evidence mappings of its status's shape, and the checker verifies each one.

In LaTeX, `\claim{id}` prints the claim's status as a coloured tag such as
**[unproven]**, `\claims{id,id,...}` prints each distinct status of several
claims once (so a sentence resting on three tested claims carries one
**[tested]**), and `\claimstatement{id}` prints its statement, so both
documents state a claim in the ledger's words. The paper's appendix prints
every claim with its status and evidence (`\ClaimList`, a list that breaks
across pages; `\ClaimTable` gives the same as a table).

`check-claims.pl` also requires that every id in a `\claim{id}`,
`\claims{id,id,...}` or `\claimstatement{id}` in a `.tex` file under `paper/`, `slides/` or `shared/`
names a ledger entry, and that every ledger entry is used at least once
(uses inside TeX comments do not count). It prints every violation and
exits non-zero. Run it on its own with `perl check-claims.pl` (needs Perl
with `YAML::Tiny`, which the TeX Live image has).

Changing a claim's status means changing its ledger entry and pointing it at
the evidence; the tag in both documents follows on the next build.

## Current state

The four properties of the email factor are `proven` in Lean
(`formal/`, built by `just email-recovery-formal`), about a model whose
agreement with the contracts is `tested`; privacy is proven in an ideal model
of the commitment and the proofs, whose step to Poseidon2 and UltraHonk is
`assumed` with the other assumptions the properties rest on. The implementation and evaluation claims are `tested` or
`measured` against the code and the results in `eval/`; proving on a phone
is `unproven`, because no phone was measured.

Bibliography entries were checked against their primary sources: the IETF
datatracker for the RFCs, the IACR ePrint and arXiv records and Crossref for
the papers, the audit PDFs in the zkEmail repositories, and the project
repositories and documentation sites.
