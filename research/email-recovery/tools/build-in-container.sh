#!/usr/bin/env bash
# The document build proper. build.sh runs this inside the pinned TeX Live
# image with the repository mounted at /repo; it can also run on any host that
# has TeX Live 2025 and Perl with YAML::Tiny.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
here="$PWD"
build="$here/build"

echo "==> checker self-tests"
bash tests/check-claims/run.sh

echo "==> claim ledger"
perl check-claims.pl
mkdir -p "$build/gen"
perl claims-to-tex.pl claims.yaml >"$build/gen/claims.tex.tmp"
mv "$build/gen/claims.tex.tmp" "$build/gen/claims.tex"

echo "==> attack tables"
perl attacks-to-tex.pl >"$build/gen/attacks.tex.tmp"
mv "$build/gen/attacks.tex.tmp" "$build/gen/attacks.tex"

echo "==> run-dependent figures"
perl figures-to-tex.pl >"$build/gen/figures.tex.tmp"
mv "$build/gen/figures.tex.tmp" "$build/gen/figures.tex"

# Both documents find the shared macros and figures, the generated ledger,
# and the paper's references.bib.
export TEXINPUTS=".:$here/shared//:$build/gen//:"
export BIBINPUTS=".:$here/paper:"

# latexmk -Werror fails on undefined references and citations; the log scan
# below repeats the check so a latexmk change cannot silently weaken it.
compile() {
    local doc="$1" out="$build/$1"
    (cd "$here/$doc" && latexmk -r "$here/latexmkrc" -Werror -outdir="$out" main.tex)
    if grep -nE "(Reference|Citation) .* undefined|There were undefined (references|citations)|I didn't find a database entry" \
        "$out/main.log" "$out"/main.blg 2>/dev/null; then
        echo "error: $doc has undefined references or citations (see above)" >&2
        exit 1
    fi
    cp "$out/main.pdf" "$build/email-recovery-$2.pdf"
}

echo "==> paper"
compile paper paper
echo "==> slides"
compile slides slides

echo "built: $build/email-recovery-paper.pdf $build/email-recovery-slides.pdf"
