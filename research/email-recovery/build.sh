#!/usr/bin/env bash
# Build the email-recovery paper and slides from source.
#
# Everything runs inside one TeX Live image pinned by digest, so the PDFs do
# not depend on the host's TeX installation. The host needs only Docker.
# Output: research/email-recovery/build/{email-recovery-paper,email-recovery-slides}.pdf
set -euo pipefail

# texlive/texlive:TL2025-historic, the frozen TeX Live 2025 release.
# The image is published for linux/amd64 only.
IMAGE="texlive/texlive:TL2025-historic@sha256:7056390eac37715fd3e01875037ceb4016cb17d44c611f7bbbfa7a012007979f"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker not found. The document build runs latexmk inside the pinned" >&2
    echo "       TeX Live image ($IMAGE); install Docker and retry." >&2
    exit 1
fi
if ! docker info >/dev/null 2>&1; then
    echo "error: docker is installed but its daemon is not reachable; start Docker and retry." >&2
    exit 1
fi

mkdir -p "$here/build"
exec docker run --rm \
    --platform linux/amd64 \
    --user "$(id -u):$(id -g)" \
    --env HOME=/tmp \
    --volume "$repo:/repo" \
    --workdir /repo/research/email-recovery \
    "$IMAGE" \
    bash tools/build-in-container.sh
