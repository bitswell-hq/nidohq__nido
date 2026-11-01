# Build the paper and the slide deck from source:
#
#   make -C paper              # anonymous review version (acmart review mode)
#   make -C paper REVIEW=0     # without acmart's anonymous and review options
#
# The build runs inside one TeX Live image pinned by digest, so the PDFs do
# not depend on the host's TeX installation; the host needs Docker and make.
# Output: paper/build/paper.pdf and paper/build/slides.pdf.

# texlive/texlive:TL2025-historic, the frozen TeX Live 2025 release. The image
# is published for linux/amd64 only; on other hosts Docker emulates it.
IMAGE := texlive/texlive:TL2025-historic@sha256:7056390eac37715fd3e01875037ceb4016cb17d44c611f7bbbfa7a012007979f
REVIEW ?= 1
REPO := $(abspath $(CURDIR)/..)

.PHONY: all pdfs clean

all:
	@command -v docker >/dev/null 2>&1 || { \
	    echo "error: the build runs latexmk inside $(IMAGE); install Docker" >&2; exit 1; }
	@docker info >/dev/null 2>&1 || { \
	    echo "error: the Docker daemon is not reachable; start Docker" >&2; exit 1; }
	docker run --rm --platform linux/amd64 \
	    --user "$$(id -u):$$(id -g)" --env HOME=/tmp \
	    --volume "$(REPO):/repo" --workdir /repo/paper \
	    "$(IMAGE)" \
	    make pdfs REVIEW=$(REVIEW)

# The build proper. `all` runs it inside the image; it also runs on any host
# with TeX Live 2025 and Perl's YAML::Tiny.
pdfs:
	bash tools/build.sh $(REVIEW)

clean:
	rm -rf build
