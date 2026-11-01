#!/usr/bin/env bash
# Writes any missing TEST-ONLY signing key under keys/. The committed keys are
# the fixtures' keys: regenerating one changes every fixture signed with it.
set -euo pipefail
cd "$(dirname "$0")/../keys"

gen() {
  local name=$1 bits=$2
  local file="TEST-ONLY-${name}-rsa${bits}.pem"
  [ -e "$file" ] && return 0
  openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:${bits}" -pkeyopt rsa_keygen_pubexp:65537 -out "$file" 2>/dev/null
  echo "wrote keys/$file"
}

for name in gmail gmail-previous google-1e100 outlook icloud icloud-me yahoo proton protonmail \
            fastmail messagingengine gmx webde \
            gappssmtp onmicrosoft attacker; do
  gen "$name" 2048
done
gen weak 1024
