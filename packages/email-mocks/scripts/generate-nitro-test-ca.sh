#!/usr/bin/env bash
# Writes the TEST-ONLY certificate chains the Nitro Enclaves mock signs
# attestation documents with (keys/nitro/). Same shape as AWS's attestation
# PKI (P-384 ECDSA, SHA-384, root -> intermediates -> per-enclave
# certificate, critical basic constraints and key usage), under a test-only
# name. Nothing here is, or chains to, an AWS certificate. Regenerating
# changes every attestation fixture; existing files are kept.
set -euo pipefail
cd "$(dirname "$0")/../keys/nitro"
[ -e TEST-ONLY-nitro-root.pem ] && { echo "keys/nitro already populated"; exit 0; }

ext() { # name, extension lines
  printf '%s\n' "${@:2}" > "$1.ext"
}
key() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "TEST-ONLY-$1.key.pem" 2>/dev/null; }

ext ca3 "basicConstraints=critical,CA:TRUE,pathlen:3" "keyUsage=critical,keyCertSign,cRLSign" "subjectKeyIdentifier=hash"
ext ca1 "basicConstraints=critical,CA:TRUE,pathlen:1" "keyUsage=critical,keyCertSign,cRLSign" "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid"
ext ca0 "basicConstraints=critical,CA:TRUE,pathlen:0" "keyUsage=critical,keyCertSign,cRLSign" "subjectKeyIdentifier=hash" "authorityKeyIdentifier=keyid"
ext leaf "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature" "authorityKeyIdentifier=keyid"
ext leaf-nosig "basicConstraints=critical,CA:FALSE" "keyUsage=critical,keyEncipherment" "authorityKeyIdentifier=keyid"

root() { # name, subject
  key "$1"
  openssl req -new -x509 -sha384 -key "TEST-ONLY-$1.key.pem" -subj "$2" -days 36500 \
    -extensions v3 -config <(printf '[req]\ndistinguished_name=dn\n[dn]\n[v3]\n'; cat ca3.ext) \
    -out "TEST-ONLY-$1.pem"
}
issue() { # name, issuer, subject, ext, [not_before not_after]
  key "$1"
  openssl req -new -key "TEST-ONLY-$1.key.pem" -subj "$3" -out "$1.csr"
  local validity=(-days 36500)
  [ $# -ge 6 ] && validity=(-not_before "$5" -not_after "$6")
  openssl x509 -req -sha384 -in "$1.csr" -CA "TEST-ONLY-$2.pem" -CAkey "TEST-ONLY-$2.key.pem" \
    -set_serial "0x$(openssl rand -hex 16)" "${validity[@]}" -extfile "$4.ext" -out "TEST-ONLY-$1.pem"
  rm "$1.csr"
}

O="/C=US/O=TEST-ONLY/OU=nido-email-mocks"
root  nitro-root            "/CN=test-only.nitro-enclaves$O"
issue nitro-zonal           nitro-root     "/CN=zonal.test-only.nitro-enclaves$O"   ca1
issue nitro-instance        nitro-zonal    "/CN=i-0000000000000test.test-only.nitro-enclaves$O" ca0
issue nitro-enclave         nitro-instance "/CN=i-0000000000000test-enc0000000000000test.test-only$O" leaf
issue nitro-enclave-expired nitro-instance "/CN=expired.test-only$O" leaf 20200101000000Z 20210101000000Z
issue nitro-enclave-nosig   nitro-instance "/CN=nosig.test-only$O" leaf-nosig
root  rogue-root            "/CN=rogue.test-only.nitro-enclaves$O"
issue rogue-enclave         rogue-root     "/CN=rogue-enclave.test-only$O" leaf
rm -f ./*.ext ./*.srl
ls
