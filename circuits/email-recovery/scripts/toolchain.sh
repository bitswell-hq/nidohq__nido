#!/usr/bin/env bash
# Installs Perch's pinned ZK toolchain (nargo and bb, checksum-verified by
# vendor/perch/scripts/zk-toolchain.sh) into <repo>/target/zk-toolchain, or
# PERCH_ZK_TOOLCHAIN_DIR, and prints the environment that selects it:
#   eval "$(circuits/email-recovery/scripts/toolchain.sh)"
# Never touches a global ~/.nargo or ~/.bb.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export PERCH_ZK_TOOLCHAIN_DIR="${PERCH_ZK_TOOLCHAIN_DIR:-$root/target/zk-toolchain}"
exec bash "$root/vendor/perch/scripts/zk-toolchain.sh"
