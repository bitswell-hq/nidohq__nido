//! Byte-string identifiers: contract ids, function names, wasm hashes, hosts,
//! key ids, network ids and path components. Identifiers compare by exact
//! bytewise equality; any normalization happens before the evaluator sees
//! them.

use alloc::vec::Vec;

/// Whether `a` and `b` are the same byte string.
#[must_use]
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `x` is one of the byte strings in `list`.
#[must_use]
pub fn bytes_in(x: &[u8], list: &[Vec<u8>]) -> bool {
    let mut i = 0;
    while i < list.len() {
        if bytes_eq(x, &list[i]) {
            return true;
        }
        i += 1;
    }
    false
}
