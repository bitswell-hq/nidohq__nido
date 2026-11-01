//! SHA-256 of a header block of at most 1024 bytes, zero past its length.
use email_recovery::pack::assert_zero_padded;
use sha256::sha256_var;

fn main(header: BoundedVec<u8, 1024>) -> pub [u8; 32] {
    assert_zero_padded(header);
    sha256_var(header.storage(), header.len())
}
