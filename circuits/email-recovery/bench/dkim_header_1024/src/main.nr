//! Header-only DKIM verification at 1024-byte headers: SHA-256, RSA-2048,
//! scan, From (124 bytes), DKIM-Signature tags (512-byte field, 16 tags),
//! Subject (the recovery phrase and 64 hex characters) and the key hash.
//! Public outputs: the key hash, the From address and domain packed as the
//! spec packs them, and the Subject value packed.
use email_recovery::dkim::verify_dkim_header;
use email_recovery::pack::pack_bytes;
use email_recovery::spec::RECOVERY_PHRASE;

fn main(
    header: BoundedVec<u8, 1024>,
    modulus: [u128; 18],
    redc: [u128; 18],
    signature: [u128; 18],
) -> pub (Field, u32, [Field; 4], u32, [Field; 2], [Field; 3]) {
    let out = verify_dkim_header::<1024, 512, 16, 124, 30, 64>(
        header,
        modulus,
        redc,
        signature,
        RECOVERY_PHRASE.as_bytes(),
    );
    (
        out.key_hash, out.from_address.len(), pack_bytes(out.from_address.storage()),
        out.domain.len(), pack_bytes(out.domain.storage()), pack_bytes(out.subject_value),
    )
}
