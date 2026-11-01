//! Constants fixed by the email-recovery interface specification
//! (`docs/email-recovery/spec.md`, version 1). Section numbers refer to it.

/// Domain tags, `BE(sha256(label)) mod r` for `nido/email-recovery/v1/<name>`
/// (section 2).
pub global DOM_COMMIT: Field = 0x28c44578265e026b7cecaa4b01b79fef9a1d1e4340e270596de3a724f044ee56;
pub global DOM_BLIND: Field = 0x2e13b680b3b2cbdab71f094fdf34f9ccd940c01ac6158ebc826ee5bdb05d0726;
pub global DOM_ENROLL: Field = 0x2bfe80f315441c3aadf9e7de0ab78fae545af772c0671cf5a512eb1ae713c9e7;
pub global DOM_KEY: Field = 0x1f6d4c7ed15d3b9480457cf9ff55d0ffff201158605d66399703659bf4d765f5;
pub global DOM_LEAF: Field = 0x1ddd7b4c7e2eba95d7da44139642c575589aa685188088b0555d3d4fbb5b1f7e;

/// Maximum address length in bytes (sections 4.5 and 5.3).
pub global ADDR_MAX: u32 = 124;
/// Maximum registry-leaf domain length in bytes (section 7.2).
pub global DOMAIN_MAX: u32 = 62;
/// Depth of the DKIM key registry tree (section 7.2).
pub global REGISTRY_DEPTH: u32 = 16;
/// The recovery Subject phrase, trailing space included (section 4.2).
pub global RECOVERY_PHRASE: str<30> = "APPROVE NIDO ACCOUNT RECOVERY ";
/// The enrollment Subject phrase (section 5.4).
pub global ENROLLMENT_PHRASE: str<29> = "ENROLL NIDO ACCOUNT RECOVERY ";
/// `hex(x)`: 64 lowercase hexadecimal characters (section 2).
pub global HEX_FIELD_LEN: u32 = 64;

/// Bound on the signed header block `H`, in bytes (section 6.2). Every
/// launch provider's recovery email fits, with the longest address and a
/// display name of at least 500 bytes (`circuits/email-recovery/README.md`,
/// "Header bound").
pub global HEADER_MAX: u32 = 1536;
/// Bound on the canonicalized DKIM-Signature field inside `H`, in bytes.
pub global DKIM_FIELD_MAX: u32 = 512;
/// Bound on the number of tags in that field.
pub global DKIM_TAGS_MAX: u32 = 16;
/// Length of `RECOVERY_PHRASE` in bytes.
pub global RECOVERY_PHRASE_LEN: u32 = 30;
