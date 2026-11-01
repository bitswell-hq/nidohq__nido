//! Byte-class lookup tables, built at compile time. A table read is one
//! memory lookup, cheaper than the range comparisons it replaces.

pub global CR: u8 = 13;
pub global LF: u8 = 10;
pub global SP: u8 = 32;
pub global HTAB: u8 = 9;

comptime fn is_alnum(c: u32) -> bool {
    ((c >= 48) & (c <= 57)) | ((c >= 65) & (c <= 90)) | ((c >= 97) & (c <= 122))
}

/// 1 for the bytes of an RFC 5322 dot-atom local part: `atext` and `.`
/// (`A-Z a-z 0-9 ! # $ % & ' * + - / = ? ^ _ ` { | } ~ .`).
comptime fn local_part_table() -> [Field; 256] {
    let mut t = [0; 256];
    for c in 0..256 {
        let symbol = (c == 33)
            | ((c >= 35) & (c <= 39))
            | (c == 42)
            | (c == 43)
            | (c == 45)
            | (c == 46)
            | (c == 47)
            | (c == 61)
            | (c == 63)
            | ((c >= 94) & (c <= 96))
            | ((c >= 123) & (c <= 126));
        if is_alnum(c) | symbol {
            t[c] = 1;
        }
    }
    t
}

/// 1 for bytes outside printable ASCII (`0x20..=0x7e`).
comptime fn not_printable_table() -> [Field; 256] {
    let mut t = [0; 256];
    for c in 0..256 {
        if (c < 32) | (c > 126) {
            t[c] = 1;
        }
    }
    t
}

/// ASCII lowercase: `A-Z` to `a-z`, every other byte unchanged.
comptime fn lower_table() -> [u8; 256] {
    let mut t = [0; 256];
    for c in 0..256 {
        t[c] = if (c >= 65) & (c <= 90) { c + 32 } else { c } as u8;
    }
    t
}

/// 1 for the bytes accepted in an address domain: `A-Z a-z 0-9 . -`.
comptime fn domain_table() -> [Field; 256] {
    let mut t = [0; 256];
    for c in 0..256 {
        if is_alnum(c) | (c == 46) | (c == 45) {
            t[c] = 1;
        }
    }
    t
}

/// 1 for lowercase hexadecimal digits `0-9 a-f`.
comptime fn hex_lower_table() -> [Field; 256] {
    let mut t = [0; 256];
    for c in 0..256 {
        if ((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)) {
            t[c] = 1;
        }
    }
    t
}

/// The numeric value of a decimal digit byte, 0 for any other byte (callers
/// check membership with `DIGIT`).
comptime fn digit_value_table() -> [Field; 256] {
    let mut t = [0; 256];
    for c in 48..58 {
        t[c] = (c - 48) as Field;
    }
    t
}

comptime fn digit_table() -> [Field; 256] {
    let mut t = [0; 256];
    for c in 48..58 {
        t[c] = 1;
    }
    t
}

/// 1 for the 64 characters of the base64 alphabet (RFC 4648 section 4), padding
/// excluded.
comptime fn base64_table() -> [Field; 256] {
    let mut t = [0; 256];
    for c in 0..256 {
        if is_alnum(c) | (c == 43) | (c == 47) {
            t[c] = 1;
        }
    }
    t
}

pub global LOCAL_PART: [Field; 256] = local_part_table();
pub global NOT_PRINTABLE: [Field; 256] = not_printable_table();
pub global LOWER: [u8; 256] = lower_table();
pub global BASE64: [Field; 256] = base64_table();
pub global DOMAIN: [Field; 256] = domain_table();
pub global HEX_LOWER: [Field; 256] = hex_lower_table();
pub global DIGIT: [Field; 256] = digit_table();
pub global DIGIT_VALUE: [Field; 256] = digit_value_table();

/// The base64 alphabet of RFC 4648 section 4.
pub global BASE64_ALPHABET: [u8; 64] = [
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
    115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47,
];

/// `bytes[index]` when `active`, else 0. The read is always in bounds: an
/// inactive read uses index 0.
pub fn read_if<let N: u32>(bytes: [u8; N], index: u32, active: bool) -> u8 {
    let i = if active { index } else { 0 };
    let v = bytes[i];
    if active {
        v
    } else {
        0
    }
}
