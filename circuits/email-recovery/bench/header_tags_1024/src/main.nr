//! The scan, the From address and the DKIM-Signature tags (512-byte field,
//! 16 tags).
use email_recovery::dkim::find_hints;
use email_recovery::dkim_signature::{check_dkim_signature, DkimSignature};
use email_recovery::from_address::parse_from;
use email_recovery::header::scan_header;

fn main(header: BoundedVec<u8, 1024>) -> pub BoundedVec<u8, 62> {
    // Safety: the hints are checked by parse_from and check_dkim_signature.
    let hints = unsafe { find_hints::<1024, 16>(header.storage(), header.len()) };
    let layout = scan_header(header);
    let h = header.storage();
    let from = parse_from::<1024, 124>(h, layout, hints.from);
    let field: DkimSignature<512> = check_dkim_signature(h, header.len(), layout, from, hints.tags);
    field.domain
}
