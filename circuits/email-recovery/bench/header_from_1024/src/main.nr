//! The scan plus the From address (124-byte bound).
use email_recovery::dkim::find_hints;
use email_recovery::from_address::parse_from;
use email_recovery::header::scan_header;

fn main(header: BoundedVec<u8, 1024>) -> pub BoundedVec<u8, 124> {
    // Safety: the hints are checked by parse_from.
    let hints = unsafe { find_hints::<1024, 16>(header.storage(), header.len()) };
    let layout = scan_header(header);
    parse_from::<1024, 124>(header.storage(), layout, hints.from).address
}
