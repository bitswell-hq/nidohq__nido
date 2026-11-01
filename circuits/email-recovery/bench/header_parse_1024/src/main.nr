//! All header parsing without SHA-256 or RSA: scan, From, DKIM-Signature
//! tags and Subject.
use email_recovery::dkim::find_hints;
use email_recovery::dkim_signature::{check_dkim_signature, DkimSignature};
use email_recovery::from_address::parse_from;
use email_recovery::header::scan_header;
use email_recovery::spec::RECOVERY_PHRASE;
use email_recovery::subject::parse_subject;

fn main(header: BoundedVec<u8, 1024>) -> pub [u8; 64] {
    // Safety: the hints are checked by parse_from and check_dkim_signature.
    let hints = unsafe { find_hints::<1024, 16>(header.storage(), header.len()) };
    let layout = scan_header(header);
    let h = header.storage();
    let from = parse_from::<1024, 124>(h, layout, hints.from);
    let _: DkimSignature<512> = check_dkim_signature(h, header.len(), layout, from, hints.tags);
    parse_subject::<1024, 30, 64>(h, layout, RECOVERY_PHRASE.as_bytes())
}
