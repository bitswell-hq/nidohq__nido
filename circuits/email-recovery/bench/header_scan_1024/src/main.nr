//! The structural scan of a 1024-byte header block.
use email_recovery::header::scan_header;

fn main(header: BoundedVec<u8, 1024>) -> pub (u32, u32, u32) {
    let layout = scan_header(header);
    (layout.from_start, layout.subject_start, layout.last_line_start)
}
