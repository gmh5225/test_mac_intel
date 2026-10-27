//! Owned caller proving that only the private compositor supplies fixture data.
use std::io::{Read, Write};
use wl_clipboard_rs::paste::{get_contents, ClipboardType, MimeType, Seat};

fn main() {
    let kind = if std::env::args().nth(1).as_deref() == Some("primary") { ClipboardType::Primary } else { ClipboardType::Regular };
    match get_contents(kind, Seat::Unspecified, MimeType::Text) {
        Ok((mut pipe, _)) => {
            let mut value = Vec::new(); pipe.read_to_end(&mut value).unwrap();
            std::io::stdout().write_all(&value).unwrap();
        }
        Err(error) => { eprintln!("{error}"); std::process::exit(1); }
    }
}
