//! Authored typed Windows classifier model, separate from runtime integration.
//! Native capsule comparison establishes the declared byte-classifier vectors.
//! Producer type names and full original-runtime equivalence are not claimed.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    Ripgrep = 0,
    Ugrep = 1,
    Runtime = 255,
}

pub fn classify(name: &[u8]) -> Role {
    match name {
        b"rg" | b"rg.exe" => Role::Ripgrep,
        b"ug" | b"ug.exe" | b"ugrep" | b"ugrep.exe" => Role::Ugrep,
        _ => Role::Runtime,
    }
}

/// Raw environment classification and Windows argv[0] basename precedence.
/// Version probes bound the selection evidence; the classifier is separately
/// compared to the exact original call-free native slices.
pub fn select(environment: Option<&[u8]>, argv0: Option<&[u8]>) -> Role {
    let from_environment = environment.map_or(Role::Runtime, classify);
    let actual = argv0.map_or(Role::Runtime, |value| {
        classify(value.rsplit(|byte| *byte == b'/' || *byte == b'\\').next().unwrap_or_default())
    });
    if actual == Role::Runtime { from_environment } else { actual }
}
