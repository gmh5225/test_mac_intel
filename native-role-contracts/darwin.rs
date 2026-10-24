//! Authored macOS selector model from exact original process observations.
//! These type and variant names do not restore erased producer declarations.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Role {
    Ripgrep = 0,
    Ugrep = 1,
    Bfs = 2,
    Runtime = 255,
}

pub(crate) fn classify(name: &[u8]) -> Role {
    match name {
        b"rg" => Role::Ripgrep,
        b"ug" | b"ugrep" => Role::Ugrep,
        b"bfs" => Role::Bfs,
        _ => Role::Runtime,
    }
}

pub(crate) fn prefer_actual(from_environment: Role, actual: Role) -> Role {
    if actual == Role::Runtime { from_environment } else { actual }
}

/// ARGV0 is a complete byte string; only actual argv[0] takes a POSIX basename.
/// The single-threaded process entry removes ARGV0 after classifying it.
pub(crate) fn select_darwin(environment: Option<&[u8]>, argv0: Option<&[u8]>) -> Role {
    let from_environment = environment.map_or(Role::Runtime, classify);
    let actual = argv0.map_or(Role::Runtime, |value| {
        classify(value.rsplit(|byte| *byte == b'/').next().unwrap_or_default())
    });
    prefer_actual(from_environment, actual)
}
