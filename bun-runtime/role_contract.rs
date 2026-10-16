//! Reconstructed Linux role selection, kept separate from component execution.
//!
//! The role byte values and exact spellings come from the 2.1.296 native
//! classifier.  These are authored Rust types, not recovered producer types.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum Role {
    Ripgrep = 0,
    Ugrep = 1,
    Bfs = 2,
    ApplySeccomp = 3,
    Runtime = 255,
}

pub(crate) fn classify(name: &[u8]) -> Role {
    match name {
        b"rg" => Role::Ripgrep,
        b"ug" | b"ugrep" => Role::Ugrep,
        b"bfs" => Role::Bfs,
        b"apply-seccomp" => Role::ApplySeccomp,
        _ => Role::Runtime,
    }
}

/// A recognized actual argv[0] basename takes precedence over ARGV0.
/// ARGV0 itself is classified as a complete byte string, without basename,
/// suffix, case or Unicode normalization.  Its removal is the caller's job.
pub(crate) fn select_linux(environment_role: Option<&[u8]>, argv0: Option<&[u8]>) -> Role {
    let from_environment = environment_role.map_or(Role::Runtime, classify);
    let actual = argv0.map_or(Role::Runtime, |value| {
        let basename = value.rsplit(|byte| *byte == b'/').next().unwrap_or_default();
        classify(basename)
    });
    if actual == Role::Runtime {
        from_environment
    } else {
        actual
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_and_actual_argv_have_distinct_path_rules() {
        assert_eq!(select_linux(Some(b"/tmp/rg"), None), Role::Runtime);
        assert_eq!(select_linux(None, Some(b"/tmp/rg")), Role::Ripgrep);
        assert_eq!(select_linux(Some(b"ug"), Some(b"/tmp/rg")), Role::Ripgrep);
        assert_eq!(select_linux(Some(b"rg"), Some(b"client")), Role::Ripgrep);
        assert_eq!(select_linux(Some(b"bfs"), Some(b"/tmp/")), Role::Bfs);
    }

    #[test]
    fn no_unsupported_alias_is_silently_recognized() {
        for name in [b"RG".as_slice(), b"rg.exe", b"grep", b"find", b"bun", b"rg/", b"ugrep\0", b"apply_seccomp", b""] {
            assert_eq!(classify(name), Role::Runtime, "{name:?}");
        }
        assert_eq!(classify(b"ug"), Role::Ugrep);
        assert_eq!(classify(b"ugrep"), Role::Ugrep);
    }
}
