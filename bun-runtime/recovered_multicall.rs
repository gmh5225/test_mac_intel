//! Direct Linux library dispatch before Bun initializes its VM or threads.
//! No ELF payload is materialized; existing process resource limits apply.
use core::ffi::{c_char, c_int};
use std::ffi::CStr;

#[path = "role_contract.rs"]
mod role_contract;
use role_contract::Role;

unsafe extern "C" {
    fn neverd_recovered_rg_main() -> !;
    fn neverd_recovered_seccomp_main(argc: c_int, argv: *const *const c_char) -> c_int;
}

/// Called once with the original C runtime arguments, before VM/thread setup.
pub(super) unsafe fn dispatch(argc: c_int, argv: *const *const c_char) -> Option<c_int> {
    // Classify before unsetenv can invalidate the borrowed C string.
    let environment = unsafe { libc::getenv(c"ARGV0".as_ptr()) };
    let from_environment = if environment.is_null() {
        Role::Runtime
    } else {
        role_contract::classify(unsafe { CStr::from_ptr(environment) }.to_bytes())
    };
    if !environment.is_null() {
        // Startup is single-threaded and the name is a static C string.
        unsafe { libc::unsetenv(c"ARGV0".as_ptr()) };
    }
    let argv0 = if argc > 0 && !argv.is_null() && !unsafe { *argv }.is_null() {
        Some(unsafe { CStr::from_ptr(*argv) }.to_bytes())
    } else {
        None
    };
    let actual = role_contract::select_linux(None, argv0);
    match role_contract::prefer_actual(from_environment, actual) {
        Role::Runtime => None,
        // The public library owns process termination with its real ExitCode.
        Role::Ripgrep => unsafe { neverd_recovered_rg_main() },
        // This C entry receives the unchanged process argv and inherited fds.
        Role::ApplySeccomp => Some(unsafe { neverd_recovered_seccomp_main(argc, argv) }),
        role @ (Role::Ugrep | Role::Bfs) => {
            eprintln!("recovered native dispatch: {role:?} implementation is not integrated");
            Some(126)
        }
    }
}
