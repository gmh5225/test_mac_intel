//! Source-library dispatch at the macOS process entry, before VM/thread setup.
use core::ffi::{c_char, c_int};
use std::ffi::CStr;

#[path = "darwin_role_contract.rs"]
mod role_contract;
use role_contract::Role;

unsafe extern "C" {
    fn neverd_recovered_bfs_main(argc: c_int, argv: *const *const c_char) -> c_int;
    fn neverd_recovered_ugrep_main(argc: c_int, argv: *const *const c_char) -> c_int;
}

pub(super) unsafe fn dispatch(argc: c_int, argv: *const *const c_char) -> Option<c_int> {
    let environment = unsafe { libc::getenv(c"ARGV0".as_ptr()) };
    // getenv's borrowed storage may be invalidated by unsetenv.
    let from_environment = if environment.is_null() {
        Role::Runtime
    } else {
        role_contract::classify(unsafe { CStr::from_ptr(environment) }.to_bytes())
    };
    if !environment.is_null() {
        // This boundary runs once, before Bun creates threads or caches env.
        unsafe { libc::unsetenv(c"ARGV0".as_ptr()) };
    }
    let actual_argv0 = if argc > 0 && !argv.is_null() && !unsafe { *argv }.is_null() {
        Some(unsafe { CStr::from_ptr(*argv) }.to_bytes())
    } else {
        None
    };
    let actual = role_contract::select_darwin(None, actual_argv0);
    match role_contract::prefer_actual(from_environment, actual) {
        Role::Runtime => None,
        Role::Ripgrep => recovered_ripgrep::neverd_recovered_rg_main(),
        Role::Ugrep => Some(unsafe { neverd_recovered_ugrep_main(argc, argv) }),
        Role::Bfs => Some(unsafe { neverd_recovered_bfs_main(argc, argv) }),
    }
}
