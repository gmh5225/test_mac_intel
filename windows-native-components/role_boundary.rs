//! Windows selection and one-time ARGV0 consumption before Bun caches env.
use core::ffi::{c_char, c_int};
use std::os::windows::ffi::OsStrExt;

#[path = "windows_role_contract.rs"]
mod contract;
pub use contract::Role;

unsafe extern "C" {
    fn _putenv_s(name: *const c_char, value: *const c_char) -> c_int;
    fn _wputenv_s(name: *const u16, value: *const u16) -> c_int;
    fn getenv(name: *const c_char) -> *const c_char;
    fn _wgetenv(name: *const u16) -> *const u16;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn SetEnvironmentVariableW(name: *const u16, value: *const u16) -> i32;
}

const NAME: [u16; 6] = [65, 82, 71, 86, 48, 0];
const EMPTY: [u16; 1] = [0];

// The existing classifier recognizes only ASCII names and path separators.
// A non-ASCII UTF-16 unit cannot occur in an accepted spelling. Project it
// to one opaque byte for classification only; actual arguments stay UTF-16.
fn classification_bytes(value: &[u16]) -> Vec<u8> {
    value.iter().map(|unit| if *unit <= 127 { *unit as u8 } else { 128 }).collect()
}

pub fn select_wide(environment: Option<&[u16]>, argv0: Option<&[u16]>) -> Role {
    let environment = environment.map(classification_bytes);
    let argv0 = argv0.map(classification_bytes);
    contract::select(environment.as_deref(), argv0.as_deref())
}

/// Caller must run this once, before creating threads or borrowing CRT env.
/// Rust uses the OS environment block; C and wide C have separate CRT views.
pub unsafe fn consume_and_select() -> Result<(Role, Vec<Vec<u16>>), &'static str> {
    let arguments: Vec<Vec<u16>> = std::env::args_os().map(|arg| arg.encode_wide().collect()).collect();
    let environment = std::env::var_os("ARGV0").map(|value| value.encode_wide().collect::<Vec<_>>());
    let role = select_wide(environment.as_deref(), arguments.first().map(Vec::as_slice));
    // CRT calls alone do not remove the variable from the OS environment
    // block inherited by CreateProcess. Clear every view before dispatch.
    if unsafe { _putenv_s(c"ARGV0".as_ptr(), c"".as_ptr()) } != 0
        || unsafe { _wputenv_s(NAME.as_ptr(), EMPTY.as_ptr()) } != 0 {
        return Err("failed to consume CRT ARGV0");
    }
    if unsafe { SetEnvironmentVariableW(NAME.as_ptr(), core::ptr::null()) } == 0 {
        // A missing OS variable is already consumed. Query the state rather
        // than assuming every failed deletion is harmless.
        if std::env::var_os("ARGV0").is_some() { return Err("failed to consume OS ARGV0"); }
    }
    if std::env::var_os("ARGV0").is_some()
        || !unsafe { getenv(c"ARGV0".as_ptr()) }.is_null()
        || !unsafe { _wgetenv(NAME.as_ptr()) }.is_null() {
        return Err("ARGV0 remains visible after consumption");
    }
    Ok((role, arguments))
}
