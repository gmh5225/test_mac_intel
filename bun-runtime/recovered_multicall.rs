//! Native, embedded Linux component routing before Bun initializes its VM.
//!
//! This rebuild uses source-built ELF payloads through sealed anonymous file
//! descriptors. It does not reproduce the original static-library linkage.
//! Roles whose implementations are not yet integrated fail explicitly.

use core::ffi::{c_char, c_int};
use std::ffi::CStr;

#[path = "role_contract.rs"]
mod role_contract;
use role_contract::Role;

static RIPGREP: &[u8] = include_bytes!(env!("RECOVERY_RG_PAYLOAD"));
static SECCOMP: &[u8] = include_bytes!(env!("RECOVERY_SECCOMP_PAYLOAD"));

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

/// Called once on the startup thread, before other threads or environment
/// caches exist. The C runtime owns all input strings for the process lifetime.
pub(super) unsafe fn dispatch(argc: c_int, argv: *const *const c_char) -> Option<c_int> {
    // SAFETY: getenv supplies either null or a NUL-terminated environment
    // string. Classify it before unsetenv can invalidate the pointer.
    let environment = unsafe { libc::getenv(c"ARGV0".as_ptr()) };
    let from_environment = if environment.is_null() {
        Role::Runtime
    } else {
        role_contract::classify(unsafe { CStr::from_ptr(environment) }.to_bytes())
    };
    if !environment.is_null() {
        // The original consumes ARGV0 even when the spelling is unrecognized.
        // SAFETY: startup is single-threaded; the name is a valid C string.
        unsafe { libc::unsetenv(c"ARGV0".as_ptr()) };
    }
    let argv0 = if argc > 0 && !argv.is_null() && !unsafe { *argv }.is_null() {
        // SAFETY: the caller forwards the C-runtime-provided argc/argv pair.
        Some(unsafe { CStr::from_ptr(*argv) }.to_bytes())
    } else {
        None
    };
    let actual = role_contract::select_linux(None, argv0);
    let selected = if actual == Role::Runtime { from_environment } else { actual };
    let payload = match selected {
        Role::Runtime => return None,
        Role::Ripgrep => RIPGREP,
        Role::ApplySeccomp => SECCOMP,
        Role::Ugrep | Role::Bfs => {
            eprintln!("recovered native dispatch: {selected:?} implementation is not integrated");
            return Some(126);
        }
    };
    // SAFETY: each payload is a pinned public ELF with the current machine
    // type. argv still belongs to the C runtime, and environ is reread after
    // ARGV0 removal. No new process or host temporary pathname is created.
    Some(unsafe { execute_payload(payload, argv) })
}

unsafe fn execute_payload(payload: &[u8], argv: *const *const c_char) -> c_int {
    let flags = libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING;
    // SAFETY: the name is a static NUL-terminated string; these flags request
    // an anonymous owned descriptor, not a filesystem object.
    let fd = unsafe { libc::memfd_create(c"recovered-native-component".as_ptr(), flags) };
    if fd < 0 {
        eprintln!("recovered native dispatch: memfd_create: {}", std::io::Error::last_os_error());
        return 126;
    }
    let mut offset = 0;
    while offset < payload.len() {
        // SAFETY: payload[offset..] is a valid readable slice and fd is owned.
        let result = unsafe { libc::write(fd, payload[offset..].as_ptr().cast(), payload.len() - offset) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if result <= 0 {
            eprintln!("recovered native dispatch: write payload: {}", std::io::Error::last_os_error());
            // SAFETY: fd was returned successfully above and has not closed.
            unsafe { libc::close(fd) };
            return 126;
        }
        offset += result as usize;
    }
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    // SAFETY: fd is owned, the mode is valid, and the seal mask has no pointer.
    if unsafe { libc::fchmod(fd, 0o500) } != 0 || unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
        eprintln!("recovered native dispatch: seal payload: {}", std::io::Error::last_os_error());
        unsafe { libc::close(fd) };
        return 126;
    }
    // SAFETY: fd holds a complete ELF, an empty pathname is required for
    // AT_EMPTY_PATH, and argv/environ are the valid C runtime vectors. CLOEXEC
    // closes only this new descriptor after successful image replacement.
    unsafe {
        libc::syscall(libc::SYS_execveat, fd, c"".as_ptr(), argv, environ, libc::AT_EMPTY_PATH);
    }
    eprintln!("recovered native dispatch: execveat: {}", std::io::Error::last_os_error());
    unsafe { libc::close(fd) };
    126
}
