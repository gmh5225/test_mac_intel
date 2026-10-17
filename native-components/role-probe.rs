//! Authored host for direct component linkage and zero-file-budget controls.
use std::alloc::System;
use std::ffi::c_char;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

#[global_allocator]
static HOST_ALLOCATOR: System = System;

unsafe extern "C" {
    fn neverd_recovered_rg_main() -> !;
    fn neverd_recovered_seccomp_main(argc: i32, argv: *const *const c_char) -> i32;
}

fn main() -> std::process::ExitCode {
    let role = std::env::var("ARGV0").unwrap_or_default();
    // This authored probe is single-threaded at the component entry.
    unsafe { std::env::remove_var("ARGV0") };
    if role == "rg" {
        unsafe { neverd_recovered_rg_main() }
    } else if role == "apply-seccomp" {
        let args: Vec<CString> = std::env::args_os()
            .map(|value| CString::new(value.as_bytes()).unwrap())
            .collect();
        let mut pointers: Vec<*const c_char> = args.iter().map(|value| value.as_ptr()).collect();
        pointers.push(std::ptr::null());
        let code = unsafe { neverd_recovered_seccomp_main(args.len() as i32, pointers.as_ptr()) };
        assert!((0..=255).contains(&code));
        std::process::ExitCode::from(code as u8)
    } else {
        std::process::ExitCode::from(64)
    }
}
