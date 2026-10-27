//! Native Windows source-role dispatch before cached env and VM/thread setup.
use core::ffi::c_int;

#[path = "role_boundary.rs"]
mod role_boundary;
use role_boundary::Role;

unsafe extern "C" {
    fn neverd_recovered_ugrep_wmain(argc: c_int, argv: *const *const u16) -> c_int;
}

pub(super) unsafe fn dispatch() -> Option<c_int> {
    let (role, arguments) = match unsafe { role_boundary::consume_and_select() } {
        Ok(value) => value,
        Err(message) => { eprintln!("native Windows role boundary: {message}"); return Some(126); }
    };
    match role {
        Role::Runtime => None,
        Role::Ripgrep => recovered_ripgrep::neverd_recovered_rg_main(),
        Role::Ugrep => {
            let arguments: Vec<Vec<u16>> = arguments.into_iter().map(|mut arg| { arg.push(0); arg }).collect();
            let argc = match c_int::try_from(arguments.len()) { Ok(count) => count, Err(_) => return Some(126) };
            let mut pointers: Vec<*const u16> = arguments.iter().map(|arg| arg.as_ptr()).collect();
            pointers.push(core::ptr::null());
            Some(unsafe { neverd_recovered_ugrep_wmain(argc, pointers.as_ptr()) })
        }
    }
}
