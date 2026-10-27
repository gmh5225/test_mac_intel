//! Authored native process controls; no captured input or recovered client.
use std::os::windows::ffi::OsStrExt;
#[path = "role_boundary.rs"]
mod boundary;

unsafe extern "C" {
    fn getenv(name: *const core::ffi::c_char) -> *const core::ffi::c_char;
    fn _wgetenv(name: *const u16) -> *const u16;
}

fn visible() -> (bool, bool, bool) {
    let name = [65, 82, 71, 86, 48, 0];
    (std::env::var_os("ARGV0").is_some(), !unsafe { getenv(c"ARGV0".as_ptr()) }.is_null(),
        !unsafe { _wgetenv(name.as_ptr()) }.is_null())
}

fn wide(text: &str) -> Vec<u16> { text.encode_utf16().collect() }

fn vectors() -> usize {
    use boundary::Role::*;
    let mut count = 0;
    for unit in 0u16..=u16::MAX {
        assert_eq!(boundary::select_wide(Some(&[unit]), None), Runtime);
        let path = [unit, 92, 114, 103];
        assert_eq!(boundary::select_wide(Some(&wide("ugrep")), Some(&path)), Ripgrep);
        if unit > 127 {
            assert_eq!(boundary::select_wide(Some(&[114, 103, unit]), None), Runtime);
            count += 1;
        }
        count += 2;
    }
    for (name, role) in [("rg", Ripgrep), ("rg.exe", Ripgrep), ("ug", Ugrep),
        ("ug.exe", Ugrep), ("ugrep", Ugrep), ("ugrep.exe", Ugrep)] {
        assert_eq!(boundary::select_wide(Some(&wide(name)), None), role);
        assert_eq!(boundary::select_wide(Some(&wide("unknown")), Some(&wide(&format!("C:\\猫\\{name}")))), role);
        count += 2;
    }
    for name in ["bfs", "apply-seccomp", "RG", "rg.EXE", "C:\\rg.exe", "", "猫"] {
        assert_eq!(boundary::select_wide(Some(&wide(name)), None), Runtime);
        count += 1;
    }
    count
}

fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--fresh-child")) {
        println!("{:?}", visible()); return;
    }
    let controls = vectors();
    let before = visible(); // Initialize both CRT views independently first.
    let (role, args) = unsafe { boundary::consume_and_select() }.expect("consume_and_select");
    assert_eq!(visible(), (false, false, false));
    println!("role:{}", role as u8);
    println!("vectors:{controls}");
    println!("before:{before:?}");
    println!("after:{:?}", visible());
    for arg in args {
        println!("arg:{}", arg.iter().map(|u| format!("{u:04x}")).collect::<String>());
    }
    let child = std::process::Command::new(std::env::current_exe().unwrap()).arg("--fresh-child").output().unwrap();
    assert!(child.status.success() && child.stderr.is_empty());
    assert_eq!(child.stdout, b"(false, false, false)\n");
    println!("fresh_child:{}", String::from_utf8(child.stdout).unwrap().trim());
    // Also exercise the OS string conversion used by actual arguments.
    assert!(std::ffi::OsStr::new("猫").encode_wide().eq([0x732b]));
}
