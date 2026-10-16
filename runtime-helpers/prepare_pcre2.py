"""Apply a recorded runtime-version fix to a separate, pinned dependency copy."""
from pathlib import Path
import difflib
import json
from build import sha, unpack

CRATE_SHA256 = "3be55c43ac18044541d58d897e8f4c55157218428953ebd39d86df3ba0286b2b"
FFI_SHA256 = "d514b003300adf0f239944210872774c83fea94e6d63d872795121bfb0073969"
OLD = """pub fn version() -> (u32, u32) {
    (PCRE2_MAJOR, PCRE2_MINOR)
}"""
NEW = """pub fn version() -> (u32, u32) {
    // Recovery build overlay: report the linked library, not the older
    // generated binding constants. Query the required size before writing.
    let size = unsafe { pcre2_config_8(PCRE2_CONFIG_VERSION, ptr::null_mut()) };
    assert!(size > 0 && size <= 1024, "invalid PCRE2 version size");
    let mut buffer = vec![0u8; size as usize];
    let written = unsafe {
        pcre2_config_8(PCRE2_CONFIG_VERSION, buffer.as_mut_ptr() as *mut c_void)
    };
    assert_eq!(written, size, "PCRE2 version query failed");
    assert_eq!(buffer.last(), Some(&0), "PCRE2 version is not terminated");
    let text = std::str::from_utf8(&buffer[..buffer.len() - 1])
        .expect("PCRE2 version is not UTF-8");
    let number = text.split_whitespace().next().expect("empty PCRE2 version");
    let (major, minor) = number.split_once('.').expect("invalid PCRE2 version");
    (major.parse().expect("invalid PCRE2 major"),
     minor.parse().expect("invalid PCRE2 minor"))
}"""

def prepare(build):
    archives = list((build / "cargo-home/registry/cache").glob("*/pcre2-0.2.9.crate"))
    assert len(archives) == 1 and sha(archives[0]) == CRATE_SHA256
    target = build / "pcre2-overlay"
    unpack(archives[0], target, "pcre2-0.2.9/")
    path = target / "src/ffi.rs"
    assert sha(path) == FFI_SHA256
    before = path.read_text(); assert before.count(OLD) == 1
    after = before.replace(OLD, NEW); path.write_text(after)
    patch = "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
        fromfile="pcre2-0.2.9/src/ffi.rs", tofile="pcre2-overlay/src/ffi.rs"))
    (build / "pcre2-runtime-version.patch").write_text(patch)
    manifest = build / "ripgrep/Cargo.toml"
    text = manifest.read_text(); assert "[patch.crates-io]" not in text
    manifest.write_text(text + '\n[patch.crates-io]\npcre2 = { path = "../pcre2-overlay" }\n')
    evidence = {"crate_sha256": CRATE_SHA256, "original_ffi_sha256": FFI_SHA256,
        "patched_ffi_sha256": sha(path), "patch_sha256": sha(build / "pcre2-runtime-version.patch"),
        "scope": "Runtime version reporting only; separately copied dependency, original archive and Cargo cache unchanged."}
    (build / "pcre2-overlay.json").write_text(json.dumps(evidence, indent=2) + "\n")
    return evidence
