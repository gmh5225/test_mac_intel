"""One authoritative locked Rust/std/rg source-graph adaptation for Bun."""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parent
RESOLVED_LOCK_SHA256 = "1bc3c6d8c1975d2693c16ca22cf84f9ea12d66ca2565916c292d27030919c723"
WINDOWS_LOCK_SHA256 = "7b4a962d2231acdedf4c49702c1a9ecc2f2744023976689d06732b90a443a6b2"


def plan(source, target_os):
    assert target_os in ["linux", "macos", "windows"]
    assert hashlib.sha256((ROOT / "resolved-Cargo.lock").read_bytes()).hexdigest() == RESOLVED_LOCK_SHA256
    root_cargo = source / "Cargo.toml"; root_before = root_cargo.read_text(encoding='utf-8')
    assert root_before.count('\nexclude = ["vendor"]\n') == 1 and "[patch.crates-io]" not in root_before
    root_after = root_before.replace('\nexclude = ["vendor"]\n', '\nexclude = ["vendor", "recovery-native"]\n')
    root_after += '\n[patch.crates-io]\npcre2 = { path = "recovery-native/pcre2-overlay" }\n'
    if target_os == "windows":
        root_after += 'pcre2-sys = { path = "recovery-native/pcre2-sys-overlay" }\n'
    runtime_cargo = source / "src/runtime/Cargo.toml"; runtime_before = runtime_cargo.read_text(encoding='utf-8')
    runtime_after = runtime_before + "\n[target.'cfg(target_os = \"" + target_os + "\")'.dependencies]\n" + 'recovered_ripgrep = { package = "ripgrep", path = "../../recovery-native/ripgrep", features = ["pcre2"] }\n'
    globs = source / "scripts/glob-sources.ts"; globs_before = globs.read_text(encoding='utf-8')
    anchor = '      "src/**/Cargo.toml",\n'; assert globs_before.count(anchor) == 1
    globs_after = globs_before.replace(anchor, anchor + '      "recovery-native/**/*.rs",\n      "recovery-native/**/Cargo.toml",\n')
    # The added serde_json trait implementations expose previously ambiguous
    # `as _` comparisons. Use the actual i32 family/u16 SystemError field types;
    # hash-gated line identities avoid changing the separate i32 syscall errors.
    type_patches = []
    for label, rel, numbers, old, new in [
        ("dns-type", "src/runtime/dns_jsc/options_jsc.rs", [226, 227], " as _ =>", " as i32 =>"),
        ("fs-type", "src/runtime/node/node_fs.rs", [1598, 2015, 8236, 8364], "E::EEXIST as _", "E::EEXIST as u16")]:
        before_type = (source / rel).read_text(encoding='utf-8'); lines = before_type.splitlines(True)
        for number in numbers:
            assert lines[number - 1].count(old) == 1
            lines[number - 1] = lines[number - 1].replace(old, new)
        type_patches.append((label, rel, before_type, "".join(lines)))
    lock_before = (source / "Cargo.lock").read_text(encoding='utf-8')
    lock_after = (ROOT / "resolved-Cargo.lock").read_text(encoding='utf-8')
    if target_os == "windows":
        windows_lock = ROOT.parent / 'windows-native-components/resolved-Cargo.lock'
        assert hashlib.sha256(windows_lock.read_bytes()).hexdigest() == WINDOWS_LOCK_SHA256
        lock_after = windows_lock.read_text(encoding='utf-8')
    return [
        ("cargo", "Cargo.toml", root_before, root_after),
        ("runtime-cargo", "src/runtime/Cargo.toml", runtime_before, runtime_after),
        ("source-globs", "scripts/glob-sources.ts", globs_before, globs_after),
        ("cargo-lock", "Cargo.lock", lock_before, lock_after), *type_patches]
