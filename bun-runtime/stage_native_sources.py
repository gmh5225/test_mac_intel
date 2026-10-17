"""Stage pinned public Rust/C source inputs, never a prebuilt native archive."""
from pathlib import Path
import hashlib,shutil,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent.parent/'runtime-helpers'))
from build import unpack

def stage(package,destination):
    assert not destination.exists();destination.mkdir()
    inputs=package/'inputs'
    unpack(inputs/'ripgrep.tar.gz',destination/'ripgrep','ripgrep-14.1.1/')
    unpack(inputs/'pcre2.tar.gz',destination/'pcre2-source','pcre2-10.45/')
    shutil.copytree(inputs/'pcre2-overlay',destination/'pcre2-overlay')
    original=(destination/'ripgrep/crates/core/main.rs').read_bytes()
    wrapper=(package/'recovery_lib.rs').read_bytes()
    assert wrapper==b'#![feature(exitcode_exit_method)]\n'+original+b'\n#[unsafe(no_mangle)]\npub extern "C" fn neverd_recovered_rg_main() -> ! { main().exit_process() }\n'
    (destination/'ripgrep/crates/core/recovery_lib.rs').write_bytes(wrapper)
    manifest=destination/'ripgrep/Cargo.toml';before=manifest.read_text();assert '[lib]' not in before
    manifest.write_text(before+'\n[lib]\nname = "recovered_ripgrep"\npath = "crates/core/recovery_lib.rs"\ncrate-type = ["rlib"]\n')
    for name in ['apply-seccomp.c','unix-block-bpf.h']:shutil.copyfile(package/name,destination/name)
    (destination/'seccomp-entry.c').write_text('#define main neverd_recovered_seccomp_main\n#include "apply-seccomp.c"\n')
    assert not any(p.name.endswith(('.rlib','.a')) for p in destination.rglob('*') if p.is_file())
