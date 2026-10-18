"""Prepare only the public rg/PCRE2 source inputs for a new target build."""
from pathlib import Path
import hashlib
import json
import shutil
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / 'runtime-helpers'))
from build import SOURCES, unpack
from prepare_pcre2 import CRATE_SHA256, prepare as prepare_pcre2


def sha(path):
    with path.open('rb') as stream: return hashlib.file_digest(stream, 'sha256').hexdigest()


def prepare(output, run, target_os=None):
    assert target_os in [None, 'windows']
    output.mkdir(); inputs = output / 'inputs'; inputs.mkdir(); work = output / 'prepare-work'; work.mkdir()
    for name, url, prefix, digest in SOURCES:
        archive = inputs / (name + '.tar.gz')
        run('native-source-download-' + name, ['curl', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '300', '--output', archive, url])
        assert archive.stat().st_size <= 16 * 1024 * 1024 and sha(archive) == digest
        if name == 'ripgrep':
            if target_os == 'windows':
                from build_native import unpack_portable
                unpack_portable(archive, work / 'ripgrep', prefix)
            else: unpack(archive, work / 'ripgrep', prefix)
    crate = work / 'cargo-home/registry/cache/pinned/pcre2-0.2.9.crate'; crate.parent.mkdir(parents=True)
    run('native-source-download-pcre2-rust', ['curl', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '300', '--output', crate, 'https://static.crates.io/crates/pcre2/pcre2-0.2.9.crate'])
    assert sha(crate) == CRATE_SHA256
    overlay = prepare_pcre2(work)
    shutil.copytree(work / 'pcre2-overlay', inputs / 'pcre2-overlay')
    for name in ['pcre2-runtime-version.patch', 'pcre2-overlay.json']: shutil.copyfile(work / name, inputs / name)
    shutil.copyfile(crate, inputs / crate.name)
    if target_os == 'windows':
        sys_crate = inputs / 'pcre2-sys-0.2.10.crate'
        run('native-source-download-pcre2-sys', ['curl', '--http1.1', '--fail', '--silent', '--show-error', '--location', '--retry', '3', '--max-time', '300', '--output', sys_crate,
            'https://static.crates.io/crates/pcre2-sys/pcre2-sys-0.2.10.crate'])
        assert sha(sys_crate) == '18b9073c1a2549bd409bf4a32c94d903bb1a09bf845bc306ae148897fa0760a4'
    original = (work / 'ripgrep/crates/core/main.rs').read_bytes()
    (output / 'recovery_lib.rs').write_bytes(b'#![feature(exitcode_exit_method)]\n' + original + b'\n#[unsafe(no_mangle)]\npub extern "C" fn neverd_recovered_rg_main() -> ! { main().exit_process() }\n')
    # Work is a throwaway public source copy; no compiled input is admitted.
    shutil.rmtree(work)
    receipt = dict(status='pinned_public_rg_and_PCRE2_sources_prepared', pcre2_version_overlay=overlay,
        compiled_rust_archive_used=False, captured_source_used=False, recovered_erased_types=False)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    rows = [dict(file=p.relative_to(output).as_posix(), bytes=p.stat().st_size, sha256=sha(p)) for p in sorted(output.rglob('*')) if p.is_file()]
    (output / 'MANIFEST.json').write_text(json.dumps(dict(files=rows), indent=2) + '\n')
    return receipt
