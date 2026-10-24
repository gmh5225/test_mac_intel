"""Stage pinned native Rust-distributed LLVM tools, without running rustup."""
from pathlib import Path
import hashlib
import json
import shutil
import struct
import tarfile

ROOT = Path(__file__).resolve().parent


def sha(path):
    with path.open('rb') as source: return hashlib.file_digest(source, 'sha256').hexdigest()


def prepare(arch, output, run, cached_archive=None):
    pins = json.loads((ROOT / 'llvm-tools-pins.json').read_bytes()); pin = pins['profiles'][arch]
    output.mkdir(); archive = output / 'llvm-tools.tar.xz'
    if cached_archive is not None:
        assert cached_archive.is_file() and not cached_archive.is_symlink(); shutil.copyfile(cached_archive, archive)
    else:
        run('download-llvm-tools', ['curl', '--http1.1', '--fail', '--silent', '--show-error', '--location',
            '--retry', '3', '--max-time', '300', '--max-filesize', str(pin['bytes']), '--output', archive, pin['url']])
    assert archive.stat().st_size == pin['bytes'] and sha(archive) == pin['sha256']
    extracted = output / 'extracted'; extracted.mkdir()
    with tarfile.open(archive, 'r:xz') as source:
        members = source.getmembers(); assert len(members) < 256 and sum(m.size for m in members) < 256 * 1024 * 1024
        assert len({m.name for m in members}) == len(members)
        assert all(not Path(m.name).is_absolute() and '..' not in Path(m.name).parts for m in members)
        source.extractall(extracted, filter='data')
    candidates = list(extracted.glob('*/llvm-tools-preview/lib/rustlib/' + pin['target'] + '/bin/llvm-objcopy'))
    assert len(candidates) == 1; toolbin = candidates[0].parent; versions = {}
    # LLVM's ar binary selects its ranlib driver by argv[0]. The Rust tools
    # package ships the binary once; keep the derived alias inside this task.
    ranlib = toolbin / 'llvm-ranlib'; assert not ranlib.exists(); ranlib.symlink_to('llvm-ar')
    for name in ['llvm-ar', 'llvm-nm', 'llvm-objcopy', 'llvm-ranlib']:
        tool = toolbin / name; assert tool.is_file()
        with tool.open('rb') as stream: header = stream.read(8)
        assert struct.unpack('<II', header) == (0xfeedfacf, {'arm64': 0x100000c, 'x64': 0x1000007}[arch])
        result = run(name + '-version', [tool, '--version']); text = result.stdout.decode()
        assert 'LLVM version 23.' in text or 'LLVM (http' in text and 'version 23.' in text
        versions[name] = dict(sha256=sha(tool), version=text)
    receipt = dict(status='pinned_native_llvm_tools_staged', arch=arch, pin=pin,
        manifest_sha256=pins['manifest_sha256'], rustup_executed=False, rust_global_state_modified=False,
        ranlib_provider='llvm-ar multicall alias in owned tool tree', tools=versions)
    (output / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return toolbin, receipt
