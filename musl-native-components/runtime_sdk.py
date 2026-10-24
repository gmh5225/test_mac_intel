"""Extract only the admitted SDK's shared-library closure for role execution."""
from pathlib import Path
import json
import os
import posixpath
import stat
import tarfile
from sdk import ROOT, sha
from build_musl_baseline import verify_package


def prepare(arch, package, output):
    pin = json.loads((ROOT.parent / 'platform-runtime/musl-sdk-runtime-pins.json').read_bytes())['profiles'][arch]
    receipt = verify_package(package, pin); assert receipt['arch'] == arch and not output.exists()
    output.mkdir(); files = {r['file']: r for r in json.loads((package / 'sysroot-files.json').read_bytes())}
    names = {name for name in files if len(Path(name).parts) == (2 if name.startswith('lib/') else 3)
        and (name.startswith('lib/') or name.startswith('usr/lib/')) and ('.so' in Path(name).name or Path(name).name.startswith('ld-musl-'))}
    with tarfile.open(package / 'musl-sysroot.tar.gz') as archive:
        members = {m.name: m for m in archive}; pending = set(names)
        while pending:
            name = pending.pop(); row = files[name]; member = members[name]
            if row['kind'] == 'symlink': target = posixpath.normpath(posixpath.join(str(Path(name).parent), row['target']))
            elif member.islnk(): target = member.linkname
            else: continue
            assert target in files and not target.startswith('/') and not target.startswith('../')
            if target not in names: names.add(target); pending.add(target)
        assert len({name.casefold() for name in names}) == len(names)
        archive.extractall(output, members=[members[name] for name in sorted(names)], filter='data')
    for name in names:
        path = output / name; row = files[name]
        if row['kind'] == 'symlink': assert path.is_symlink() and os.readlink(path) == row['target'] and path.resolve().is_relative_to(output)
        else:
            assert path.is_file() and not path.is_symlink() and path.stat().st_size == row['bytes'] and sha(path) == row['sha256']
            assert stat.S_IMODE(path.stat().st_mode) == row['mode']
    assert {p.relative_to(output).as_posix() for p in output.rglob('*') if p.is_file() or p.is_symlink()} == names
    return dict(SDK_pin=pin, runtime_files=len(names), headers_extracted=False)
