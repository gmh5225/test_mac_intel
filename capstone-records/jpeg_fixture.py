"""Read the pinned AVX2 assembly objects used by the full library comparison."""
from pathlib import Path
import hashlib
import io
import json
import subprocess as sp
import tarfile
from corpus import elf_text


def gnu_archive(data):
    # The pinned Debian inputs use GNU ar names; macOS /usr/bin/ar does not
    # resolve its long-name table. Read that format directly on both hosts.
    assert data.startswith(b'!<arch>\n')
    offset, strings, members = 8, b'', []
    while offset < len(data):
        header = data[offset:offset + 60]
        assert len(header) == 60 and header[58:] == b'`\n'
        name = header[:16].rstrip().decode()
        size = int(header[48:58])
        body = data[offset + 60:offset + 60 + size]
        assert len(body) == size
        offset += 60 + size + size % 2
        if name == '//':
            strings = body
        elif name in ('/', '/SYM64/'):
            continue
        else:
            if name.startswith('/'):
                start = int(name[1:])
                name = strings[start:strings.index(b'/\n', start)].decode()
            else:
                assert not name.startswith('#1/')
                name = name.removesuffix('/')
            members.append((name, body))
    assert offset == len(data)
    return members


def prepare_jpeg(source, scratch, evidence, command):
    meta = json.loads((source / 'jpeg-source.json').read_text())
    sha = lambda data: hashlib.sha256(data).hexdigest()
    package = scratch / 'jpeg-dev.deb'
    command(['curl', '-fsSL', '--retry', '3', '--max-time', '120', '-o', package, meta['url']], 'download-jpeg-avx2')
    assert sha(package.read_bytes()) == meta['package_sha256']
    payload, data = next((name, data) for name, data in gnu_archive(package.read_bytes()) if name.startswith('data.tar'))
    if payload.endswith('.zst'):
        data = sp.check_output(['zstd', '-d', '-q', '-c'], input=data)
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:*') as tar:
        member, = [item for item in tar.getmembers() if item.isfile() and Path(item.name).name == 'libjpeg.a']
        archive_data = tar.extractfile(member).read()
    objects = [(name, data) for name, data in gnu_archive(archive_data) if name in meta['members']]
    names = [name for name, _ in objects]
    assert len(names) == len(set(names)) and set(names) == set(meta['members'])
    output = bytearray()
    records = []
    for name, obj in objects:
        assert sha(obj) == meta['members'][name]['sha256']
        code = elf_text(obj)
        assert len(code) == meta['members'][name]['section_bytes']
        records.append(dict(name=name, offset=len(output), bytes=len(code), sha256=sha(obj)))
        output.extend(code)
    assert sha(output) == meta['text_sha256']
    target = scratch / 'jpeg-avx2-i386.text'
    target.write_bytes(output)
    result = dict(name='jpeg-avx2-i386', selector=32, path=str(target), bytes=len(output),
                  text_sha256=sha(output), package_sha256=meta['package_sha256'], url=meta['url'],
                  objects=records, executable_was_run=False,
                  selection='Complete text from the nine AVX2 objects recorded in the full i386 libjpeg comparison; sequential private iterator diagnostic, no iced comparison or common-function filtering.')
    (evidence / 'jpeg-fixture.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
