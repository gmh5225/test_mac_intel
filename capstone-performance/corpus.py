"""Fetch public, digest-pinned fixtures; never execute downloaded binaries."""
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import tarfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def elf_text(data):
    if data[:4] != b'\x7fELF' or data[4] not in (1, 2) or data[5] not in (1, 2):
        raise ValueError('unsupported ELF header')
    endian = '<' if data[5] == 1 else '>'
    if data[4] == 2:
        offset = struct.unpack_from(endian + 'Q', data, 40)[0]
        size, count, names = struct.unpack_from(endian + 'HHH', data, 58)
        fmt = endian + 'IIQQQQIIQQ'
    else:
        offset = struct.unpack_from(endian + 'I', data, 32)[0]
        size, count, names = struct.unpack_from(endian + 'HHH', data, 46)
        fmt = endian + 'IIIIIIIIII'
    if not count or names >= count or size != struct.calcsize(fmt):
        raise ValueError('unsupported ELF section table')
    sections = [struct.unpack_from(fmt, data, offset + i * size) for i in range(count)]
    table = sections[names]
    strings = data[table[4]:table[4] + table[5]]
    matches = []
    for section in sections:
        end = strings.find(b'\0', section[0])
        if strings[section[0]:end] == b'.text':
            text = data[section[4]:section[4] + section[5]]
            if len(text) != section[5]:
                raise ValueError('truncated ELF text')
            matches.append(text)
    if len(matches) != 1 or not matches[0]:
        raise ValueError('expected exactly one nonempty .text section')
    return matches[0]


def pe_text(data):
    if data[:2] != b'MZ':
        raise ValueError('missing DOS signature')
    pe = struct.unpack_from('<I', data, 60)[0]
    if data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('missing PE signature')
    count = struct.unpack_from('<H', data, pe + 6)[0]
    header_size = struct.unpack_from('<H', data, pe + 20)[0]
    sections = pe + 24 + header_size
    matches = []
    for i in range(count):
        offset = sections + 40 * i
        if data[offset:offset + 8].rstrip(b'\0') != b'.text':
            continue
        virtual_size, _, raw_size, raw_offset = struct.unpack_from('<IIII', data, offset + 8)
        size = min(virtual_size, raw_size)
        text = data[raw_offset:raw_offset + size]
        if len(text) != size:
            raise ValueError('truncated PE text')
        matches.append(text)
    if len(matches) != 1 or not matches[0]:
        raise ValueError('expected exactly one nonempty PE .text section')
    return matches[0]


def deb_binary(package, name):
    members = subprocess.check_output(['ar', 't', str(package)], text=True).splitlines()
    payloads = [member for member in members if member.startswith('data.tar')]
    if len(payloads) != 1:
        raise ValueError('expected one Debian data archive')
    payload = subprocess.check_output(['ar', 'p', str(package), payloads[0]])
    with tarfile.open(fileobj=io.BytesIO(payload), mode='r:*') as archive:
        matches = [m for m in archive.getmembers()
                   if m.name.lstrip('./') in ('usr/bin/' + name, 'bin/' + name)]
        if len(matches) != 1 or not matches[0].isfile():
            raise ValueError('expected one ordinary binary member: ' + name)
        return archive.extractfile(matches[0]).read()


def prepare(source, scratch, evidence, command):
    corpus = scratch / 'corpus'
    corpus.mkdir()
    manifest = json.loads((source / 'manifest.json').read_text())
    packages = {}
    cases = []
    for row in manifest['inputs']:
        sha = row['package_sha256']
        if sha not in packages:
            package = corpus / sha
            command(['curl', '--fail', '--location', '--silent', '--show-error',
                     '--max-time', '120', row['url'], '-o', package], 'download-' + sha[:8])
            if digest(package.read_bytes()) != sha:
                raise ValueError('download digest mismatch: ' + row['name'])
            packages[sha] = package
        package = packages[sha]
        if row['kind'] == 'deb':
            binary = deb_binary(package, row['command'])
            text = elf_text(binary)
        else:
            binary = package.read_bytes()
            text = pe_text(binary)
        actual = digest(text)
        if 'text_sha256' in row and actual != row['text_sha256']:
            raise ValueError('text digest mismatch: ' + row['name'])
        target = corpus / (row['name'] + '.text')
        target.write_bytes(text)
        cases.append(dict(row, path=str(target), bytes=len(text), text_sha256=actual,
                          binary_sha256=digest(binary), executable_was_run=False))
    for name, bits, source_name, flags in [
        ('scalar32', 32, 'scalar.c', ['-fno-vectorize', '-fno-slp-vectorize']),
        ('scalar64', 64, 'scalar.c', ['-fno-vectorize', '-fno-slp-vectorize']),
        ('simd64', 64, 'simd.c', ['-mavx2', '-mfma']),
    ]:
        target = corpus / (name + '.o')
        triple = 'i686-unknown-linux-gnu' if bits == 32 else 'x86_64-unknown-linux-gnu'
        command(['clang', '-target', triple, '-O3', '-ffreestanding', *flags,
                 '-c', source / source_name, '-o', target], 'fixture-' + name)
        text = elf_text(target.read_bytes())
        path = corpus / (name + '.text')
        path.write_bytes(text)
        cases.append(dict(name=name, selector=bits, path=str(path), bytes=len(text),
                          text_sha256=digest(text), source=source_name,
                          source_sha256=digest((source / source_name).read_bytes()),
                          executable_was_run=False))
    (evidence / 'corpus.json').write_text(json.dumps(cases, indent=2) + '\n')
    return cases
