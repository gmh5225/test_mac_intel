"""Check the final Mach-O file after release strip and code signing."""
from pathlib import Path
import hashlib
import struct
from patch_macos import EXCEPTION_IMPORTS


def qualify(path, arch):
    body = Path(path).read_bytes(); header = struct.unpack_from('<8I', body)
    assert header[:2] == (0xfeedfacf, {'arm64': 0x100000c, 'x64': 0x1000007}[arch]) and header[3] == 2
    assert header[6] & (0x200000 | 0x80 | 0x4) == (0x200000 | 0x80 | 0x4)
    offset = 32; sections = {}; versions = []; libraries = []; symbols = None
    for _ in range(header[4]):
        command, size = struct.unpack_from('<II', body, offset); assert size >= 8 and offset + size <= 32 + header[5]
        if command == 0x19:
            count = struct.unpack_from('<I', body, offset + 64)[0]; assert size == 72 + 80 * count
            for i in range(count):
                name, owner, address, length, fileoff = struct.unpack_from('<16s16sQQI', body, offset + 72 + 80 * i)
                key = (owner.split(b'\0')[0].decode(), name.split(b'\0')[0].decode()); assert key not in sections
                sections[key] = length
        elif command == 0x32: versions.append(struct.unpack_from('<III', body, offset + 8))
        elif command in [0xc, 0x80000018, 0x8000001f]:
            nameoff = struct.unpack_from('<I', body, offset + 8)[0]; assert 0 < nameoff < size
            libraries.append(body[offset + nameoff:offset + size].split(b'\0')[0].decode())
        elif command == 0x2:
            assert symbols is None; symbols = struct.unpack_from('<4I', body, offset + 8)
        offset += size
    assert offset == 32 + header[5] and versions == [(1, 13 << 16, (26 << 16) | (5 << 8))]
    assert len(libraries) == 4 and set(libraries) == {'/usr/lib/libSystem.B.dylib', '/usr/lib/libc++.1.dylib', '/usr/lib/libicucore.A.dylib', '/usr/lib/libresolv.9.dylib'}
    assert sections.get(('__TEXT', '__unwind_info'), 0) > 0 and sections.get(('__TEXT', '__gcc_except_tab'), 0) > 0
    assert symbols is not None; symoff, count, stroff, strsize = symbols
    assert symoff + count * 16 <= len(body) and stroff + strsize <= len(body)
    strings = body[stroff:stroff + strsize]; imported = {}; weak = []
    for i in range(count):
        nameoff, kind, section, desc, value = struct.unpack_from('<IBBHQ', body, symoff + 16 * i)
        assert nameoff < len(strings); name = strings[nameoff:strings.index(b'\0', nameoff)].decode()
        if kind & 0xe == 0 and kind & 1:
            assert name not in imported; imported[name] = desc
            if desc & 0x40: weak.append(name)
    for name in EXCEPTION_IMPORTS: assert '_' + name in imported, 'Missing final exception runtime import: ' + name
    assert not any(name.startswith(('___atomic_', '___emutls_')) for name in imported)
    assert '_posix_spawn_file_actions_addfchdir' in weak, 'The measured original Bfs new-OS weak import must be retained'
    return dict(status='final_MachO_native_source_roles_exception_and_OS_boundary_verified', binary_sha256=hashlib.sha256(body).hexdigest(),
        arch=arch, build_versions=versions, dylibs=libraries, exception_imports=EXCEPTION_IMPORTS,
        exception_sections=[dict(segment=s, section=n, bytes=v) for (s,n),v in sections.items() if n in ['__eh_frame','__unwind_info','__gcc_except_tab']],
        weak_imports=weak, original_macos15_execdir_boundary_retained=True, goal_complete=False)
