"""Bounded PE32+ section and native exception-directory observations."""
from pathlib import Path
import hashlib
import struct


def qualify(path, arch):
    raw = Path(path).read_bytes()
    def span(offset, size):
        assert 0 <= offset <= len(raw) and 0 <= size <= len(raw) - offset, 'PE range outside file'
        return raw[offset:offset + size]
    def at(fmt, offset): return struct.unpack(fmt, span(offset, struct.calcsize(fmt)))
    assert span(0, 2) == b'MZ'; pe, = at('<I', 60); assert span(pe, 4) == b'PE\0\0'
    machine, count, stamp, syms, nsyms, optional, flags = at('<HHIIIHH', pe + 4)
    assert machine == {'arm64': 0xaa64, 'x64': 0x8664}[arch] and 0 < count < 96 and optional >= 240
    opt = pe + 24; assert at('<H', opt)[0] == 0x20b
    assert at('<I', opt + 108)[0] >= 4
    sections = []
    for i in range(count):
        name, virtual, rva, size, offset, reloc, line, nr, nl, attrs = at('<8sIIIIIIHHI', opt + optional + 40 * i)
        name = name.rstrip(b'\0').decode('ascii'); data = span(offset, size)
        sections.append(dict(index=i + 1, name=name, rva=rva, virtual=virtual, raw_bytes=size, offset=offset, attrs=attrs,
            sha256=hashlib.sha256(data).hexdigest()))
    # PE section labels are eight bytes. The admitted Bun baseline already
    # contains two distinct __DATA,_ labels; section ordinal/RVA own identity.
    for i, left in enumerate(sections):
        for right in sections[i + 1:]:
            assert left['rva'] + max(left['virtual'], left['raw_bytes']) <= right['rva'] or right['rva'] + max(right['virtual'], right['raw_bytes']) <= left['rva']
    def section(rva, length):
        found = [s for s in sections if s['rva'] <= rva and rva + length <= s['rva'] + s['raw_bytes']]
        assert len(found) == 1, 'PE RVA does not resolve to one file-backed section'
        s = found[0]; return s, s['offset'] + rva - s['rva']
    text = [s for s in sections if s['name'] == '.text']; assert len(text) == 1 and text[0]['attrs'] & 0x20000000
    exception_rva, size = at('<II', opt + 112 + 3 * 8); width = 12 if arch == 'x64' else 8
    assert size > 0 and size % width == 0
    pdata, offset = section(exception_rva, size); assert pdata['name'] == '.pdata'
    previous = -1; unpacked = packed = 0; links = {}
    for i in range(size // width):
        fields = at('<III' if arch == 'x64' else '<II', offset + width * i); start = fields[0]
        code, _ = section(start, 1); assert code['attrs'] & 0x20000000 and start > previous; previous = start
        if arch == 'x64':
            end, unwind = fields[1:]; assert end > start
            end_section, _ = section(end - 1, 1); assert end_section['name'] == code['name']
            section(unwind & ~1, 4); unpacked += 1
        else:
            unwind = fields[1]; flag = unwind & 3
            if flag == 0: section(unwind, 4); unpacked += 1
            elif flag in [1, 2]: packed += 1
            else:
                # Current ARM64 ABI uses flag 3 for jump-island parent links.
                parent = unwind & ~3
                assert exception_rva <= parent < exception_rva + size and (parent - exception_rva) % width == 0
                links[i] = (parent - exception_rva) // width
    for start in links:
        seen = set(); current = start
        while current in links:
            assert current not in seen, 'Cyclic ARM64 exception record link'
            seen.add(current); current = links[current]
    return dict(status='native_PE32plus_sections_and_nonempty_exception_directory_verified', arch=arch,
        binary_sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw), sections=sections,
        exception_records=size // width, unpacked_unwind_records=unpacked, packed_ARM64_unwind_records=packed,
        ARM64_jump_island_parent_links=len(links), complete_unwind_program_validation=False,
        exception_directory_sha256=hashlib.sha256(span(offset, size)).hexdigest(), input_executed=False)
