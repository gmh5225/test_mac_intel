"""Construct a 64-bit-only diagnostic control by changing one call operand."""
import hashlib
import re
import struct
import subprocess as sp


def sections(data):
    assert data[:6] == b'\x7fELF\x02\x01'
    phoff, shoff = struct.unpack_from('<QQ', data, 32)
    phsize, phnum, shsize, shnum, names = struct.unpack_from('<HHHHH', data, 54)
    assert shsize == 64
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize)
               for i in range(shnum)]
    strings = headers[names]
    names_data = data[strings[4]:strings[4] + strings[5]]
    result = {}
    for header in headers:
        name_offset, kind, flags, address, offset, size = header[:6]
        if not flags & 2:
            continue
        name = names_data[name_offset:names_data.index(b'\0', name_offset)].decode()
        body = b'' if kind == 8 else data[offset:offset + size]
        result[name] = dict(kind=kind, flags=flags, address=address,
                            offset=offset, size=size, body=body)
    return data[phoff:phoff + phnum * phsize], result


def make_control(candidate, control):
    original = candidate.read_bytes()
    headers, before = sections(original)
    names = {}
    for line in sp.check_output(['nm', '-n', '-S', '--defined-only', candidate], text=True).splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[3] in ('X86_writeVectorModeOutput', 'X86_writeVectorOutput'):
            assert fields[3] not in names
            names[fields[3]] = int(fields[0], 16)
    assert len(names) == 2
    assembly = sp.check_output(['objdump', '-d', candidate], text=True)
    calls = re.findall(r'^\s*([0-9a-f]+):\s+e8\s+(?:[0-9a-f]{2}\s+){4}\s*call\s+[^\n]*<X86_writeVectorModeOutput>', assembly, re.M)
    assert len(calls) == 1, calls
    address = int(calls[0], 16)
    text = before['.text']
    relative = address - text['address']
    assert 0 <= relative <= text['size'] - 5
    offset = text['offset'] + relative
    assert original[offset] == 0xe8
    assert address + 5 + struct.unpack_from('<i', original, offset + 1)[0] == names['X86_writeVectorModeOutput']
    changed = bytearray(original)
    struct.pack_into('<i', changed, offset + 1, names['X86_writeVectorOutput'] - address - 5)
    control.write_bytes(changed)
    control.chmod(candidate.stat().st_mode & 0o777)
    loaded = control.read_bytes()
    after_headers, after = sections(loaded)
    assert headers == after_headers and before.keys() == after.keys()
    rows = []
    for name, old in before.items():
        new = after[name]
        assert {k: v for k, v in old.items() if k != 'body'} == {k: v for k, v in new.items() if k != 'body'}
        if name != '.text':
            assert old['body'] == new['body'], name
        rows.append(dict(section=name, address=old['address'], size=old['size'],
                         identical_bytes=old['body'] == new['body']))
    assert original[:offset + 1] == loaded[:offset + 1]
    assert original[offset + 5:] == loaded[offset + 5:]
    assert original[offset + 1:offset + 5] != loaded[offset + 1:offset + 5]
    disassembly = sp.check_output(['objdump', '-d', '--start-address=' + str(address),
                                   '--stop-address=' + str(address + 5), control], text=True)
    assert '<X86_writeVectorOutput>' in disassembly
    return dict(complete=True, source_sha256=hashlib.sha256(original).hexdigest(),
                control_sha256=hashlib.sha256(loaded).hexdigest(), call_address=address,
                old_target=names['X86_writeVectorModeOutput'], new_target=names['X86_writeVectorOutput'],
                program_headers_identical=True, allocated_layout_identical=True,
                only_changed_file_bytes=list(range(offset + 1, offset + 5)),
                changed_bytes=sum(a != b for a, b in zip(original, loaded)), sections=rows,
                scope='Diagnostic control is valid only for 64-bit input. It retains the candidate build ID deliberately; SHA256 identifies the patched image.')
