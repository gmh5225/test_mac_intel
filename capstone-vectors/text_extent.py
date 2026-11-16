"""Diagnostic only: increase a baseline ELF object's trailing text extent."""
import hashlib
import struct


def sections(path):
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01'
    assert struct.unpack_from('<H', data, 16)[0] == 1  # ET_REL
    offset = struct.unpack_from('<Q', data, 40)[0]
    size, count, names = struct.unpack_from('<HHH', data, 58)
    assert size == 64
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, offset + i * size)
               for i in range(count)]
    strings = headers[names]
    table = data[strings[4]:strings[4] + strings[5]]
    result = {}
    for header in headers:
        name = table[header[0]:table.index(b'\0', header[0])].decode()
        assert name not in result
        result[name] = dict(kind=header[1], flags=header[2], address=header[3],
                            size=header[5], link=header[6], info=header[7],
                            alignment=header[8], entry_size=header[9],
                            body=b'' if header[1] == 8 else data[header[4]:header[4] + header[5]])
    return result


def make_control(source, output, amount=32):
    before = sections(source)
    text = before['.text']['body']
    original = source.read_bytes()
    data = bytearray(original)
    shoff = struct.unpack_from('<Q', data, 40)[0]
    shsize, shnum, shnames = struct.unpack_from('<HHH', data, 58)
    names_header = struct.unpack_from('<IIQQQQIIQQ', data, shoff + shsize * shnames)
    names = data[names_header[4]:names_header[4] + names_header[5]]
    header_offset = None
    for i in range(shnum):
        offset = shoff + i * shsize
        name_offset = struct.unpack_from('<I', data, offset)[0]
        if names[name_offset:names.index(0, name_offset)] == b'.text':
            assert header_offset is None
            header_offset = offset
    assert header_offset is not None
    alignment = before['.text']['alignment']
    tail = (len(data) + alignment - 1) // alignment * alignment
    data.extend(bytes(tail - len(data)))
    data.extend(text + b'\x90' * amount)
    struct.pack_into('<QQ', data, header_offset + 24, tail, len(text) + amount)
    output.write_bytes(data)
    after = sections(output)
    assert before.keys() == after.keys()
    for name in before:
        a, b = before[name], after[name]
        if name == '.text':
            assert b['body'] == a['body'] + b'\x90' * amount
            assert b['size'] == a['size'] + amount
            assert {k: v for k, v in a.items() if k not in ('body', 'size')} == {
                k: v for k, v in b.items() if k not in ('body', 'size')}
        else:
            assert a == b, name
    # In particular, symbols, relocation entries, tables and unwind data are exact.
    changed = [i for i, (a, b) in enumerate(zip(original, data)) if a != b]
    assert all(header_offset + 24 <= i < header_offset + 40 for i in changed)
    return dict(complete=True, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                control_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                added_unreachable_text_bytes=amount, original_text_bytes=len(text),
                original_file_header_fields_changed=changed,
                existing_text_unchanged=True, other_sections_unchanged=True,
                symbols_and_relocations_unchanged=True,
                scope='Diagnostic object only. Added bytes follow the entire original text section and are never executed.')
