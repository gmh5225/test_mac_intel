"""Diagnostic only: increase a baseline ELF object's trailing text extent."""
import hashlib
import struct
import subprocess as sp


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
    payload = output.with_suffix('.text')
    payload.write_bytes(text + b'\x90' * amount)
    sp.run(['objcopy', '--update-section', '.text=' + str(payload), source, output], check=True)
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
    payload.unlink()
    return dict(complete=True, source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                control_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),
                added_unreachable_text_bytes=amount, original_text_bytes=len(text),
                existing_text_unchanged=True, other_sections_unchanged=True,
                symbols_and_relocations_unchanged=True,
                scope='Diagnostic object only. Added bytes follow the entire original text section and are never executed.')
