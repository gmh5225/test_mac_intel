"""Prove the diagnostic pair differs in one call, not code/data placement."""
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
        end = names_data.index(b'\0', name_offset)
        name = names_data[name_offset:end].decode()
        body = b'' if kind == 8 else data[offset:offset + size]
        result[name] = dict(kind=kind, flags=flags, address=address,
                            offset=offset, size=size, body=body)
    return data[phoff:phoff + phnum * phsize], result


def verify_layout(baseline, candidate):
    a, b = baseline.read_bytes(), candidate.read_bytes()
    a_headers, before = sections(a)
    b_headers, after = sections(b)
    assert a_headers == b_headers, 'PT_LOAD/program header layout differs'
    assert before.keys() == after.keys()
    changed = []
    rows = []
    for name in before:
        old, new = before[name], after[name]
        assert {k: v for k, v in old.items() if k != 'body'} == {
            k: v for k, v in new.items() if k != 'body'}, name
        identical = old['body'] == new['body']
        if not identical:
            changed.append(name)
        rows.append(dict(section=name, address=old['address'], size=old['size'],
                         identical=identical,
                         before_sha256=hashlib.sha256(old['body']).hexdigest(),
                         after_sha256=hashlib.sha256(new['body']).hexdigest()))
    assert set(changed) == {'.text', '.note.gnu.build-id'}, changed
    asm = sp.check_output(['objdump', '-d', candidate], text=True)
    calls = re.findall(r'^\s*([0-9a-f]+):\s+e8\s+(?:[0-9a-f]{2}\s+){4}\s*call\s+[^\n]*<X86_getEvexInstructionScan>',
                       asm, re.M)
    assert len(calls) == 1, calls
    call_address = int(calls[0], 16)
    offset = call_address - before['.text']['address']
    old_text, new_text = before['.text']['body'], after['.text']['body']
    assert old_text[offset] == new_text[offset] == 0xe8
    assert old_text[:offset + 1] == new_text[:offset + 1]
    assert old_text[offset + 5:] == new_text[offset + 5:]
    assert old_text[offset + 1:offset + 5] != new_text[offset + 1:offset + 5]
    return dict(complete=True, load_headers_identical=True,
                allocated_section_layout_identical=True,
                permitted_differences=changed, sections=rows,
                call_address=call_address, call_operand_bytes=4,
                changed_text_bytes=sum(x != y for x, y in zip(old_text, new_text)),
                scope='All allocated bytes are equal except the intentional relative call operand and GNU build ID. This is a diagnostic pair, not the original production baseline.')
