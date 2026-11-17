from pathlib import Path
import hashlib
import struct
from geometry import elf


def capture(path, code_section):
    data, _, sections, names = elf(path)
    code = sections[names.index(code_section)]
    instructions = data[code[4]:code[4] + code[5]]
    arrays = {}
    for section in sections:
        if section[1] != 2:  # SHT_SYMTAB
            continue
        strings_section = sections[section[6]]
        strings = data[strings_section[4]:strings_section[4] + strings_section[5]]
        assert section[9] == 24
        for offset in range(section[4], section[4] + section[5], 24):
            name, info, _, owner, value, size = struct.unpack_from('<IBBHQQ', data, offset)
            if info & 15 != 1 or not size or not 0 < owner < len(sections):
                continue
            label = strings[name:strings.index(b'\0', name)].decode()
            contents = sections[owner]
            assert contents[1] != 8 and value + size <= contents[5]
            arrays[label] = data[contents[4] + value:contents[4] + value + size]
    assert instructions and len(arrays) == 4, (len(instructions), list(arrays))
    return instructions, arrays


def compare(before, after):
    assert before == after, dict(instructions_equal=before[0] == after[0],
                                old_arrays={k: len(v) for k, v in before[1].items()},
                                new_arrays={k: len(v) for k, v in after[1].items()})
    return dict(instruction_bytes=len(before[0]), instruction_sha256=hashlib.sha256(before[0]).hexdigest(),
                arrays={k: dict(bytes=len(v), sha256=hashlib.sha256(v).hexdigest()) for k, v in before[1].items()},
                scope='The reader instruction section bytes and all four named immutable array payloads match exactly. ELF relocation records refer to the new sections; linked addresses are measured separately.')
