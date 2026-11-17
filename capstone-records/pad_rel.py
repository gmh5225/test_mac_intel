"""Extend owned ELF64 .text while retaining all original relocation records."""
import struct

HEADER = struct.Struct('<16sHHIQQQIHHHHHH')
SECTION = struct.Struct('<IIQQQQIIQQ')


def sections(data):
    header = list(HEADER.unpack_from(data))
    assert header[0][:6] == b'\x7fELF\x02\x01'
    assert header[1] == 1 and header[2] == 62 and header[10] == 0
    assert header[11] == SECTION.size and header[12] > 0
    rows = [list(SECTION.unpack_from(data, header[6] + i * SECTION.size)) for i in range(header[12])]
    names = rows[header[13]]
    strings = data[names[4]:names[4] + names[5]]
    labels = [strings[row[0]:strings.index(b'\0', row[0])].decode() for row in rows]
    return header, rows, labels


def pad_text(data, growth):
    header, rows, names = sections(data)
    index = names.index('.text')
    text = rows[index]
    end = text[4] + text[5]
    assert growth > 0 and header[6] >= end
    alignment = max([1] + [row[8] for row in rows if row[4] >= end])
    assert alignment & (alignment - 1) == 0
    insertion = (growth + alignment - 1) & -alignment
    result = bytearray(data[:end] + b'\x90' * growth + bytes(insertion - growth) + data[end:])
    header[6] += insertion
    HEADER.pack_into(result, 0, *header)
    for i, row in enumerate(rows):
        if i == index:
            row[5] += growth
        elif row[4] >= end:
            row[4] += insertion
        SECTION.pack_into(result, header[6] + i * SECTION.size, *row)
    _, original, before_names = sections(data)
    _, updated, after_names = sections(result)
    assert before_names == after_names
    for i, (before, after) in enumerate(zip(original, updated)):
        assert before[0:4] == after[0:4] and before[6:] == after[6:]
        if i == index:
            assert result[after[4]:after[4] + after[5]] == data[before[4]:before[4] + before[5]] + b'\x90' * growth
        elif before[1] != 8:  # SHT_NOBITS has no file content.
            assert before[5] == after[5]
            assert result[after[4]:after[4] + after[5]] == data[before[4]:before[4] + before[5]]
    return bytes(result)
