#!/usr/bin/env python3
"""Copy self-contained Mach-O instruction bytes without retargeting their ABI."""

import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "CptaMachOText.def").read_text())


def read(data, symbol, allowed_calls=()):
    def require(condition):
        if not condition:
            raise ValueError(CONFIG["error"])

    def unpack(kind, offset):
        fmt = CONFIG[kind + "_format"]
        require(0 <= offset <= len(data) - struct.calcsize(fmt))
        return struct.unpack_from(fmt, data, offset)

    header = unpack("header", 0)
    require(header[0] == CONFIG["magic"] and header[1] == CONFIG["cpu"]
            and header[2] & CONFIG["subtype_mask"] in CONFIG["subtypes"]
            and header[3] == CONFIG["object"])
    start = struct.calcsize(CONFIG["header_format"])
    end = start + header[5]
    require(end <= len(data))
    cursor, section_index, text, symtab = start, 0, None, None
    for _ in range(header[4]):
        command, size = unpack("command", cursor)
        require(size >= struct.calcsize(CONFIG["command_format"])
                and size <= end - cursor)
        if command == CONFIG["segment_command"]:
            segment = unpack("segment", cursor)
            section_start = cursor + struct.calcsize(CONFIG["segment_format"])
            section_size = struct.calcsize(CONFIG["section_format"])
            require(section_start + segment[9] * section_size <= cursor + size)
            for index in range(segment[9]):
                section_index += 1
                section = unpack("section", section_start + index * section_size)
                if (section[0].rstrip(b"\0").decode() == CONFIG["text_section"]
                        and section[1].rstrip(b"\0").decode() == CONFIG["text_segment"]):
                    require(text is None)
                    require(section[4] >= end and section[3] > 0
                            and section[4] + section[3] <= len(data))
                    text = (section_index, section)
        elif command == CONFIG["symbols_command"]:
            require(symtab is None and size == struct.calcsize(CONFIG["symbols_format"]))
            symtab = unpack("symbols", cursor)
        cursor += size
    require(cursor == end and text is not None and symtab is not None)
    ordinal, section = text
    _, _, symbols_offset, symbols_count, strings_offset, strings_size = symtab
    symbol_size = struct.calcsize(CONFIG["symbol_format"])
    require(symbols_offset >= end and strings_offset >= end
            and symbols_count * symbol_size <= len(data) - symbols_offset
            and strings_size <= len(data) - strings_offset)
    strings = data[strings_offset:strings_offset + strings_size]
    entries, symbols = [], []
    for index in range(symbols_count):
        name, kind, sect, _, address = unpack("symbol", symbols_offset + index * symbol_size)
        require(name < len(strings) and strings.find(b"\0", name) >= 0)
        spelling = strings[name:strings.index(b"\0", name)].decode()
        symbols.append((spelling, kind, sect, address))
        if (spelling == symbol
                and not kind & CONFIG["symbol_debug_mask"]
                and kind & CONFIG["symbol_type_mask"] == CONFIG["symbol_section_type"]
                and sect == ordinal):
            entries.append(address - section[2])
    require(len(entries) == 1 and 0 <= entries[0] < section[3]
            and entries[0] % CONFIG["alignment"] == 0
            and section[3] % CONFIG["alignment"] == 0)
    instructions = data[section[4]:section[4] + section[3]]
    relocations = []
    relocation_size = struct.calcsize(CONFIG["relocation_format"])
    require(not section[7] or (allowed_calls and section[6] >= end
            and section[6] + section[7] * relocation_size <= len(data)))
    offsets = set()
    for index in range(section[7]):
        offset, bits = unpack("relocation", section[6] + index * relocation_size)
        ordinal = bits & CONFIG["relocation_symbol_mask"]
        require(bits >> CONFIG["relocation_flags_shift"] == CONFIG["call26_flags"]
                and ordinal < len(symbols) and offset not in offsets
                and 0 <= offset <= len(instructions) - CONFIG["alignment"]
                and offset % CONFIG["alignment"] == 0)
        name, kind, sect, address = symbols[ordinal]
        require(name in allowed_calls and kind == CONFIG["symbol_external_mask"]
                and sect == 0 and address == 0)
        word, = struct.unpack_from(CONFIG["instruction_format"], instructions, offset)
        require(word == CONFIG["call26_opcode"])
        relocations.append({"offset": offset, "symbol": name})
        offsets.add(offset)
    return instructions, entries[0], relocations


def extract(data, symbol):
    """The original API still requires a completely relocation-free body."""
    instructions, entry, _ = read(data, symbol)
    return instructions, entry


def linked_symbols(data):
    """Read defined symbols and their bytes from the fixed ELF64 guest image."""
    def require(condition):
        if not condition:
            raise ValueError(CONFIG["linked_error"])

    def unpack(kind, offset):
        fmt = CONFIG["elf_" + kind + "_format"]
        require(0 <= offset <= len(data) - struct.calcsize(fmt))
        return struct.unpack_from(fmt, data, offset)

    header = unpack("header", 0)
    require(header[0].startswith(bytes.fromhex(CONFIG["elf_ident"]))
            and header[1] == CONFIG["elf_executable"]
            and header[2] == CONFIG["elf_machine"]
            and header[11] == struct.calcsize(CONFIG["elf_section_format"]))
    sections = [unpack("section", header[6] + index * header[11])
                for index in range(header[12])]
    result = {}
    for section in sections:
        if section[1] != CONFIG["elf_symbols_type"]:
            continue
        require(section[9] == struct.calcsize(CONFIG["elf_symbol_format"])
                and section[5] % section[9] == 0 and section[6] < len(sections))
        names = sections[section[6]]
        require(names[1] == CONFIG["elf_strings_type"]
                and names[4] + names[5] <= len(data))
        strings = data[names[4]:names[4] + names[5]]
        for offset in range(section[4], section[4] + section[5], section[9]):
            name, info, _, ordinal, address, _ = unpack("symbol", offset)
            if info >> CONFIG["elf_binding_shift"] != CONFIG["elf_global_binding"]:
                continue
            if not 0 < ordinal < len(sections):
                continue
            require(name < len(strings) and strings.find(b"\0", name) >= 0)
            spelling = strings[name:strings.index(b"\0", name)].decode()
            if not spelling:
                continue
            require(spelling not in result)
            result[spelling] = (address, sections[ordinal])
    return result


def verify_linked(data, symbols, name, instructions, entry, relocations, targets):
    address, section = symbols[name]
    begin = address - entry
    offset = section[4] + begin - section[3]
    if (begin < section[3] or begin + len(instructions) > section[3] + section[5]
            or offset + len(instructions) > len(data)):
        raise ValueError(CONFIG["linked_error"])
    expected = bytearray(instructions)
    for relocation in relocations:
        destination = symbols[targets[relocation["symbol"]]][0]
        delta = destination - (begin + relocation["offset"])
        scaled = delta // CONFIG["alignment"]
        bound = (CONFIG["call26_mask"] + 1) // 2
        if delta % CONFIG["alignment"] or not -bound <= scaled < bound:
            raise ValueError(CONFIG["linked_error"])
        struct.pack_into(CONFIG["instruction_format"], expected, relocation["offset"],
                         CONFIG["call26_opcode"] | (scaled & CONFIG["call26_mask"]))
    if data[offset:offset + len(expected)] != expected:
        raise ValueError(CONFIG["linked_error"])
