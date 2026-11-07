#!/usr/bin/env python3
"""Copy self-contained Mach-O instruction bytes without retargeting their ABI."""

import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / "CptaMachOText.def").read_text())


def extract(data, symbol):
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
                    require(text is None and section[7] == 0)
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
    entries = []
    for index in range(symbols_count):
        name, kind, sect, _, address = unpack("symbol", symbols_offset + index * symbol_size)
        require(name < len(strings) and strings.find(b"\0", name) >= 0)
        if (strings[name:strings.index(b"\0", name)].decode() == symbol
                and not kind & CONFIG["symbol_debug_mask"]
                and kind & CONFIG["symbol_type_mask"] == CONFIG["symbol_section_type"]
                and sect == ordinal):
            entries.append(address - section[2])
    require(len(entries) == 1 and 0 <= entries[0] < section[3]
            and entries[0] % CONFIG["alignment"] == 0
            and section[3] % CONFIG["alignment"] == 0)
    return data[section[4]:section[4] + section[3]], entries[0]
