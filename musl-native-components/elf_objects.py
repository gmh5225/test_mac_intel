"""Strict ELF64 little-endian relocatable-object readback for symbol renames."""
from pathlib import Path
import hashlib
import struct


class ObjectError(ValueError):
    pass


def require(condition, message):
    if not condition: raise ObjectError(message)


def parse(raw):
    def at(fmt, offset):
        size = struct.calcsize(fmt)
        require(0 <= offset <= len(raw) - size, 'Truncated ELF record')
        return struct.unpack_from(fmt, raw, offset)
    header = at('<16sHHIQQQIHHHHHH', 0)
    ident, kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, strings = header
    require(ident[:7] == b'\x7fELF\x02\x01\x01' and kind == 1 and machine in [62, 183] and version == 1, 'Unsupported ELF object')
    require(ehsize == 64 and entry == phoff == phnum == 0 and shsize == 64 and 0 < shnum < 65535 and 0 < strings < shnum, 'Unsupported ELF layout')
    sections = [at('<IIQQQQIIQQ', shoff + i * 64) for i in range(shnum)]
    def data(section):
        _, typ, _, _, offset, size, _, _, _, _ = section
        if typ == 8: return b''
        require(0 <= offset <= len(raw) and size <= len(raw) - offset, 'Section outside ELF')
        return raw[offset:offset + size]
    def string(table, offset):
        require(0 <= offset < len(table) and b'\0' in table[offset:], 'Invalid ELF string')
        return table[offset:table.index(b'\0', offset)].decode('utf-8', errors='strict')
    table = data(sections[strings]); names = [string(table, s[0]) for s in sections]
    # ELF permits repeated section names; use their ordinal as part of identity.
    def owner(index):
        require(index < shnum or index >= 0xff00, 'Invalid ELF section index')
        require(index != 0xffff, 'Extended ELF indexes are not admitted')
        return (index, names[index]) if index < shnum else index
    symbols = {}; symbol_rows = {}
    for i, section in enumerate(sections):
        _, typ, _, _, _, size, link, _, _, entsize = section
        if typ != 2: continue
        require(entsize == 24 and size % 24 == 0 and 0 < link < shnum and sections[link][1] == 3, 'Invalid ELF symtab')
        strings_data = data(sections[link]); rows = []
        for offset in range(0, size, 24):
            name, info, other, index, value, length = struct.unpack_from('<IBBHQQ', data(section), offset)
            rows.append((string(strings_data, name), info, other, owner(index), value, length))
        symbols[i] = rows; symbol_rows[i] = rows
    require(len(symbols) == 1, 'Exactly one ELF symtab is required')
    string_sections = {strings} | {sections[i][6] for i in symbols}
    require(all(i in string_sections and not section[2] & 2 for i, section in enumerate(sections) if section[1] == 3), 'Unexpected ELF string section')
    ordinary = {}; relocations = {}
    for i, section in enumerate(sections):
        _, typ, flg, addr, _, size, link, info, align, entsize = section
        if typ in [4, 9]:
            width = 24 if typ == 4 else 16
            require(link in symbols and 0 < info < shnum and entsize == width and size % width == 0, 'Invalid ELF relocations')
            rows = []
            for offset in range(0, size, width):
                rel = struct.unpack_from('<QQq' if typ == 4 else '<QQ', data(section), offset)
                index = rel[1] >> 32; require(index < len(symbols[link]), 'Invalid relocation symbol')
                rows.append((rel[0], rel[1] & 0xffffffff, rel[2] if typ == 4 else None, symbols[link][index]))
            relocations[(i, names[i])] = (typ, flg, addr, size, owner(info), align, entsize, rows)
        elif typ not in [2, 3]:
            ordinary[(i, names[i])] = (typ, flg, addr, size, link, info, align, entsize, data(section))
    return dict(machine=machine, identity=(ident, kind, machine, version, flags, phsize), names=names,
        ordinary=ordinary, symbols=symbol_rows, relocations=relocations)


def compare_objects(before, after, mapping):
    old = parse(Path(before).read_bytes()); new = parse(Path(after).read_bytes())
    require(old['identity'] == new['identity'] and old['names'] == new['names'], 'ELF header or section identity changed')
    require(old['ordinary'] == new['ordinary'], 'ELF allocated/debug/group section bytes changed')
    def symbol(row): return (mapping.get(row[0], row[0]), *row[1:])
    # COMDAT sh_info and LLVM addrsig bytes contain symbol ordinals. Require
    # order as well as typed identity so those references cannot be retargeted.
    require({i: list(map(symbol, rows)) for i, rows in old['symbols'].items()} ==
        new['symbols'], 'ELF typed symbol or ordinal changed')
    renamed = {}
    for name, row in old['relocations'].items():
        renamed[name] = (*row[:-1], [(offset, typ, addend, symbol(sym)) for offset, typ, addend, sym in row[-1]])
    require(renamed == new['relocations'], 'ELF relocation referent changed')
    return dict(cpu=old['machine'], data_sections=len(old['ordinary']),
        relocations=sum(len(row[-1]) for row in old['relocations'].values()),
        before_sha256=hashlib.sha256(Path(before).read_bytes()).hexdigest(),
        after_sha256=hashlib.sha256(Path(after).read_bytes()).hexdigest(),
        status='all_data_bytes_typed_symbols_and_relocations_preserved')
