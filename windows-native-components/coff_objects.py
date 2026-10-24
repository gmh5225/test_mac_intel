"""Typed COFF/BigObj symbol renaming without moving linker-visible records.

Format references: Microsoft PE/COFF specification and LLVM 23.1.1's
llvm/{BinaryFormat,Object}/COFF.h. No PE, import objects or bitcode admitted.
"""
from pathlib import Path
import hashlib
import re
import struct


class ObjectError(ValueError): pass


def require(condition, message):
    if not condition: raise ObjectError(message)


def parse(raw):
    require(len(raw) <= 512 * 1024 * 1024, 'COFF object exceeds bound')
    def span(offset, size):
        require(0 <= offset <= len(raw) and 0 <= size <= len(raw) - offset, 'COFF range outside file')
        return raw[offset:offset + size]
    def at(fmt, offset): return struct.unpack(fmt, span(offset, struct.calcsize(fmt)))
    first, second = at('<HH', 0)
    big = first == 0 and second == 0xffff
    if big:
        sig1, sig2, version, machine, stamp, uuid, a, b, c, d, count, symoff, nsyms = at('<HHHHI16s7I', 0)
        require(version == 2 and uuid == bytes.fromhex('c7a1bad1eebaa94baf20faf66aa4dcb8') and a == b == c == d == 0, 'Unsupported BigObj header')
        header_size, width, flags = 56, 20, 0
    else:
        machine, count, stamp, symoff, nsyms, optional, flags = at('<HHIIIHH', 0)
        require(optional == 0 and count <= 65279, 'Expected ordinary relocatable COFF')
        header_size, width = 20, 18
    require(machine in [0x8664, 0xaa64] and 0 < count <= 1000000 and 0 < nsyms <= 4000000, 'Unsupported COFF machine/count')
    require(symoff >= header_size + 40 * count, 'COFF symbols overlap section headers')
    span(symoff, nsyms * width)
    strings_at = symoff + nsyms * width; strings_size, = at('<I', strings_at)
    require(strings_size >= 4 and strings_at + strings_size == len(raw), 'COFF string table or unclassified trailer')
    strings = span(strings_at, strings_size)
    def string(offset):
        require(4 <= offset < len(strings), 'COFF name offset outside string table')
        end = strings.find(b'\0', offset); require(end >= offset, 'Unterminated COFF name')
        return strings[offset:end].decode('latin1')
    def section_name(value):
        value = value.split(b'\0', 1)[0]
        if value.startswith(b'//'):
            alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
            offset = 0
            for char in value[2:]:
                require(char in alphabet, 'Invalid COFF base64 section-name offset')
                offset = offset * 64 + alphabet.index(char)
            return string(offset)
        if value.startswith(b'/'):
            require(value[1:].isdigit(), 'Invalid COFF section-name offset')
            return string(int(value[1:]))
        return value.decode('latin1')
    sections = []
    for index in range(count):
        name, virtual, address, size, data, relocs, lines, nreloc, nline, attrs = at('<8sIIIIIIHHI', header_size + 40 * index)
        require(nline == 0 and lines == 0, 'Legacy COFF line tables are not admitted')
        require(virtual == address == 0, 'Unexpected COFF object virtual address')
        zero = bool(attrs & 0x80) and data == 0
        body = None if zero else span(data, size)
        if size and not zero: require(data >= header_size + 40 * count and data + size <= symoff, 'COFF section overlaps metadata')
        sentinel = None; total = nreloc
        if attrs & 0x1000000:
            require(nreloc == 0xffff, 'Invalid extended COFF relocation flag')
            sentinel = at('<IIH', relocs); total = sentinel[0]
            require(total > 0xffff and sentinel[1:] == (0, 0), 'Invalid COFF relocation overflow sentinel')
        elif nreloc == 0: require(relocs == 0, 'Unexpected empty COFF relocation table')
        span(relocs, total * 10)
        if total: require(relocs >= header_size + 40 * count and relocs + total * 10 <= symoff, 'COFF relocations overlap metadata')
        records = [at('<IIH', relocs + i * 10) for i in range(1 if sentinel else 0, total)]
        # CLR TOKEN and AMD64 span/PAIR records have different referent rules;
        # they are outside the admitted native C/C++ source-object contract.
        valid_types = set(range(0x12)) - {0x0c} if machine == 0xaa64 else set(range(0x0d))
        require(all(kind in valid_types and offset < size for offset, symbol, kind in records), 'Unsupported COFF relocation kind/address')
        sections.append(dict(index=index + 1, name=section_name(name), virtual=virtual, address=address, size=size, data_offset=data,
            reloc_offset=relocs, attrs=attrs, body=body, sentinel=sentinel, relocations=records))
    symbols = []; ordinal = 0; main_indices = set()
    while ordinal < nsyms:
        offset = symoff + width * ordinal
        name, value, owner, kind, storage, aux_count = at('<8sIiHBB' if big else '<8sIHHBB', offset)
        if not big and owner >= 0xfffe: owner -= 0x10000
        require(-2 <= owner <= count and ordinal + aux_count < nsyms, 'Invalid COFF symbol section/auxiliary count')
        actual = string(struct.unpack_from('<I', name, 4)[0]) if name[:4] == b'\0\0\0\0' else name.split(b'\0', 1)[0].decode('latin1')
        aux = span(offset + width, width * aux_count)
        if aux_count:
            if storage == 103: require(owner == -2 and kind == 0, 'Invalid COFF file auxiliary record')
            elif storage == 3:
                require(aux_count == 1 and owner > 0 and kind == 0 and actual == sections[owner - 1]['name'], 'Unknown static COFF auxiliary metadata')
                length, nr, nl, checksum, low, selection, unused, high = struct.unpack_from('<IHHIHBBH', aux)
                require(0 <= selection <= 7 and unused == 0 and nl == 0, 'Invalid COFF COMDAT auxiliary fields')
                if selection == 5: require(1 <= low + (high << 16) <= count, 'Invalid associated COFF section')
            elif storage == 105: require(aux_count == 1 and owner == 0 and struct.unpack_from('<I', aux, 4)[0] in [1, 2, 3, 4], 'Invalid COFF weak external')
            else: raise ObjectError('Unsupported COFF auxiliary symbol class: ' + str(storage))
        symbols.append(dict(index=ordinal, name=actual, value=value, owner=owner, type=kind, storage=storage, aux_count=aux_count, aux=aux, name_offset=offset))
        main_indices.add(ordinal); ordinal += aux_count + 1
    require(ordinal == nsyms, 'COFF symbol table ends in an auxiliary record')
    for row in symbols:
        if row['storage'] == 105: require(row['aux_count'] == 1 and struct.unpack_from('<I', row['aux'])[0] in main_indices, 'Invalid weak COFF fallback symbol')
    for section in sections:
        require(all(symbol in main_indices for _, symbol, _ in section['relocations']), 'COFF relocation does not name a primary symbol')
        if section['name'] == '.llvm_addrsig':
            value = shift = 0
            for char in section['body']:
                require(shift < 35, 'Oversized COFF addrsig ordinal'); value |= (char & 127) << shift
                if char & 128: shift += 7
                else:
                    require(value in main_indices, 'Invalid COFF addrsig primary symbol'); value = shift = 0
            require(shift == 0, 'Truncated COFF addrsig ordinal')
    return dict(identity=(big, machine, stamp, flags), header_size=header_size, symbol_width=width, symoff=symoff, nsyms=nsyms,
        strings_at=strings_at, strings=strings, sections=sections, symbols=symbols)


def validate_mapping(parsed, mapping):
    require(len(set(mapping.values())) == len(mapping), 'Noninjective COFF rename map')
    require(all(re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', old) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', new) for old, new in mapping.items()), 'Only exact C external names may be renamed')
    existing = {r['name'] for r in parsed['symbols'] if r['storage'] in [2, 105]}
    require(not set(mapping.values()) & existing, 'Private COFF name collides with an existing external')
    for section in parsed['sections']:
        if section['name'] == '.drectve':
            directives = section['body'].decode('latin1')
            require(not any(re.search(r'(?<![A-Za-z0-9_?@$.])' + re.escape(name) + r'(?![A-Za-z0-9_?@$.])', directives) for name in mapping), 'COFF linker directive references a renamed external')
def rename_bytes(raw, mapping):
    parsed = parse(raw); validate_mapping(parsed, mapping)
    prefix = bytearray(raw[:parsed['strings_at']]); table = bytearray(parsed['strings']); added = {}
    for row in parsed['symbols']:
        if row['storage'] not in [2, 105] or row['name'] not in mapping: continue
        name = mapping[row['name']]
        if name not in added: added[name] = len(table); table.extend(name.encode('ascii') + b'\0')
        struct.pack_into('<II', prefix, row['name_offset'], 0, added[name])
    struct.pack_into('<I', table, 0, len(table))
    return bytes(prefix + table)


def compare_objects(before, after, mapping):
    raw, changed = Path(before).read_bytes(), Path(after).read_bytes(); a, b = parse(raw), parse(changed)
    validate_mapping(a, mapping)
    require(a['identity'] == b['identity'] and a['header_size'] == b['header_size'] and a['symbol_width'] == b['symbol_width'] and a['symoff'] == b['symoff'] and a['nsyms'] == b['nsyms'], 'COFF header identity/record positions changed')
    require(a['sections'] == b['sections'], 'COFF code/data, relocation or section ordinal changed')
    require(len(a['symbols']) == len(b['symbols']), 'COFF primary symbol count changed')
    for old, new in zip(a['symbols'], b['symbols']):
        expected = dict(old)
        if old['storage'] in [2, 105]: expected['name'] = mapping.get(old['name'], old['name'])
        require(expected == new, 'COFF symbol value/type/owner/order or auxiliary association changed')
    require(b['strings'][4:len(a['strings'])] == a['strings'][4:], 'Existing COFF string data changed')
    # Independently restrict physical changes to selected external-name records
    # and appended, mapped names. All gaps and unclassified bytes stay exact.
    prefix = bytearray(changed[:a['strings_at']])
    for row in a['symbols']:
        if row['storage'] in [2, 105] and row['name'] in mapping:
            prefix[row['name_offset']:row['name_offset'] + 8] = raw[row['name_offset']:row['name_offset'] + 8]
    require(bytes(prefix) == raw[:a['strings_at']], 'Bytes outside named COFF symbol records changed')
    tail = b['strings'][len(a['strings']):]
    require(not tail or tail.endswith(b'\0') and set(tail[:-1].decode('ascii').split('\0')) <= set(mapping.values()), 'Unexpected appended COFF string data')
    return dict(status='COFF_all_code_data_relocations_symbol_ordinals_and_auxiliary_records_preserved', machine=a['identity'][1], bigobj=a['identity'][0],
        sections=len(a['sections']), primary_symbols=len(a['symbols']), relocations=sum(len(s['relocations']) for s in a['sections']),
        before_sha256=hashlib.sha256(raw).hexdigest(), after_sha256=hashlib.sha256(changed).hexdigest())
