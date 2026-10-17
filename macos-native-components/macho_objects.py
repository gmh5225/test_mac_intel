"""Verify Mach-O object renaming against linker-visible bytes and references.

The supported inputs are little-endian 64-bit x86_64/arm64 MH_OBJECT files.
Definitions follow Apple's mach-o/{loader,nlist,reloc}.h. Unknown object
metadata is rejected instead of being omitted from the comparison.
"""
from collections import Counter
from pathlib import Path
import hashlib
import json
import struct


class ObjectError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ObjectError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(path, renames=None):
    path = Path(path)
    require(path.stat().st_size <= 512 * 1024 * 1024, 'Object exceeds size bound')
    body = path.read_bytes()
    renames = renames or {}

    def span(offset, size):
        require(0 <= offset <= len(body) and 0 <= size <= len(body) - offset,
                'Object range is outside the file')
        return body[offset:offset + size]

    def unpack(fmt, offset):
        return struct.unpack(fmt, span(offset, struct.calcsize(fmt)))

    def name(raw):
        return raw.split(b'\0', 1)[0].decode('latin1')

    header = unpack('<8I', 0)
    magic, cpu, subtype, kind, count, command_bytes, flags, reserved = header
    require(magic == 0xfeedfacf and kind == 1, 'Expected 64-bit little-endian MH_OBJECT')
    require(cpu in (0x01000007, 0x0100000c), 'Unsupported Mach-O CPU')
    require(count <= 256 and command_bytes <= len(body) - 32, 'Invalid load-command bounds')
    sections, commands, segments = [], [], []
    symtab = dysymtab = None
    cursor = 32
    for _ in range(count):
        command, size = unpack('<II', cursor)
        require(size >= 8 and size % 8 == 0 and cursor + size <= 32 + command_bytes,
                'Invalid load-command size')
        payload = span(cursor, size)
        if command == 0x19:  # LC_SEGMENT_64
            require(size >= 72, 'Truncated segment')
            seg, vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects, segflags = unpack('<16sQQQQiiII', cursor + 8)
            require(size == 72 + 80 * nsects and len(sections) + nsects <= 255,
                    'Invalid segment section table')
            span(fileoff, filesize)
            segments.append((name(seg), vmaddr, vmsize, maxprot, initprot, nsects, segflags))
            for index in range(nsects):
                offset = cursor + 72 + index * 80
                row = unpack('<16s16sQQ8I', offset)
                sect, owner, addr, length, dataoff, align, reloff, nreloc, attrs, r1, r2, r3 = row
                require(align <= 31 and nreloc <= 4_000_000, 'Invalid section bounds')
                span(reloff, nreloc * 8)
                zero = (attrs & 0xff) in (1, 12, 18)
                data = None if zero else digest(span(dataoff, length))
                sections.append(dict(key=(name(owner), name(sect)), addr=addr, size=length,
                    offset=dataoff, align=align, attrs=attrs, reserved=(r1, r2, r3),
                    data=data, relocation_offset=reloff, relocation_count=nreloc))
        elif command == 2:  # LC_SYMTAB
            require(symtab is None and size == 24, 'Duplicate or invalid symbol table')
            symtab = unpack('<4I', cursor + 8)
        elif command == 0xb:  # LC_DYSYMTAB
            require(dysymtab is None and size == 80, 'Duplicate or invalid dynamic symbol table')
            dysymtab = unpack('<18I', cursor + 8)
        elif command in (0x29, 0x2e):  # LC_DATA_IN_CODE, LC_LINKER_OPTIMIZATION_HINT
            require(size == 16, 'Invalid link-edit data command')
            dataoff, datasize = unpack('<II', cursor + 8)
            commands.append((command, span(dataoff, datasize)))
        elif command in (0x24, 0x2a, 0x2d, 0x32):
            # Version, source version, linker options and build-version metadata.
            commands.append((command, payload))
        else:
            raise ObjectError('Unsupported object load command: ' + hex(command))
        cursor += size
    require(cursor == 32 + command_bytes and len(segments) == 1, 'Unexpected object layout')
    require(len({s['key'] for s in sections}) == len(sections), 'Ambiguous section identity')
    if symtab is None:
        # Apple Clang emits valid empty translation units without LC_SYMTAB.
        # There must be no metadata that could reference an absent table.
        require(dysymtab is None and not any(s['relocation_count'] for s in sections),
                'Missing symbol table with object references')
        symoff, nsyms, stroff, strsize = len(body), 0, len(body), 0
    else:
        symoff, nsyms, stroff, strsize = symtab
    require(nsyms <= 2_000_000, 'Symbol count exceeds bound')
    span(symoff, 16 * nsyms)
    strings = span(stroff, strsize)
    require((strings and strings[0] == 0) or (not nsyms and not strsize), 'Invalid string table')

    def symbol_name(offset):
        require(offset < len(strings), 'Symbol name is outside string table')
        end = strings.find(b'\0', offset)
        require(end >= 0, 'Unterminated symbol name')
        raw = strings[offset:end].decode('latin1')
        return renames.get(raw, raw)

    def section_key(ordinal):
        require(1 <= ordinal <= len(sections), 'Invalid section ordinal')
        return sections[ordinal - 1]['key']

    symbols = []
    for index in range(nsyms):
        strx, typ, ordinal, desc, value = unpack('<IBBHQ', symoff + 16 * index)
        owner = section_key(ordinal) if ordinal else None
        if not typ & 0xe0:
            basic = typ & 0x0e
            require(basic in (0, 2, 0xa, 0xc, 0xe), 'Unsupported symbol type')
            if basic == 0xe:
                require(ordinal != 0, 'Section symbol has no section')
                section = sections[ordinal - 1]
                require(section['addr'] <= value <= section['addr'] + section['size'],
                        'Symbol value is outside its section')
                value = ('section_offset', value - section['addr'])
            elif basic == 0xa:  # N_INDR: value is a string-table reference.
                value = ('indirect_name', symbol_name(value))
            else:
                require(ordinal == 0, 'Non-section symbol has a section')
                value = ('value', value)
        else:
            value = ('debug_value', value)
        symbols.append((symbol_name(strx), typ, owner, desc, value))

    def symbol(index):
        require(index < len(symbols), 'Reference is outside symbol table')
        return symbols[index]

    linked_sections = []
    relocation_count = 0
    for section in sections:
        relocations = []
        for index in range(section['relocation_count']):
            address, word = unpack('<iI', section['relocation_offset'] + 8 * index)
            require(address >= 0, 'Scattered/negative relocations are unsupported')
            number, pcrel, length, external, typ = word & 0xffffff, (word >> 24) & 1, (word >> 25) & 3, (word >> 27) & 1, word >> 28
            require(typ <= (11 if cpu == 0x0100000c else 9), 'Unsupported relocation type')
            require(address + (1 << length) <= section['size'], 'Relocation exceeds section')
            if cpu == 0x0100000c and typ == 10:  # ARM64_RELOC_ADDEND
                require(not external and not pcrel and length == 2, 'Invalid ARM64 addend relocation')
                target = ('explicit_addend', number - (1 << 24) if number & (1 << 23) else number)
                require(index + 1 < section['relocation_count'], 'Unpaired ARM64 addend')
                next_address, next_word = unpack('<iI', section['relocation_offset'] + 8 * (index + 1))
                require(next_address == address and next_word >> 28 in (2, 3, 4), 'Invalid ARM64 addend pair')
            elif external:
                target = ('symbol', symbol(number))
            else:
                target = ('section', section_key(number)) if number else ('absolute',)
            relocations.append((address, typ, pcrel, length, external, target))
        relocation_count += len(relocations)
        # Debug sections are compared as well; no section body is omitted.
        linked_sections.append((section['key'], section['addr'], section['size'],
            section['align'], section['attrs'], section['reserved'], section['data'], tuple(relocations)))

    def multiset(items):
        return tuple(sorted(Counter(json.dumps(s, separators=(',', ':')) for s in items).items()))

    dynamic = None
    if dysymtab is not None:
        local, nlocal, defined, ndefined, undef, nundef = dysymtab[:6]
        # These tables belong to dynamic libraries, not relocatable objects.
        require(not any(dysymtab[i] for i in (7, 9, 11, 15, 17)), 'Unsupported dynamic object table')
        groups = []
        covered = set()
        for start, length in ((local, nlocal), (defined, ndefined), (undef, nundef)):
            require(start <= nsyms and length <= nsyms - start, 'Invalid symbol partition')
            indices = set(range(start, start + length))
            require(not covered & indices, 'Overlapping symbol partitions')
            covered.update(indices)
            groups.append(multiset(symbols[start:start + length]))
        require(len(covered) == nsyms, 'Unpartitioned symbols')
        indirectoff, nindirect = dysymtab[12:14]
        require(nindirect <= 2_000_000, 'Indirect symbol count exceeds bound')
        indirect = []
        for index in range(nindirect):
            entry, = unpack('<I', indirectoff + 4 * index)
            if entry & 0xc0000000:
                require(entry in (0x80000000, 0xc0000000), 'Unsupported indirect symbol marker')
                indirect.append(('marker', entry))
            else:
                indirect.append(('symbol', symbol(entry)))
        dynamic = (tuple(groups), tuple(indirect))

    def section_address(file_offset, length):
        matches = [s for s in sections if s['data'] is not None and
                   s['offset'] <= file_offset and file_offset + length <= s['offset'] + s['size']]
        require(len(matches) == 1, 'Link-edit address has no unique section')
        s = matches[0]
        return s['key'], file_offset - s['offset']

    metadata = []
    for command, data in commands:
        if command == 0x29:
            require(len(data) % 8 == 0, 'Invalid data-in-code table')
            entries = []
            for offset in range(0, len(data), 8):
                fileoff, length, kind = struct.unpack_from('<IHH', data, offset)
                entries.append((section_address(fileoff, length), length, kind))
            metadata.append((command, tuple(entries)))
        else:
            metadata.append((command, digest(data)))
    result = dict(header=(cpu, subtype, flags, reserved), segments=tuple(segments),
                  sections=tuple(linked_sections), symbols=multiset(symbols),
                  dynamic_symbols=dynamic, metadata=tuple(metadata))
    return result, dict(cpu=cpu, sections=len(sections), symbols=len(symbols), relocations=relocation_count)


def compare_objects(before, after, renames):
    require(all(isinstance(a, str) and isinstance(b, str) and a != b for a, b in renames.items()),
            'Invalid symbol rename')
    require(len(set(renames.values())) == len(renames) and not set(renames) & set(renames.values()),
            'Ambiguous symbol rename')
    original, counts = canonical(before, renames)
    rewritten, actual_counts = canonical(after)
    for key in original:
        require(original[key] == rewritten[key], 'Mach-O rename changed ' + key)
    require(counts == actual_counts, 'Mach-O object counts changed')
    return dict(status='all_section_bytes_symbols_and_relocations_equal_modulo_rename',
                before_sha256=digest(Path(before).read_bytes()), after_sha256=digest(Path(after).read_bytes()), **counts)
