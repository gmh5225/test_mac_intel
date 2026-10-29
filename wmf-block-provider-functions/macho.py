import bisect
import hashlib
import struct
import uuid


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounds(data, offset, size):
    assert 0 <= offset <= len(data) and 0 <= size <= len(data) - offset
    return data[offset:offset + size]


def cstring(data, offset):
    assert 0 <= offset < len(data)
    end = data.index(b'\0', offset)
    return data[offset:end]


class MachO:
    def __init__(self, data):
        self.whole_sha256 = digest(data)
        self.whole_size = len(data)
        self.architectures = []
        magic = struct.unpack_from('>I', bounds(data, 0, 4))[0]
        if magic in (0xcafebabe, 0xcafebabf):
            count = struct.unpack_from('>I', bounds(data, 4, 4))[0]
            stride = 20 if magic == 0xcafebabe else 32
            bounds(data, 8, count * stride)
            candidates = []
            for index in range(count):
                raw = bounds(data, 8 + stride * index, stride)
                if stride == 20:
                    cpu, subtype, offset, size, align = struct.unpack('>5I', raw)
                    reserved = None
                else:
                    cpu, subtype, offset, size, align, reserved = struct.unpack('>IIQQII', raw)
                bounds(data, offset, size)
                row = dict(cpu_type=cpu, cpu_subtype=subtype, offset=offset, size=size, align=align, reserved=reserved)
                self.architectures.append(row)
                if cpu == 0x100000c and subtype == 0:
                    candidates.append(row)
            assert len(candidates) == 1, 'Expected exactly one ordinary ARM64 slice'
            self.slice_offset = candidates[0]['offset']
            data = bounds(data, self.slice_offset, candidates[0]['size'])
        else:
            self.slice_offset = 0
        self.data = data
        self.slice_sha256 = digest(data)
        header = struct.unpack('<8I', bounds(data, 0, 32))
        assert header[0] == 0xfeedfacf and header[1] == 0x100000c and header[2] == 0
        self.header = dict(magic=header[0], cpu_type=header[1], cpu_subtype=header[2], filetype=header[3],
                           ncmds=header[4], sizeofcmds=header[5], flags=header[6], reserved=header[7])
        self.commands = []
        self.segments = []
        self.sections = []
        self.versions = []
        self.dependencies = []
        self.symbols = []
        self.function_starts = []
        self.uuid = None
        symtab = None
        dysymtab = None
        starts = None
        offset = 32
        command_end = 32 + header[5]
        bounds(data, 32, header[5])
        for index in range(header[4]):
            cmd, length = struct.unpack('<II', bounds(data, offset, 8))
            assert length >= 8 and offset + length <= command_end
            raw = bounds(data, offset, length)
            self.commands.append(dict(index=index, offset=offset, cmd=cmd, cmdsize=length, bytes_hex=raw.hex()))
            if cmd == 0x1b:
                assert length == 24 and self.uuid is None
                self.uuid = str(uuid.UUID(bytes=raw[8:24])).upper()
            elif cmd == 0x32:
                _, _, platform, minimum, sdk, tools = struct.unpack('<6I', bounds(raw, 0, 24))
                assert length == 24 + 8 * tools
                self.versions.append(dict(platform=platform, minos_bits=minimum, sdk_bits=sdk, ntools=tools))
            elif cmd == 0x19:
                fields = struct.unpack('<II16s4Q4I', bounds(raw, 0, 72))
                assert length == 72 + 80 * fields[9]
                name = fields[2].rstrip(b'\0').decode()
                segment = dict(name=name, vmaddr=fields[3], vmsize=fields[4], fileoff=fields[5], filesize=fields[6],
                               maxprot=fields[7], initprot=fields[8], nsects=fields[9], flags=fields[10])
                bounds(data, segment['fileoff'], segment['filesize'])
                self.segments.append(segment)
                for number in range(fields[9]):
                    section = struct.unpack('<16s16sQQ8I', bounds(raw, 72 + number * 80, 80))
                    self.sections.append(dict(index=len(self.sections) + 1, name=section[0].rstrip(b'\0').decode(),
                        segment=section[1].rstrip(b'\0').decode(), addr=section[2], size=section[3], offset=section[4],
                        align=section[5], reloff=section[6], nreloc=section[7], flags=section[8],
                        reserved1=section[9], reserved2=section[10], reserved3=section[11]))
            elif cmd == 0x2:
                assert symtab is None and length == 24
                symtab = struct.unpack('<6I', raw)
            elif cmd == 0xb:
                assert dysymtab is None and length == 80
                dysymtab = struct.unpack('<20I', raw)
            elif cmd == 0x26:
                assert starts is None and length == 16
                starts = struct.unpack('<4I', raw)
            elif cmd in (0xc, 0x80000018, 0x8000001f, 0x80000023):
                assert length >= 24
                name_offset, timestamp, current, compatibility = struct.unpack('<4I', raw[8:24])
                assert name_offset >= 24
                name = cstring(raw, name_offset)
                self.dependencies.append(dict(ordinal=len(self.dependencies) + 1, cmd=cmd,
                    path=name.decode(), timestamp=timestamp, current_version_bits=current,
                    compatibility_version_bits=compatibility))
            offset += length
        assert offset == command_end and self.uuid
        assert symtab is not None and starts is not None
        self.text = next(section for section in self.sections if section['name'] == '__text' and section['segment'] == '__TEXT')
        self.text_base = next(segment['vmaddr'] for segment in self.segments if segment['name'] == '__TEXT')
        assert self.text['size'] % 4 == 0
        self.text_bytes = bounds(data, self.text['offset'], self.text['size'])
        strings = bounds(data, symtab[4], symtab[5])
        symbols = bounds(data, symtab[2], symtab[3] * 16)
        self.symtab_identity = dict(offset=symtab[2], count=symtab[3], bytes_sha256=digest(symbols),
                                    string_offset=symtab[4], string_size=symtab[5], string_sha256=digest(strings))
        for number in range(symtab[3]):
            string_index, kind, section, descriptor, value = struct.unpack_from('<IBBHQ', symbols, number * 16)
            name = cstring(strings, string_index)
            self.symbols.append(dict(index=number, name=name.decode('utf-8', errors='backslashreplace'),
                name_hex=name.hex(), string_index=string_index, type=kind, section=section, descriptor=descriptor, value=value))
        raw_starts = bounds(data, starts[2], starts[3])
        self.raw_function_starts = raw_starts.hex()
        position = 0
        address = self.text_base
        terminated = False
        while position < len(raw_starts):
            value = 0
            shift = 0
            while True:
                assert position < len(raw_starts) and shift <= 63
                byte = raw_starts[position]
                position += 1
                assert shift < 63 or byte <= 1
                value |= (byte & 0x7f) << shift
                if not byte & 0x80:
                    break
                shift += 7
            if value == 0:
                assert not any(raw_starts[position:])
                terminated = True
                break
            address += value
            assert address <= (1 << 64) - 1
            assert not self.function_starts or address > self.function_starts[-1]
            self.function_starts.append(address)
        assert terminated
        self.indirect_symbols = []
        if dysymtab is not None:
            indirect = bounds(data, dysymtab[14], dysymtab[15] * 4)
            self.indirect_symbols = list(struct.unpack('<' + str(dysymtab[15]) + 'I', indirect))

    def function(self, address):
        assert address in self.function_starts
        assert self.text['addr'] <= address < self.text['addr'] + self.text['size']
        number = bisect.bisect_right(self.function_starts, address)
        end = self.text['addr'] + self.text['size']
        if number < len(self.function_starts):
            end = min(end, self.function_starts[number])
        assert address < end and (end - address) % 4 == 0
        code_offset = address - self.text['addr']
        code = bounds(self.text_bytes, code_offset, end - address)
        names = [symbol for symbol in self.symbols if symbol['value'] == address and symbol['type'] & 0x0e == 0x0e and not symbol['type'] & 0xe0]
        words = []
        branches = []
        dynamic = []
        for offset in range(0, len(code), 4):
            pc = address + offset
            word = struct.unpack_from('<I', code, offset)[0]
            words.append(dict(address=hex(pc), word_hex=f'{word:08x}'))
            if word & 0x7c000000 == 0x14000000:
                immediate = word & 0x3ffffff
                if immediate & 0x2000000:
                    immediate -= 0x4000000
                target = pc + 4 * immediate
                branches.append(dict(pc=hex(pc), word_hex=f'{word:08x}',
                    kind='BL' if word & 0x80000000 else 'B', target=hex(target), internal=address <= target < end,
                    target_identity=self.target(target)))
            elif word & 0xfffffc1f in (0xd61f0000, 0xd63f0000):
                dynamic.append(dict(pc=hex(pc), word_hex=f'{word:08x}', register=(word >> 5) & 31,
                                    kind='BLR' if word & 0x200000 else 'BR'))
        return dict(start=hex(address), end=hex(end), size=len(code), code_sha256=digest(code), code_hex=code.hex(),
                    symbol_records=names, words=words, direct_branches=branches, indirect_branches=dynamic)

    def target(self, target):
        for section in self.sections:
            if section['addr'] <= target < section['addr'] + section['size'] and section['flags'] & 0xff == 8:
                stride = section['reserved2']
                assert stride and (target - section['addr']) % stride == 0
                index = section['reserved1'] + (target - section['addr']) // stride
                assert index < len(self.indirect_symbols)
                symbol = self.indirect_symbols[index]
                row = dict(kind='symbol_stub', section=section['name'], stub_stride=stride,
                           indirect_index=index, raw_symbol_index=symbol)
                if not symbol & 0xc0000000:
                    assert symbol < len(self.symbols)
                    row['symbol'] = self.symbols[symbol]
                    ordinal = self.symbols[symbol]['descriptor'] >> 8
                    row['raw_ordinal'] = ordinal
                    row['declared_dependency'] = next((item for item in self.dependencies if item['ordinal'] == ordinal), None)
                return row
        if self.text['addr'] <= target < self.text['addr'] + self.text['size']:
            number = bisect.bisect_right(self.function_starts, target) - 1
            if number >= 0:
                return dict(kind='text_function_interval', function_start=hex(self.function_starts[number]),
                            exact_function_entry=self.function_starts[number] == target)
        return dict(kind='unresolved_external_address')

    def manifest(self):
        return dict(whole_file_sha256=self.whole_sha256, whole_file_bytes=self.whole_size,
                    fat_architectures=self.architectures, selected_slice_offset=self.slice_offset,
                    selected_slice_sha256=self.slice_sha256, selected_slice_bytes=len(self.data), header=self.header,
                    uuid=self.uuid, versions=self.versions, load_commands=self.commands,
                    segments=self.segments, sections=self.sections, dependencies=self.dependencies,
                    symtab_identity=self.symtab_identity, symbols=self.symbols,
                    raw_function_starts_hex=self.raw_function_starts, function_starts=[hex(value) for value in self.function_starts],
                    indirect_symbols=self.indirect_symbols)
