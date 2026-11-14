"""Freeze compiler output; pad only the changed object's trailing section bytes."""
from collections import Counter, defaultdict
from pathlib import Path
import hashlib
import json
import platform
import struct
import subprocess as sp
from frozen_layout import Layouts as Original, sha, symbols


def elf(path):
    data = path.read_bytes()
    header = list(struct.unpack_from('<16sHHIQQQIHHHHHH', data))
    assert header[0][:6] == b'\x7fELF\x02\x01' and header[1:3] == [1, 62]
    assert header[5] == header[10] == 0 and header[8] == header[11] == 64
    assert 0 < header[12] < 0xff00 and header[13] < header[12]
    sections = [list(struct.unpack_from('<IIQQQQIIQQ', data, header[6] + 64*i))
                for i in range(header[12])]
    strings = sections[header[13]]
    names = data[strings[4]:strings[4]+strings[5]]
    def name(s):
        end = names.index(b'\0', s[0])
        return names[s[0]:end].decode()
    return data, header, sections, [name(s) for s in sections]


def padded_object(source, target, requested):
    data, header, sections, names = elf(source)
    original = {name: data[s[4]:s[4]+s[5]] for name, s in zip(names, sections)
                if s[1] not in (0, 8)}
    chunks = bytearray(data[:64])
    for index, s in enumerate(sections):
        if s[1] == 0:
            continue
        align = max(1, s[8])
        assert align & (align-1) == 0
        chunks.extend(bytes((-len(chunks)) % align))
        body = b'' if s[1] == 8 else original[names[index]]
        s[4] = len(chunks)
        if names[index] in requested:
            size = requested[names[index]]
            assert names[index] in ('.text', '.rodata') and size >= len(body)
            assert s[1] == 1 and not s[2] & (16 | 32 | 2048)
            body += (b'\x90' if names[index] == '.text' else b'\0') * (size-len(body))
            s[5] = len(body)
        chunks.extend(body)
    chunks.extend(bytes((-len(chunks)) % 8))
    header[6] = len(chunks)
    for s in sections:
        chunks.extend(struct.pack('<IIQQQQIIQQ', *s))
    chunks[:64] = struct.pack('<16sHHIQQQIHHHHHH', *header)
    target.write_bytes(chunks)
    result, after, sections_after, names_after = elf(target)
    assert names_after == names and after[1:6] == header[1:6]
    for name, s in zip(names_after, sections_after):
        if s[1] in (0, 8):
            continue
        body = result[s[4]:s[4]+s[5]]
        if name in requested:
            assert body[:len(original[name])] == original[name]
        else:
            assert body == original[name], name
    assert symbols(source) == symbols(target), 'padding must preserve every original symbol'
    return dict(original=sha(source), padded=sha(target),
                sections={k: dict(original=len(original[k]), padded=v) for k,v in requested.items()},
                original_section_prefixes_preserved=True,
                other_section_bytes_including_symbols_and_relocations_preserved=True)


class Layouts(Original):
    def prepare(self, consumer, iced):
        assert set(self.objects) == {'integer', 'scan'}
        assert set(self.objects['integer']) == set(self.objects['scan'])
        assert self.records['integer']['consumer'] == self.records['scan']['consumer'] == sha(consumer)
        names = self.records['integer']['active_objects']
        changed = [n for n in names if self.records['integer']['objects'][n] != self.records['scan']['objects'][n]]
        assert changed == ['X86DisassemblerDecoder.c.o'], changed
        change = changed[0]
        self.payloads = {'archive': {k: v.read_bytes() for k,v in self.executables.items()}}
        sizes = defaultdict(list)
        for label in ('integer', 'scan'):
            data, header, sections, section_names = elf(self.objects[label][change])
            for n, s in zip(section_names, sections):
                if n in ('.text', '.rodata'):
                    sizes[n].append(s[5])
        assert set(sizes) == {'.text', '.rodata'} and all(len(v) == 2 for v in sizes.values())
        targets = {k: (max(v)+63)//64*64 for k,v in sizes.items()}
        all_names = Counter()
        common_names = set()
        for name in names:
            for address, size, kind, symbol in symbols(self.objects['integer'][name]):
                all_names[symbol] += 1
                if name != change and kind.lower() in ('t', 'r', 'd', 'b'):
                    common_names.add(symbol)
        common_names = {s for s in common_names if all_names[s] == 1}
        assert len(common_names) > 200
        checks, pads = {}, {}
        for layout in ('direct-control', 'text-padded', 'text-rodata-padded'):
            content, symbol_maps = {}, {}
            for label in ('integer', 'scan'):
                objects = [self.objects[label][name] for name in names]
                assert all(sha(o) == self.records[label]['objects'][o.name] for o in objects)
                if layout != 'direct-control':
                    replacement = self.work / (layout+'-'+label+'.o')
                    requested = {'.text': targets['.text']}
                    if layout == 'text-rodata-padded':
                        requested['.rodata'] = targets['.rodata']
                    pads[layout+'/'+label] = padded_object(self.objects[label][change], replacement, requested)
                    objects[names.index(change)] = replacement
                target = self.work / (layout+'-'+label)
                self.run(['clang++', consumer, *objects, iced, '-lpthread', '-ldl', '-lm', '-o', target],
                         'link-'+layout+'-'+label)
                current = symbols(target)
                original = symbols(self.executables[label])
                assert Counter((n,k,s) for a,n,k,s in current) == Counter((n,k,s) for a,n,k,s in original)
                symbol_maps[label] = {s: [a,n,k] for a,n,k,s in current if s in common_names or s == '_end'}
                (self.evidence/(layout+'-'+label+'-symbols.txt')).write_bytes(sp.check_output(['nm','-n','-S','--defined-only',target]))
                (self.evidence/(layout+'-'+label+'-sections.txt')).write_bytes(sp.check_output(['readelf','-WS',target]))
                content[label] = target.read_bytes()
                target.unlink()
            assert symbol_maps['integer'].keys() == symbol_maps['scan'].keys()
            differences = {s: dict(integer=symbol_maps['integer'][s], scan=symbol_maps['scan'][s])
                           for s in symbol_maps['integer'] if symbol_maps['integer'][s] != symbol_maps['scan'][s]}
            checks[layout] = dict(common_symbols_checked=len(symbol_maps['integer']), differences=differences,
                                  all_common_symbol_addresses_equal=not differences)
            if layout == 'direct-control':
                equal = {k: content[k] == self.payloads['archive'][k] for k in content}
                self.save('direct-control.json', dict(symbol_multisets_equal=True, byte_identical_to_archive=equal))
                assert all(equal.values()), equal
            else:
                self.payloads[layout] = content
        self.save('object-padding.json', dict(target_sizes=targets, transformations=pads))
        self.save('address-controls.json', checks)
        # Record imperfect address isolation; do not mislabel it as a successful control.
        self.maximum = max(len(v) for pair in self.payloads.values() for v in pair.values())
        for pair in self.payloads.values():
            for label, data in pair.items():
                pair[label] = data + bytes(self.maximum-len(data))
            pair['aa'] = pair['integer']
        self.image = self.work/'same-image'
        self.image.write_bytes(self.payloads['archive']['integer']); self.image.chmod(0o755)
        self.inode = self.image.stat().st_ino
        probe = sp.run(['setarch', platform.machine(), '-R', '/bin/true'], capture_output=True, text=True)
        assert probe.returncode == 0, probe.stderr
        self.save('layout-controls.json', dict(inode=self.inode, fixed_size=self.maximum, aslr_disabled=True,
                  consumer_sha256=sha(consumer), original_archive_preserved=True, same_active_objects=True,
                  layouts=list(self.payloads), cycles=21,
                  padded_sha256={layout:{name:hashlib.sha256(v).hexdigest() for name,v in pair.items()}
                                 for layout,pair in self.payloads.items()},
                  isolation_status=checks['text-rodata-padded']['all_common_symbol_addresses_equal'],
                  scope='Object-tail padding only; instructions, symbols, relocations preserved. Internal addresses inside the changed Decoder object are not held fixed.'))
