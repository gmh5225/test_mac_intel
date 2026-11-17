"""Diagnostic-only replacement of a shorter function; never a production ELF."""
from collections import Counter
import hashlib
import re
import struct
import subprocess as sp


def make(payloads, exes, save, work):
    def image(data):
        assert data[:6] == b'\x7fELF\x02\x01'
        phoff = struct.unpack_from('<Q', data, 32)[0]
        entsize, count = struct.unpack_from('<HH', data, 54)
        assert entsize == 56
        segments = []
        for i in range(count):
            kind, flags, offset, address, physical, filesz, memsz, align = struct.unpack_from(
                '<IIQQQQQQ', data, phoff + i * entsize)
            if kind == 1:
                segments.append(dict(flags=flags, offset=offset, address=address,
                                     filesz=filesz, memsz=memsz, align=align))
        return segments

    def symbols(exe):
        result = {}
        for line in sp.check_output(['nm', '-n', '-S', '--defined-only', exe], text=True).splitlines():
            fields = line.split(maxsplit=3)
            if len(fields) == 4 and fields[2] in ('t', 'T'):
                result.setdefault(fields[3], []).append([int(fields[0], 16), int(fields[1], 16)])
        return result

    def instructions(exe):
        text = sp.check_output(['objdump', '-d', '--disassemble=X86_reg_access', exe], text=True)
        assert '(%rip)' not in text
        result = []
        for line in text.splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*([a-z][a-z0-9]*)\s+(.*)$', line)
            if match and (match[2].startswith('j') or match[2].startswith('call')):
                target = re.fullmatch(r'([0-9a-f]+) <(.+)>', match[3].strip())
                assert target is not None, line
                result.append(dict(address=int(match[1], 16), opcode=match[2],
                                   target=int(target[1], 16), name=target[2]))
        assert result
        return result

    base, candidate = payloads['integer'], payloads['scan']
    base_segments, candidate_segments = image(base), image(candidate)
    old, new = symbols(exes['integer']), symbols(exes['scan'])
    target = 'X86_reg_access'
    assert old.keys() == new.keys() and len(old[target]) == len(new[target]) == 1
    address, old_size = old[target][0]
    candidate_address, size = new[target][0]
    assert address == candidate_address and 0 < size < old_size
    end = min(v[0] for group in old.values() for v in group if v[0] > address)

    def offset(segments, length):
        segment, = [x for x in segments if x['flags'] & 1 and
                    x['address'] <= address and address + length <= x['address'] + x['filesz']]
        return segment['offset'] + address - segment['address']

    old_offset, new_offset = offset(base_segments, old_size), offset(candidate_segments, size)
    old_instructions, new_instructions = instructions(exes['integer']), instructions(exes['scan'])
    calls = {(x['name'], x['target']) for x in old_instructions if x['opcode'].startswith('call')}
    for insn in new_instructions:
        if insn['opcode'].startswith('call'):
            assert (insn['name'], insn['target']) in calls, insn
        else:
            assert address <= insn['target'] < address + size, insn
    patched = bytearray(base)
    patched[old_offset:old_offset + size] = candidate[new_offset:new_offset + size]
    patched = bytes(patched)
    assert patched != base
    assert patched[:old_offset] == base[:old_offset]
    assert patched[old_offset + size:] == base[old_offset + size:]
    assert image(patched) == base_segments
    payloads['patch'], payloads['twin'] = patched, base
    for label in ('patch', 'twin'):
        exes[label] = work / label
        exes[label].write_bytes(payloads[label])
        exes[label].chmod(0o755)
    save('image-difference-control.json', dict(
        diagnostic_only=True, candidate_source='Exact R1327 countdown-pointer candidate',
        function=target, address=address, baseline_size=old_size, candidate_size=size,
        slot_bytes=end - address, copied_bytes=size,
        relative_targets_validated=True, source_candidate_targets=new_instructions,
        source_symbol_shift_histogram=dict(Counter(new[k][0][0] - old[k][0][0] for k in old)),
        source_load_segments_equal=base_segments == candidate_segments,
        patched_bytes_only_inside_function_slot=True, all_other_patched_bytes_unchanged=True,
        changed_function_bytes=sum(a != b for a, b in zip(base[old_offset:old_offset + size],
                                                        patched[old_offset:old_offset + size])),
        load_segments=base_segments,
        hashes={k: hashlib.sha256(v).hexdigest() for k, v in payloads.items()},
        note='The patched baseline retains its original unwind/build metadata; no exception or unwinding is part of the timed workload. This ELF is diagnostic only. Source-built layout effects are measured separately.'))
