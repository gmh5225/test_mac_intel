"""Diagnostic only: split long NOPs without moving any effective instruction."""
from pathlib import Path
import hashlib
import re
import struct
import subprocess as sp


NOPS = {
    1: '90', 2: '90 90', 3: '0f 1f 00', 4: '0f 1f 40 00',
    5: '0f 1f 44 00 00', 6: '66 0f 1f 44 00 00',
    7: '0f 1f 80 00 00 00 00', 8: '0f 1f 84 00 00 00 00 00',
}


def instructions(path):
    assembly = sp.check_output(['objdump', '-d', '--insn-width=16',
                               '--disassemble=X86_reg_access', path], text=True)
    rows = []
    for line in assembly.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(.*)$', line)
        if match:
            rows.append((int(match[1], 16), bytes.fromhex(match[2]), match[3]))
    assert rows
    return rows


def is_nop(text):
    return re.search(r'\bnop[lw]?\b', text) is not None


def make(payloads, exes, save, work, source_key, prefix):
    source = payloads[source_key]
    assert source[:6] == b'\x7fELF\x02\x01'
    symbols = []
    for line in sp.check_output(['nm', '-n', '-S', '--defined-only', exes[source_key]], text=True).splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[3] == 'X86_reg_access':
            symbols.append((int(fields[0], 16), int(fields[1], 16)))
    (address, size), = symbols
    rows = [row for row in instructions(exes[source_key])
            if address <= row[0] < address + size]
    assert rows and all(at + len(raw) <= address + size for at, raw, _ in rows)
    selected = [(at, raw, text) for at, raw, text in rows if len(raw) > 8 and is_nop(text)]
    assert selected and any(len(raw) >= 13 for _, raw, _ in selected)
    branches = [int(match[1], 16) for _, _, text in rows
                if (match := re.search(r'\b(?:j[a-z]+|call)\s+([0-9a-f]+)\b', text))]
    assert all(not any(at < target < at + len(raw) for target in branches)
               for at, raw, _ in selected)
    phoff = struct.unpack_from('<Q', source, 32)[0]
    entsize, count = struct.unpack_from('<HH', source, 54)
    assert entsize == 56
    segments = [struct.unpack_from('<IIQQQQQQ', source, phoff + i * entsize)
                for i in range(count)]

    def offset(at, length):
        matches = [off + at - addr for kind, flags, off, addr, _, filesz, _, _ in segments
                   if kind == 1 and flags & 1 and addr <= at and at + length <= addr + filesz]
        value, = matches
        return value

    variants = {}
    for label, maximum in [('nops8', 8), ('nops4', 4)]:
        data = bytearray(source)
        replacements = []
        allowed = set()
        for at, raw, text in selected:
            file_offset = offset(at, len(raw))
            assert source[file_offset:file_offset + len(raw)] == raw
            remaining = len(raw)
            replacement = b''
            while remaining:
                width = min(maximum, remaining)
                replacement += bytes.fromhex(NOPS[width])
                remaining -= width
            assert len(replacement) == len(raw)
            data[file_offset:file_offset + len(raw)] = replacement
            allowed.update(range(file_offset, file_offset + len(raw)))
            replacements.append(dict(address=at, file_offset=file_offset,
                                     before=raw.hex(' '), after=replacement.hex(' '),
                                     old_instruction=text))
        data = bytes(data)
        changed = [i for i, (old, new) in enumerate(zip(source, data)) if old != new]
        assert changed and set(changed) <= allowed and len(data) == len(source)
        target = Path(work) / (prefix + '-' + label + ('.so' if prefix == 'library' else ''))
        target.write_bytes(data)
        target.chmod(0o755)
        new_rows = [row for row in instructions(target)
                    if address <= row[0] < address + size]
        assert [(at, raw, text) for at, raw, text in rows if not is_nop(text)] == [
            (at, raw, text) for at, raw, text in new_rows if not is_nop(text)]
        for at, raw, text in new_rows:
            if any(start <= at < start + len(old) for start, old, _ in selected):
                assert is_nop(text) and len(raw) <= maximum
        payloads[label], exes[label] = data, target
        variants[label] = dict(sha256=hashlib.sha256(data).hexdigest(), replacements=replacements,
                               changed_offsets=changed, bytes_outside_padding_identical=True,
                               effective_instructions_and_addresses_identical=True,
                               maximum_replacement_instruction_bytes=maximum)
    save(prefix + '-nop-control.json', dict(
        diagnostic_only=True, function='X86_reg_access', source=source_key,
        source_sha256=hashlib.sha256(source).hexdigest(), function_address=address,
        function_size=size, original_long_nops=len(selected),
        no_interior_branch_targets=True, variants=variants,
        semantic_scope='Only long NOP encodings are split into bounded-width NOPs in the same byte intervals. All non-NOP instructions, their addresses, branch targets, function size, stack usage and unwind bytes remain identical. Shared-library variants must pass complete register-output comparisons before timing.'))
