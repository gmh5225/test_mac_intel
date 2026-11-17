"""Diagnostic-only, equal-length counter-instruction replacement."""
from pathlib import Path
import hashlib
import re
import struct
import subprocess as sp


def make(payloads, exes, save, work, source_key, prefix):
    source = payloads[source_key]
    assert source[:6] == b'\x7fELF\x02\x01'
    rows = []
    for line in sp.check_output(['nm', '-n', '-S', '--defined-only', exes[source_key]], text=True).splitlines():
        fields = line.split()
        if len(fields) == 4 and fields[3] == 'X86_reg_access':
            rows.append((int(fields[0], 16), int(fields[1], 16)))
    (address, size), = rows
    assembly = sp.check_output(['objdump', '-d', '--disassemble=X86_reg_access', exes[source_key]], text=True)
    matches = list(re.finditer(r'^\s*([0-9a-f]+):\s+fe c8\s+dec\s+%al\s*$', assembly, re.M))
    assert len(matches) == 1, assembly
    instruction_address = int(matches[0][1], 16)
    assert address <= instruction_address < address + size - 8
    before = assembly[:matches[0].start()]
    after = assembly[matches[0].end():]
    assert re.search(r'movzbl\s+[^\n]+,%eax', before)
    assert re.search(r'test\s+%al,%al', before)
    # The conditional branch consumes ZF; no flags consumer lies between them.
    first_line = next(line for line in after.splitlines() if line.strip())
    assert re.search(r'\bje\s', first_line), first_line
    phoff = struct.unpack_from('<Q', source, 32)[0]
    entsize, count = struct.unpack_from('<HH', source, 54)
    assert entsize == 56
    offsets = []
    for i in range(count):
        kind, flags, off, addr, _, filesz, _, _ = struct.unpack_from('<IIQQQQQQ', source, phoff + i * entsize)
        if kind == 1 and flags & 1 and addr <= instruction_address < addr + filesz - 8:
            offsets.append(off + instruction_address - addr)
    offset, = offsets
    assert source[offset:offset + 4] == bytes.fromhex('fe c8 0f 84')
    variants = {}
    for label, opcode, mnemonic in [('dec32', 'ff c8', 'dec'), ('sub8', '2c 01', 'sub')]:
        replacement = bytes.fromhex(opcode)
        data = source[:offset] + replacement + source[offset + 2:]
        changed = [i for i, (a, b) in enumerate(zip(source, data)) if a != b]
        assert len(data) == len(source) and set(changed) <= {offset, offset + 1}
        assert len(changed) == (1 if label == 'dec32' else 2)
        target = Path(work) / (prefix + '-' + label + ('.so' if prefix == 'library' else ''))
        target.write_bytes(data)
        target.chmod(0o755)
        new_assembly = sp.check_output(['objdump', '-d', '--disassemble=X86_reg_access', target], text=True)
        line, = [v for v in new_assembly.splitlines() if re.match(r'\s*' + format(instruction_address, 'x') + r':', v)]
        assert re.search(r'\b' + mnemonic + r'\s', line)
        assert ('%eax' if label == 'dec32' else '$0x1,%al') in line, line
        payloads[label], exes[label] = data, target
        variants[label] = dict(sha256=hashlib.sha256(data).hexdigest(), replacement=opcode,
                               changed_offsets=changed, disassembly=line.strip(),
                               bytes_outside_instruction_identical=True)
    save(prefix + '-counter-control.json', dict(
        diagnostic_only=True, function='X86_reg_access', source=source_key,
        source_sha256=hashlib.sha256(source).hexdigest(), function_address=address,
        function_size=size, instruction_address=instruction_address, file_offset=offset,
        original='fe c8', zero_extended_counter_observed=True,
        next_instruction=first_line.strip(), variants=variants,
        semantic_scope='Count starts from zero-extended 8-bit op_count; the loop is skipped at zero and exits at zero after decrement. Shared-library variants must pass the full register-output differential probe before timing. Neither variant changes instruction sizes, addresses, branch targets, stack usage or unwind information.'))
