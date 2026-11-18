from pathlib import Path
import hashlib
import re
import subprocess as sp

from elftools.elf.elffile import ELFFile


def make_bypass(source, target):
    source, target = Path(source), Path(target)
    original = source.read_bytes()
    with source.open('rb') as f:
        elf = ELFFile(f)
        table = elf.get_section_by_name('.symtab')
        generic, = table.get_symbol_by_name('X86_trySimpleOutput')
        selector, = table.get_symbol_by_name('X86_tryModeSimpleOutput')
        iterator, = table.get_symbol_by_name('X86_disasmIter')
        address = generic['st_value']
        assembly = sp.check_output(['objdump', '-d', '--disassemble=X86_disasmIter', source], text=True)
        calls = [int(m[1], 16) for m in re.finditer(
            r'^\s*([0-9a-f]+):.*\bcallq?\s+[^\n]*<X86_tryModeSimpleOutput>', assembly, re.M)]
        assert len(calls) == 1, calls
        pc, = calls
        assert iterator['st_value'] <= pc < iterator['st_value'] + iterator['st_size']
        segment, = [seg for seg in elf.iter_segments() if seg['p_type'] == 'PT_LOAD'
                    and seg['p_vaddr'] <= pc and pc + 5 <= seg['p_vaddr'] + seg['p_filesz']]
        offset = segment['p_offset'] + pc - segment['p_vaddr']
        assert original[offset] == 0xe8
        old_target = pc + 5 + int.from_bytes(original[offset + 1:offset + 5], 'little', signed=True)
        assert old_target == selector['st_value']
        modified = bytearray(original)
        modified[offset + 1:offset + 5] = int(address - pc - 5).to_bytes(4, 'little', signed=True)
    changed = [i for i, (a, b) in enumerate(zip(original, modified)) if a != b]
    assert changed and set(changed) <= set(range(offset + 1, offset + 5))
    assert len(original) == len(modified)
    target.write_bytes(modified)
    target.chmod(source.stat().st_mode)
    after = sp.check_output(['objdump', '-d', '--disassemble=X86_disasmIter', target], text=True)
    assert re.search(r'^\s*' + format(pc, 'x') + r':.*\bcallq?\s+[^\n]*<X86_trySimpleOutput>', after, re.M)
    before_symbols = sp.check_output(['nm', '-n', '-S', '--defined-only', source])
    after_symbols = sp.check_output(['nm', '-n', '-S', '--defined-only', target])
    assert before_symbols == after_symbols
    digest = lambda data: hashlib.sha256(data).hexdigest()
    return dict(passed=True, call_pc=pc, file_offset=offset, original_target=old_target,
                replacement_target=address, modified_byte_offsets=changed,
                all_other_bytes_identical=True, all_symbols_identical=True,
                before_sha256=digest(original), after_sha256=digest(modified),
                purpose='Diagnostic placement-preserving bypass only; not a runtime source or publication candidate.')
