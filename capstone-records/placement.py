"""Relink frozen diagnostic objects; never use this layout as a source fix."""
from pathlib import Path
import hashlib
import json
import re
import shutil
import struct
import subprocess as sp

def allocated_sections(path):
    data = path.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01'
    offset = struct.unpack_from('<Q', data, 40)[0]
    stride, count, names = struct.unpack_from('<HHH', data, 58)
    assert stride == 64
    headers = [struct.unpack_from('<IIQQQQIIQQ', data, offset+i*stride) for i in range(count)]
    strings = headers[names]
    strings = data[strings[4]:strings[4]+strings[5]]
    result = {}
    for row in headers:
        name = strings[row[0]:strings.index(0,row[0])].decode()
        if row[2] & 2:
            result[name] = dict(type=row[1],flags=row[2],size=row[5],alignment=row[8],
                sha256=hashlib.sha256(data[row[4]:row[4]+row[5]]).hexdigest())
    return result

def symbols(path):
    result = {}
    for line in path.read_text().splitlines():
        found = re.fullmatch(r'([0-9a-f]+) ([0-9a-f]+) (\S) (.+)',line)
        if found:
            result.setdefault(found[4],[]).append((int(found[1],16),int(found[2],16),found[3]))
    return result

def relocate(build, temporary, evidence, consumer, baseline_symbols, run):
    leaf = build/'CMakeFiles/capstone.dir/arch/X86/X86Vex32Output.c.o'
    original = allocated_sections(leaf)
    selected = [n for n,v in original.items() if v['size'] and v['type']==1 and v['flags'] & 2 and not v['flags'] & 5 and n != '.eh_frame']
    assert selected and all(n.startswith('.rodata') for n in selected),selected
    renamed = {name:'.cs_vex32_control_data'+name for name in selected}
    folder = temporary/'placement-object';folder.mkdir()
    changed = folder/leaf.name
    run(['objcopy',*['--rename-section='+name+'='+target for name,target in renamed.items()],leaf,changed],'rename-added-constants')
    after = allocated_sections(changed)
    assert {renamed.get(k,k):v for k,v in original.items()} == after
    library = temporary/'placed.a'
    shutil.copyfile(build/'libcapstone.a',library)
    members = sp.check_output(['ar','t',library])
    run(['ar','r',library,changed],'replace-only-added-object')
    assert sp.check_output(['ar','t',library]) == members
    # Give the appended executable area its own page. No writable executable
    # load segment is permitted; all original source/code bytes remain frozen.
    script = temporary/'placement.ld'
    script.write_text('SECTIONS {\n'
        ' .cs_vex32_control_text ALIGN(CONSTANT(COMMONPAGESIZE)) : { *(.cs_x86_vex32_output) }\n'
        ' .cs_vex32_control_data : { *(.cs_vex32_control_data*) }\n'
        '} INSERT AFTER .bss;\n')
    shutil.copyfile(script,evidence/'placement.ld')
    target = temporary/'placed'
    run(['clang++',consumer,library,'-Wl,-T,'+str(script),'-lm','-o',target],'link-placement-control')
    for kind,command in [('symbols',['nm','-n','-S','--defined-only']),('sections',['readelf','-WS']),('segments',['readelf','-Wl'])]:
        (evidence/('placed-'+kind+'.txt')).write_bytes(sp.check_output([*command,target]))
    loads = [line for line in (evidence/'placed-segments.txt').read_text().splitlines() if line.strip().startswith('LOAD')]
    assert loads and not any('W' in ''.join(line.split()[6:-1]) and 'E' in ''.join(line.split()[6:-1]) for line in loads),loads
    old,current = symbols(baseline_symbols),symbols(evidence/'placed-symbols.txt')
    preserved,remaining = [],[]
    for name,entries in old.items():
        if all(item in current.get(name,[]) for item in entries):preserved.append(name)
        else:remaining.append(dict(symbol=name,before=entries,after=current.get(name)))
    # Fail instead of timing a control that does not restore the boundaries
    # implicated by the mixed-architecture measurement.
    watched = ['cs_disasm_iter','X86_disasmIter','map_set_aarch64_alias_id','map_set_alias_id_trie_impl','map_set_mips_alias_id']
    assert all(old[name]==current[name] for name in watched),[x for x in remaining if x['symbol'] in watched]
    backend_tables = [name for name,entries in old.items() if name.startswith(('ARM','AArch64','Mips')) and all(x[2].lower()=='r' for x in entries)]
    assert backend_tables and all(old[name]==current[name] for name in backend_tables)
    report = dict(complete=True,source_runtime_changed=False,original_allocated_sections=original,
        renaming=renamed,all_allocated_section_bytes_flags_alignment_preserved=True,
        original_archive_member_order_preserved=True,restored_backend_readonly_symbols=len(backend_tables),
        original_symbols_preserved=len(preserved),remaining_symbol_differences=remaining,
        load_segments=loads,no_writable_executable_segment=True,
        limitations='Diagnostic link layout; unwind metadata and ELF segment geometry are reported, not a production proposal or hardware cache explanation.')
    (evidence/'placement-control.json').write_text(json.dumps(report,indent=2)+'\n')
    return target
