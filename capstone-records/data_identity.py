from pathlib import Path
import hashlib,json
from elftools.elf.elffile import ELFFile

def executable_sections(path):
    with Path(path).open('rb') as stream:
        elf=ELFFile(stream)
        return [(i,section.name,hashlib.sha256(section.data()).hexdigest(),section['sh_size'])
                for i,section in enumerate(elf.iter_sections()) if section['sh_flags'] & 4]

def section_proof(previous_object, control_object, previous_objects, control_objects):
    changed=[name for name,value in previous_objects.items() if control_objects.get(name)!=value]
    assert set(previous_objects)==set(control_objects)
    assert changed==['arch/X86/X86Mapping.c.o'],changed
    # Section indices can differ after adding a named data section. Compare
    # executable section names, sizes and literal object payloads directly.
    previous=[x[1:] for x in executable_sections(previous_object)]
    control=[x[1:] for x in executable_sections(control_object)]
    assert previous==control,(previous,control)
    return dict(changed=changed,all_other_objects_identical=True,
                executable_section_bytes_identical=True,sections=previous)
