import hashlib
import re
import shlex
import subprocess as sp
from pathlib import Path
from elftools.elf.elffile import ELFFile

RECORD = '.cs_x86_public_record_text'

def executable_sections(image):
    with image.open('rb') as stream:
        elf = ELFFile(stream)
        return {s.name: [s['sh_addr'], s.data_size, hashlib.sha256(s.data()).hexdigest()]
                for s in elf.iter_sections() if s['sh_flags'] & 4 and s.data_size}

def link_script(names):
    assert len(set(names)) == len(names) and all(re.fullmatch(r'\.cs_[A-Za-z0-9_]+', n) for n in names)
    sections = ''.join(f'  {n} : {{ *({n}) }}\n' for n in names)
    return 'SECTIONS {\n' + sections + '} INSERT AFTER .text;\n'

def orders(sections):
    by_address = sorted(sections, key=lambda n: sections[n][0])
    names = by_address[by_address.index('.text')+1 : by_address.index('.fini')]
    assert names[0] == RECORD and len(names) >= 2
    return {'explicit': names, 'late': names[1:]+[RECORD]}

def same_objects(build, image, archive, temporary, run):
    commands = sp.check_output(['ninja','-C',build,'-t','commands','capstone-product'], text=True)
    words = shlex.split(commands.splitlines()[-1])
    compiler, = [i for i, word in enumerate(words) if Path(word).name == 'clang++']
    args = words[compiler:]
    if '&&' in args:
        end = args.index('&&')
        assert args[end:] == ['&&', ':']
        args = args[:end]
    assert (build/args[args.index('-o')+1]).resolve() == image.resolve()
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    original = executable_sections(image)
    result = {'default': original}
    for label, order in orders(original).items():
        source = temporary/(label+'.ld')
        source.write_text(link_script(order))
        run(args+['-Wl,-T,'+str(source)],'relink-'+label,build)
        sections = executable_sections(image)
        assert set(sections) == set(original)
        assert all(original[n][1] == sections[n][1] for n in sections)
        equal = all(sections[n] == original[n] for n in sections)
        if label == 'explicit':
            assert equal, [(n,original[n][:2],sections[n][:2]) for n in original if sections[n] != original[n]]
        else:
            assert not equal and sections[RECORD][0] > max(sections[n][0] for n in order[:-1])
            assert sections[order[0]][0] < original[order[0]][0]
        result[label] = sections
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == archive_digest
        (temporary/(label+'-product')).write_bytes(image.read_bytes())
    return result
