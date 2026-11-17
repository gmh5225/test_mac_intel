from pathlib import Path
import hashlib
import io
import json
import shutil
import subprocess as sp
import tarfile
import tempfile
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.callframe import FDE

r = Path(__file__).resolve().parent
source = r.parent / 'source'
out = r.parent / 'evidence'
out.mkdir()
revision = '106380545da022533aa28bb9af6ba4df9f6e9970'
assert sp.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], text=True).strip() == revision
sha = lambda value: hashlib.sha256(value).hexdigest()


def save(name, value):
    (out / (name + '.json')).write_text(json.dumps(value, indent=2) + '\n')


def run(name, args):
    with (out / (name + '.log')).open('wb') as log:
        sp.run(list(map(str, args)), stdout=log, stderr=sp.STDOUT, check=True)


w = Path(tempfile.mkdtemp(prefix='capstone-vector-census-'))
try:
    b = w / 'build'
    run('configure', ['cmake', '-S', source, '-B', b, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
                     '-DCMAKE_C_COMPILER=clang', '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
                     '-DCAPSTONE_X86_SUPPORT=ON', '-DCAPSTONE_BUILD_SHARED_LIBS=OFF',
                     '-DCAPSTONE_BUILD_CSTOOL=OFF', '-DCAPSTONE_BUILD_CSTEST=OFF',
                     '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF'])
    run('build', ['cmake', '--build', b, '--target', 'capstone_static', '--parallel', '4'])
    generated=(source/'arch/X86/X86GenVectorOutput.inc').read_text()
    marker='static const struct VectorOutputRow vex_indexed_rows'
    assert generated.count(marker)==1
    prefix=generated[:generated.index(marker)]
    (w/'evex_rows.inc').write_text(prefix)
    save('canonical-rows',dict(owner='arch/X86/X86GenVectorOutput.inc',full_sha256=sha(generated.encode()),evex_prefix_sha256=sha(prefix.encode()),method='Verbatim EVEX prefix from the frozen generated owner, excluding unrelated VEX and padding rows.'))
    run('consumer', ['clang++', '-O2', '-std=c++17', '-I', source, '-I', w, '-I', source/'include',
                     r/'census.cpp', b/'libcapstone.a', '-lm', '-o', w/'census'])
    manifest = json.loads((r/'inputs.json').read_text())
    results = {}
    for name, meta in manifest.items():
        package = w/'input.deb'
        run('download-'+name, ['curl','--location','--silent','--show-error','--fail','--max-time','80',
                              '--retry','3','--output',package,meta['url']])
        assert sha(package.read_bytes()) == meta['package_sha256']
        member = next(x for x in sp.check_output(['ar','t',package],text=True).splitlines() if x.startswith('data.tar'))
        payload = sp.check_output(['ar','p',package,member]); package.unlink()
        if member.endswith('.zst'):
            import zstandard
            stream = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(payload))
        else:
            stream = io.BytesIO(payload)
        binary = None
        with tarfile.open(fileobj=stream,mode='r|*') as archive:
            for item in archive:
                if item.isfile() and Path(item.name).name.startswith('libcrypto.so.' if 'ssl' in name else 'libjpeg.so.'):
                    assert binary is None
                    binary = archive.extractfile(item).read()
        assert binary is not None and sha(binary) == meta['binary_sha256']
        elf = ELFFile(io.BytesIO(binary)); section = elf.get_section_by_name('.text')
        address, size, code = section['sh_addr'], section['sh_size'], section.data()
        assert sha(code) == meta['text_sha256']
        spans = set()
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                spans.update((symbol['st_value'],symbol['st_size']) for symbol in section.iter_symbols()
                             if symbol['st_info']['type']=='STT_FUNC' and symbol['st_size'])
        if elf.get_section_by_name('.eh_frame'):
            spans.update((entry['initial_location'],entry['address_range']) for entry in elf.get_dwarf_info().EH_CFI_entries() if isinstance(entry,FDE))
        intervals, end = [], address
        for start, length in sorted(spans, key=lambda v:(v[0],-v[1])):
            if start >= end and length > 0 and start + length <= address + size:
                intervals.append((start-address,length,start)); end = start + length
        assert len(intervals) == meta['functions']
        text = w/'input.text'; text.write_bytes(code)
        extents = w/'extents.tsv'; extents.write_text(''.join('%d %d %d\n'%v for v in intervals))
        print('Census '+name,flush=True)
        process=sp.run([w/'census','64' if name.endswith('amd64') else '32',text,extents],capture_output=True,text=True)
        (out/(name+'-stderr.log')).write_text(process.stderr)
        if process.returncode:raise RuntimeError(process.stderr)
        result=json.loads(process.stdout)
        if 'simd-functions' in meta:
            assert result['all-functions']['vectors'] > 0 and result['simd-functions']['functions'] > 0, 'The recorded SIMD cohort must populate vector selection'
        results[name] = dict(provenance=meta, observed=result)
        save('census',results)
        print(name, {k:{x:v[x] for x in ('decoded','invalid_bytes','vectors','functions')} for k,v in result.items()}, flush=True)
    save('complete',dict(source=revision,cases=len(results),success=True,
        selection='All nonoverlapping symbol/FDE extents; SIMD subset requires at least 8 vector instructions and at least 15% vector instructions. No iced common-boundary filter in this diagnostic; do not relabel these as timed benchmark panels.',
        assertions='Every raw decode agrees with canonical detail-enabled/no-text decode on status, public ID, length and cursor. Printed detail agrees on status, length and cursor; existing predicate ID adjustments are counted separately. Every admitted historical EVEX row agrees with both canonical IDs and lengths.',
        limits='One linear traversal, not application runtime frequencies or native timing; no source optimization or publication.'))
finally:
    amount = sum(path.stat().st_size for path in w.rglob('*') if path.is_file())
    shutil.rmtree(w)
    save('cleanup',dict(bytes=amount,removed=not w.exists()))
