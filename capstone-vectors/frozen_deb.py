"""Reconstruct the earlier five library inputs from frozen package hashes."""
from pathlib import Path
import hashlib
import io
import json
import subprocess as sp
import tarfile
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.dwarf.callframe import FDE

def prepare(w):
    inputs = json.loads((Path(__file__).resolve().parent / 'inputs.json').read_text())
    sha = lambda data: hashlib.sha256(data).hexdigest()
    for name, meta in inputs.items():
        if name == 'jpeg-avx2-i386':
            from jpeg_archive import jpeg_avx2
            fields = {'Package': meta['package'], 'Version': meta['version'],
                      'SHA256': meta['package_sha256'], 'Filename': meta['url']}
            result = jpeg_avx2(w, '', {meta['package']: '\n'.join(k + ': ' + v for k, v in fields.items())})
            assert result[4]['text_sha256'] == meta['text_sha256']
            assert result[4]['members'] == meta['members']
            yield result
            continue
        package = w / (name + '.deb')
        sp.run(['curl', '-fsSL', '--retry', '3', '--max-time', '120', '-o', package, meta['url']], check=True)
        assert sha(package.read_bytes()) == meta['package_sha256']
        member = next(x for x in sp.check_output(['ar', 't', package], text=True).splitlines() if x.startswith('data.tar'))
        payload = sp.check_output(['ar', 'p', package, member]); package.unlink()
        if member.endswith('.zst'):
            import zstandard
            stream = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(payload))
        else:
            stream = io.BytesIO(payload)
        prefix = 'libcrypto.so.' if 'ssl' in name else 'libzstd.so.' if 'zstd' in name else 'libjpeg.so.'
        with tarfile.open(fileobj=stream, mode='r|*') as archive:
            binaries = [archive.extractfile(item).read() for item in archive if item.isfile() and Path(item.name).name.startswith(prefix)]
        binary, = binaries
        assert sha(binary) == meta['binary_sha256']
        elf = ELFFile(io.BytesIO(binary)); section = elf.get_section_by_name('.text')
        address, size, code = section['sh_addr'], section['sh_size'], section.data()
        assert sha(code) == meta['text_sha256'] and len(code) == meta['text_bytes']
        spans = set()
        for section in elf.iter_sections():
            if isinstance(section, SymbolTableSection):
                spans.update((symbol['st_value'], symbol['st_size']) for symbol in section.iter_symbols()
                             if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_size'])
        if elf.get_section_by_name('.eh_frame'):
            spans.update((entry['initial_location'], entry['address_range']) for entry in elf.get_dwarf_info().EH_CFI_entries() if isinstance(entry, FDE))
        intervals, end = [], address
        for start, length in sorted(spans, key=lambda v: (v[0], -v[1])):
            if start >= end and length > 0 and start + length <= address + size:
                intervals.append((start - address, length, start)); end = start + length
        assert len(intervals) == meta['functions'] and sum(v[1] for v in intervals) == meta['function_bytes']
        target = w / (name + '.text'); target.write_bytes(code)
        provenance = {key: value for key, value in meta.items() if key not in ('host', 'iced_revision', 'selection', 'all-functions', 'simd-functions', 'common_bytes', 'common_functions')}
        yield name, 32 if name.endswith('i386') else 64, target, intervals, provenance
